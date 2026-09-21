package smb2

import (
	"errors"
	"math"
	"strings"
	"syscall"

	. "github.com/macos-fuse-t/go-smb2/internal/erref"
	. "github.com/macos-fuse-t/go-smb2/internal/smb2"
	"github.com/macos-fuse-t/go-smb2/vfs"
)

type smbByteRangeLock struct {
	offset    uint64
	length    uint64
	exclusive bool
}

type smbLockElement struct {
	offset          uint64
	length          uint64
	exclusive       bool
	unlock          bool
	failImmediately bool
}

func decodeSMBLockElements(in []LockElementDecoder) ([]smbLockElement, NtStatus) {
	out := make([]smbLockElement, len(in))
	for i, element := range in {
		flags := element.Flags()
		const known = SMB2_LOCKFLAG_SHARED_LOCK | SMB2_LOCKFLAG_EXCLUSIVE_LOCK |
			SMB2_LOCKFLAG_UNLOCK | SMB2_LOCKFLAG_FAIL_IMMEDIATELY
		if flags&^known != 0 || element.Length() == 0 || element.Offset() > math.MaxUint64-(element.Length()-1) {
			return nil, STATUS_INVALID_LOCK_RANGE
		}

		kind := flags & (SMB2_LOCKFLAG_SHARED_LOCK | SMB2_LOCKFLAG_EXCLUSIVE_LOCK | SMB2_LOCKFLAG_UNLOCK)
		if kind != SMB2_LOCKFLAG_SHARED_LOCK && kind != SMB2_LOCKFLAG_EXCLUSIVE_LOCK && kind != SMB2_LOCKFLAG_UNLOCK {
			return nil, STATUS_INVALID_PARAMETER
		}
		if kind == SMB2_LOCKFLAG_UNLOCK && flags&SMB2_LOCKFLAG_FAIL_IMMEDIATELY != 0 {
			return nil, STATUS_INVALID_PARAMETER
		}

		out[i] = smbLockElement{
			offset:          element.Offset(),
			length:          element.Length(),
			exclusive:       kind == SMB2_LOCKFLAG_EXCLUSIVE_LOCK,
			unlock:          kind == SMB2_LOCKFLAG_UNLOCK,
			failImmediately: flags&SMB2_LOCKFLAG_FAIL_IMMEDIATELY != 0,
		}
	}
	return out, STATUS_SUCCESS
}

func (e smbLockElement) vfsLock() vfs.ByteRangeLock {
	t := vfs.ByteRangeLockShared
	if e.exclusive {
		t = vfs.ByteRangeLockExclusive
	} else if e.unlock {
		t = vfs.ByteRangeLockUnlock
	}
	return vfs.ByteRangeLock{
		Offset:          e.offset,
		Length:          e.length,
		Type:            t,
		FailImmediately: e.failImmediately,
	}
}

func lockRangesOverlap(aOffset, aLength, bOffset, bLength uint64) bool {
	aEnd := aOffset + aLength - 1
	bEnd := bOffset + bLength - 1
	return aOffset <= bEnd && bOffset <= aEnd
}

func copyLocks(in []smbByteRangeLock) []smbByteRangeLock {
	return append([]smbByteRangeLock(nil), in...)
}

func applyLockElementsToOpen(current []smbByteRangeLock, elements []smbLockElement) ([]smbByteRangeLock, NtStatus) {
	locks := copyLocks(current)
	for _, element := range elements {
		if element.unlock {
			found := -1
			for i, held := range locks {
				if held.offset == element.offset && held.length == element.length {
					found = i
					break
				}
			}
			if found < 0 {
				return nil, STATUS_RANGE_NOT_LOCKED
			}
			locks = append(locks[:found], locks[found+1:]...)
			continue
		}
		locks = append(locks, smbByteRangeLock{offset: element.offset, length: element.length, exclusive: element.exclusive})
	}
	return locks, STATUS_SUCCESS
}

func (d *Server) lockConflict(open *Open, elements []smbLockElement) bool {
	for _, element := range elements {
		if element.unlock {
			continue
		}
		for _, other := range d.opens {
			if other == open || !opensShareLockFile(open, other) {
				continue
			}
			for _, held := range other.byteRangeLocks {
				if lockRangesOverlap(element.offset, element.length, held.offset, held.length) &&
					(element.exclusive || held.exclusive) {
					return true
				}
			}
		}
	}
	return false
}

func opensShareLockFile(a, b *Open) bool {
	if a.durableFileId != b.durableFileId || a.isEa != b.isEa || a.eaKey != b.eaKey {
		return false
	}
	if a.tree == nil || b.tree == nil {
		return true
	}
	return strings.EqualFold(a.tree.path, b.tree.path)
}

func (d *Server) ioConflictsWithByteRangeLock(open *Open, offset, length uint64, write bool) bool {
	if length == 0 || offset > math.MaxUint64-(length-1) {
		return false
	}
	d.lock.Lock()
	defer d.lock.Unlock()
	for _, other := range d.opens {
		if other == open || !opensShareLockFile(open, other) {
			continue
		}
		for _, held := range other.byteRangeLocks {
			if lockRangesOverlap(offset, length, held.offset, held.length) && (write || held.exclusive) {
				return true
			}
		}
	}
	return false
}

// reserveByteRangeLocks atomically updates the SMB-visible lock table. It may
// wait for a conflicting lock unless FAIL_IMMEDIATELY was requested.
func (d *Server) reserveByteRangeLocks(open *Open, elements []smbLockElement) ([]smbByteRangeLock, NtStatus) {
	d.lock.Lock()
	defer d.lock.Unlock()

	for {
		if d.opens[open.fileId] != open {
			return nil, STATUS_FILE_CLOSED
		}
		if !d.lockConflict(open, elements) {
			break
		}
		for _, element := range elements {
			if !element.unlock && element.failImmediately {
				return nil, STATUS_LOCK_NOT_GRANTED
			}
		}
		d.lockCond.Wait()
	}

	old := copyLocks(open.byteRangeLocks)
	updated, status := applyLockElementsToOpen(old, elements)
	if status != STATUS_SUCCESS {
		return nil, status
	}
	open.byteRangeLocks = updated
	open.lockCount = len(updated)
	d.lockCond.Broadcast()
	return old, STATUS_SUCCESS
}

func (d *Server) rollbackByteRangeLocks(open *Open, old []smbByteRangeLock) {
	d.lock.Lock()
	defer d.lock.Unlock()
	if d.opens[open.fileId] == open {
		open.byteRangeLocks = copyLocks(old)
		open.lockCount = len(old)
	}
	d.lockCond.Broadcast()
}

func lockErrorStatus(err error) NtStatus {
	switch {
	case errors.Is(err, syscall.EAGAIN), errors.Is(err, syscall.EACCES):
		return STATUS_LOCK_NOT_GRANTED
	case errors.Is(err, syscall.EBADF):
		return STATUS_INVALID_HANDLE
	case errors.Is(err, syscall.EINVAL), errors.Is(err, syscall.EOVERFLOW):
		return STATUS_INVALID_LOCK_RANGE
	default:
		return STATUS_UNSUCCESSFUL
	}
}
