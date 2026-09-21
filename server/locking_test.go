package smb2

import (
	"sync"
	"testing"
	"time"

	. "github.com/macos-fuse-t/go-smb2/internal/erref"
)

func lockTestServer(opens ...*Open) *Server {
	d := &Server{opens: make(map[uint64]*Open)}
	d.lockCond = syncNewCond(&d.lock)
	for _, open := range opens {
		d.opens[open.fileId] = open
	}
	return d
}

// Kept behind a tiny wrapper so tests exercise the same mutex used by Server.
func syncNewCond(lock *sync.Mutex) *sync.Cond { return sync.NewCond(lock) }

func TestExclusiveLockConflictAndUnlock(t *testing.T) {
	a := &Open{fileId: 1, durableFileId: 99}
	b := &Open{fileId: 2, durableFileId: 99}
	d := lockTestServer(a, b)

	exclusive := []smbLockElement{{offset: 10, length: 20, exclusive: true, failImmediately: true}}
	if _, status := d.reserveByteRangeLocks(a, exclusive); status != STATUS_SUCCESS {
		t.Fatalf("first lock status = %v", status)
	}
	if _, status := d.reserveByteRangeLocks(b, exclusive); status != STATUS_LOCK_NOT_GRANTED {
		t.Fatalf("conflicting lock status = %v", status)
	}
	if _, status := d.reserveByteRangeLocks(a, []smbLockElement{{offset: 10, length: 20, unlock: true}}); status != STATUS_SUCCESS {
		t.Fatalf("unlock status = %v", status)
	}
	if _, status := d.reserveByteRangeLocks(b, exclusive); status != STATUS_SUCCESS {
		t.Fatalf("lock after unlock status = %v", status)
	}
}

func TestSharedLocksDoNotConflict(t *testing.T) {
	a := &Open{fileId: 1, durableFileId: 99}
	b := &Open{fileId: 2, durableFileId: 99}
	d := lockTestServer(a, b)
	shared := []smbLockElement{{offset: 0, length: 1, failImmediately: true}}
	if _, status := d.reserveByteRangeLocks(a, shared); status != STATUS_SUCCESS {
		t.Fatalf("first shared lock status = %v", status)
	}
	if _, status := d.reserveByteRangeLocks(b, shared); status != STATUS_SUCCESS {
		t.Fatalf("second shared lock status = %v", status)
	}
}

func TestBlockingLockWakesAfterUnlock(t *testing.T) {
	a := &Open{fileId: 1, durableFileId: 99}
	b := &Open{fileId: 2, durableFileId: 99}
	d := lockTestServer(a, b)
	if _, status := d.reserveByteRangeLocks(a, []smbLockElement{{offset: 0, length: 1, exclusive: true}}); status != STATUS_SUCCESS {
		t.Fatalf("first lock status = %v", status)
	}

	done := make(chan NtStatus, 1)
	go func() {
		_, status := d.reserveByteRangeLocks(b, []smbLockElement{{offset: 0, length: 1, exclusive: true}})
		done <- status
	}()
	select {
	case status := <-done:
		t.Fatalf("blocking lock returned early with %v", status)
	case <-time.After(30 * time.Millisecond):
	}
	if _, status := d.reserveByteRangeLocks(a, []smbLockElement{{offset: 0, length: 1, unlock: true}}); status != STATUS_SUCCESS {
		t.Fatalf("unlock status = %v", status)
	}
	select {
	case status := <-done:
		if status != STATUS_SUCCESS {
			t.Fatalf("blocking lock status = %v", status)
		}
	case <-time.After(time.Second):
		t.Fatal("blocking lock was not woken")
	}
}

func TestLocksBlockConflictingIO(t *testing.T) {
	a := &Open{fileId: 1, durableFileId: 99}
	b := &Open{fileId: 2, durableFileId: 99}
	d := lockTestServer(a, b)
	if _, status := d.reserveByteRangeLocks(a, []smbLockElement{{offset: 10, length: 10, exclusive: true}}); status != STATUS_SUCCESS {
		t.Fatalf("exclusive lock status = %v", status)
	}
	if !d.ioConflictsWithByteRangeLock(b, 15, 1, false) {
		t.Fatal("exclusive lock did not block an overlapping read")
	}
	if d.ioConflictsWithByteRangeLock(b, 20, 1, true) {
		t.Fatal("non-overlapping write was blocked")
	}
}
