//go:build !windows

package main

import (
	"os"
	"syscall"

	"github.com/macos-fuse-t/go-smb2/vfs"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

func statFS(rootPath string) (*vfs.FSAttributes, error) {
	var statfs unix.Statfs_t
	if err := unix.Statfs(rootPath, &statfs); err != nil {
		log.Errorf("statfs")
		return nil, err
	}

	a := vfs.FSAttributes{}
	a.SetAvailableBlocks(statfs.Bavail)
	a.SetBlockSize(uint64(statfs.Bsize))
	a.SetBlocks(statfs.Bavail)
	a.SetFiles(statfs.Files)
	a.SetFreeBlocks(statfs.Bfree)
	a.SetFreeFiles(statfs.Ffree)
	a.SetIOSize(uint64(statfs.Bsize))
	return &a, nil
}

func openSymlink(p string) (*os.File, error) {
	fd, err := syscall.Open(p, 0x200000, 0) // O_SYMLINK, O_PATH
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), p), nil
}

func applyFileLocks(file *os.File, locks []vfs.ByteRangeLock) error {
	const maxInt64 = uint64(^uint64(0) >> 1)
	for _, lock := range locks {
		if lock.Offset > maxInt64 || lock.Length > maxInt64 {
			return syscall.EOVERFLOW
		}
		flock := syscall.Flock_t{
			Start:  int64(lock.Offset),
			Len:    int64(lock.Length),
			Whence: int16(os.SEEK_SET),
		}
		switch lock.Type {
		case vfs.ByteRangeLockShared:
			flock.Type = syscall.F_RDLCK
		case vfs.ByteRangeLockExclusive:
			flock.Type = syscall.F_WRLCK
		case vfs.ByteRangeLockUnlock:
			flock.Type = syscall.F_UNLCK
		default:
			return syscall.EINVAL
		}
		cmd := syscall.F_SETLKW
		if lock.FailImmediately || lock.Type == vfs.ByteRangeLockUnlock {
			cmd = syscall.F_SETLK
		}
		if err := syscall.FcntlFlock(file.Fd(), cmd, &flock); err != nil {
			return err
		}
	}
	return nil
}
