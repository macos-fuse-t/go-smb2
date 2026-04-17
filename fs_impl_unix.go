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
