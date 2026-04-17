//go:build windows

package main

import (
	"os"

	"github.com/macos-fuse-t/go-smb2/vfs"
)

func statFS(rootPath string) (*vfs.FSAttributes, error) {
	const blockSize = 4096
	const blocks = 1 << 28

	a := vfs.FSAttributes{}
	a.SetAvailableBlocks(blocks)
	a.SetBlockSize(blockSize)
	a.SetBlocks(blocks)
	a.SetFreeBlocks(blocks)
	a.SetIOSize(blockSize)
	return &a, nil
}

func openSymlink(p string) (*os.File, error) {
	return os.OpenFile(p, os.O_RDONLY, 0)
}
