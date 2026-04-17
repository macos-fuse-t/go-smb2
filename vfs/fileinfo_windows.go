package vfs

import (
	"hash/fnv"
	"os"
	"syscall"
	"time"
)

func CompatStat(stat os.FileInfo) (Stat, bool) {
	mtime := stat.ModTime()
	s := Stat{
		Ino:     fallbackInode(stat),
		Blocks:  (stat.Size() + 511) / 512,
		BlkSize: 4096,
		Atime:   mtime,
		Mtime:   mtime,
		Ctime:   mtime,
		Btime:   mtime,
	}

	if sysStat, ok := stat.Sys().(*syscall.Win32FileAttributeData); ok {
		s.Atime = time.Unix(0, sysStat.LastAccessTime.Nanoseconds())
		s.Mtime = time.Unix(0, sysStat.LastWriteTime.Nanoseconds())
		s.Ctime = time.Unix(0, sysStat.CreationTime.Nanoseconds())
		s.Btime = s.Ctime
	}

	return s, true
}

func fallbackInode(stat os.FileInfo) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(stat.Name()))
	var b [16]byte
	size := uint64(stat.Size())
	mod := uint64(stat.ModTime().UnixNano())
	for i := 0; i < 8; i++ {
		b[i] = byte(size >> (i * 8))
		b[i+8] = byte(mod >> (i * 8))
	}
	_, _ = h.Write(b[:])
	return h.Sum64()
}
