package vfs

import (
	"os"
	"syscall"
	"time"
)

func CompatStat(stat os.FileInfo) (Stat, bool) {
	sysStat, ok := stat.Sys().(*syscall.Stat_t)
	if !ok {
		return Stat{}, false
	}

	s := Stat{
		Ino:     sysStat.Ino,
		Blocks:  sysStat.Blocks,
		BlkSize: int32(sysStat.Blksize),
		Atime:   time.Unix(int64(sysStat.Atim.Sec), int64(sysStat.Atim.Nsec)),
		Mtime:   time.Unix(int64(sysStat.Mtim.Sec), int64(sysStat.Mtim.Nsec)),
		Ctime:   time.Unix(int64(sysStat.Ctim.Sec), int64(sysStat.Ctim.Nsec)),
		Btime:   time.Unix(0, 0),
	}

	return s, true
}
