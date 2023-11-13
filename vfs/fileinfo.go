package vfs

import "time"

type Stat struct {
	Ino     uint64
	Blocks  int64
	BlkSize int32
	Mtime   time.Time
	Atime   time.Time
	Ctime   time.Time
	Btime   time.Time
}
