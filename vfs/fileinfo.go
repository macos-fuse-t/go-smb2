package vfs

import "time"

type Stat struct {
	Ino     uint64
	Dev     uint64
	Blocks  int64
	BlkSize int32
	Nlink   uint32
	UID     uint32
	GID     uint32
	Mtime   time.Time
	Atime   time.Time
	Ctime   time.Time
	Btime   time.Time
}
