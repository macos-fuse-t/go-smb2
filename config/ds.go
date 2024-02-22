package config

import (
	"github.com/macos-fuse-t/go-smb2/vfs"
)

type UesrPwdI interface {
	UserPwd(name string) (password string, err error)
}
type UserSharedI interface {
	UserShared(name string) (shared map[string]vfs.VFSFileSystem, err error)
}

type DSI interface {
	UesrPwdI
	UserSharedI
}
