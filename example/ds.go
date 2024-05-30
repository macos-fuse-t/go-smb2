package example

import (
	"github.com/macos-fuse-t/go-smb2/config"
	"github.com/macos-fuse-t/go-smb2/vfs"
)

var _ config.DSI = (*ds)(nil)

func NewDS(UserPassword map[string]string, UserShareds, GuestShareds map[string]vfs.VFSFileSystem) config.DSI {
	return &ds{UserPassword: UserPassword, UserShareds: UserShareds, GuestShareds: GuestShareds}
}

type ds struct {
	UserPassword map[string]string
	UserShareds  map[string]vfs.VFSFileSystem
	GuestShareds map[string]vfs.VFSFileSystem
}

func (d *ds) UserPwd(name string) (password string, err error) {
	if pwd, ok := d.UserPassword[name]; ok {
		return pwd, nil
	}
	err = config.ErrAccountNotFound
	return
}
func (d *ds) UserShared(name string) (shared map[string]vfs.VFSFileSystem, err error) {
	if name == config.KGuest {
		return d.GuestShareds, nil
	}
	return d.UserShareds, nil
}
