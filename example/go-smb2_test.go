package example

import (
	"fmt"
	"os"
	"testing"

	"github.com/macos-fuse-t/go-smb2/config"
	"github.com/macos-fuse-t/go-smb2/vfs"
)

var (
	cfg     config.AppConfig
	homeDir string
)

const (
	// PORT_mac = 10445
	PORT_mac   = 445
	ShareName1 = "Share1"
	ShareName2 = "Share2"
	ShareName3 = "ShareGuest"
)

func init() {
	homeDir, _ = os.UserHomeDir()
	homeDir, _ = os.Getwd()

	cfg = config.NewConfig([]string{
		"smb2.ini",
		homeDir + "/.fuse-t/smb2.ini",
	})

	cfg.ListenAddr = fmt.Sprintf(":%d", PORT_mac)
	cfg.Advertise = false
	cfg.AllowGuest = false
	cfg.AllowGuest = true
}

func Test_goSmb2(t *testing.T) {
	userPwd := map[string]string{"b": "a"}
	sharedUser := map[string]vfs.VFSFileSystem{ShareName1: NewPassthroughFS(homeDir), ShareName2: NewPassthroughFS(homeDir)}
	sharedGuest := map[string]vfs.VFSFileSystem{ShareName3: NewPassthroughFS(homeDir)}
	ds := NewDS(userPwd, sharedUser, sharedGuest)

	Run(cfg, ds, ShareName1)
}
