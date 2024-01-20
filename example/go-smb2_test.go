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
	PORT_mac   = 10445
	ShareName1 = "Share1"
	ShareName2 = "Share2"
)

func init() {
	homeDir, _ = os.UserHomeDir()
	homeDir, _ = os.Getwd()

	cfg = config.NewConfig([]string{
		"smb2.ini",
		homeDir + "/.fuse-t/smb2.ini",
	})

	cfg.MountDir = homeDir
	cfg.ListenAddr = fmt.Sprintf(":%d", PORT_mac)
	cfg.Advertise = false
	cfg.AllowGuest = true
}

func Test_goSmb2(t *testing.T) {
	userPwd := map[string]string{"a": "a"}
	shared := map[string]vfs.VFSFileSystem{ShareName1: NewPassthroughFS(cfg.MountDir), ShareName2: NewPassthroughFS(cfg.MountDir)}
	ds := NewDS(userPwd, shared)

	Run(cfg, ds, ShareName1)
}
