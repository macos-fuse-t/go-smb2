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
	// PORT_mac   = 10445
	PORT_mac   = 445
	ShareName1 = "Share1"
	ShareName2 = "Share2"
)

func init() {
	homeDir, _ = os.UserHomeDir()
	homeDir, _ = os.Getwd()
	homeDir = "/Volumes/Vault/64gupan"

	cfg = config.NewConfig([]string{
		"smb2.ini",
		homeDir + "/.fuse-t/smb2.ini",
	})

	cfg.ListenAddr = fmt.Sprintf(":%d", PORT_mac)
	cfg.Advertise = false
	cfg.AllowGuest = false
}

func Test_goSmb2(t *testing.T) {
	userPwd := map[string]string{"a": "abcd1234"}
	shared := map[string]vfs.VFSFileSystem{ShareName1: NewPassthroughFS(homeDir), ShareName2: NewPassthroughFS(homeDir)}
	ds := NewDS(userPwd, shared)

	Run(cfg, ds, ShareName1)
}
