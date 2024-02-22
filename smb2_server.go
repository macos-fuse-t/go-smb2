package main

import (
	"os"

	"github.com/macos-fuse-t/go-smb2/config"
	"github.com/macos-fuse-t/go-smb2/example"
	"github.com/macos-fuse-t/go-smb2/vfs"
)

func main() {

	homeDir, _ := os.UserHomeDir()
	cfg := config.NewConfig([]string{
		"smb2.ini",
		homeDir + "/.fuse-t/smb2.ini",
	})

	userPwd := map[string]string{"a": "a"}
	shared := map[string]vfs.VFSFileSystem{cfg.ShareName: example.NewPassthroughFS(cfg.MountDir)}
	ds := example.NewDS(userPwd, shared)
	example.Run(cfg, ds, cfg.ShareName)

}
