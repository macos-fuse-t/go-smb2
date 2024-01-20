package config

import (
	"os"

	"github.com/go-ini/ini"
	"github.com/spf13/pflag"
)

type AppConfig struct {
	Debug      bool
	Console    bool
	ListenAddr string
	MountDir   string
	// ShareName   string
	Advertise   bool
	Hostname    string
	Xatrrs      bool
	AllowGuest  bool
	MaxIOReads  int
	MaxIOWrites int
}

func NewConfig(iniFile []string) AppConfig {
	cfg := AppConfig{
		ListenAddr: "127.0.0.1:8082",
		Debug:      false,
		Console:    true,
		Advertise:  true,
		Hostname:   "SmbServer",
		// ShareName:   "Share",
		Xatrrs:      true,
		AllowGuest:  false,
		MaxIOReads:  4,
		MaxIOWrites: 4,
	}
	cfg.MountDir, _ = os.UserHomeDir()

	var f *ini.File
	var err error
	for _, file := range iniFile {
		if f, err = ini.Load(file); err == nil {
			break
		}
	}

	if err == nil {
		s, err := f.GetSection("Default")
		if err == nil {
			if v := s.Key("debug"); v != nil {
				if b, err := v.Bool(); err == nil {
					cfg.Debug = b
				}
			}
			if v := s.Key("console"); v != nil {
				if b, err := v.Bool(); err == nil {
					cfg.Console = b
				}
			}

		}
	}

	pflag.BoolVarP(&cfg.Debug, "debug", "d", cfg.Debug, "debug mode")
	pflag.BoolVarP(&cfg.Console, "console", "c", cfg.Console, "output logs to console")
	pflag.StringVarP(&cfg.ListenAddr, "listen_addr", "l", cfg.ListenAddr, "smb server listen address")
	pflag.StringVarP(&cfg.MountDir, "mount_dir", "m", cfg.MountDir, "smb server mount dir")
	// pflag.StringVarP(&cfg.ShareName, "share", "s", cfg.ShareName, "smb server share name")
	pflag.StringVarP(&cfg.Hostname, "hostname", "h", cfg.Hostname, "hostname to display")
	pflag.BoolVarP(&cfg.Advertise, "advertise", "a", cfg.Advertise, "advertise the server")
	pflag.BoolVarP(&cfg.Xatrrs, "xattr", "x", cfg.Xatrrs, "support extended attributes")
	pflag.BoolVarP(&cfg.AllowGuest, "guest", "g", cfg.AllowGuest, "allow guest")
	pflag.IntVar(&cfg.MaxIOReads, "ioreads", cfg.MaxIOReads, "max in-flight io reads")
	pflag.IntVar(&cfg.MaxIOWrites, "iowrites", cfg.MaxIOWrites, "max in-flight io writes")
	pflag.Parse()

	return cfg
}
