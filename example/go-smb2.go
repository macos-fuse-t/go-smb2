package example

import (
	"os"
	"os/signal"

	"github.com/macos-fuse-t/go-smb2/bonjour"
	"github.com/macos-fuse-t/go-smb2/config"
	smb2 "github.com/macos-fuse-t/go-smb2/server"
	log "github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

func Run(cfg config.AppConfig, ds config.DSI, shareName string) {

	InitLogs(cfg)

	srv := smb2.NewServer(
		&smb2.ServerConfig{
			AllowGuest:  cfg.AllowGuest,
			MaxIOReads:  cfg.MaxIOReads,
			MaxIOWrites: cfg.MaxIOWrites,
			Xatrrs:      cfg.Xatrrs,
		},
		&smb2.NTLMAuthenticator{
			DS:         ds,
			TargetSPN:  "",
			NbDomain:   cfg.Hostname,
			NbName:     cfg.Hostname,
			DnsName:    cfg.Hostname + ".local",
			DnsDomain:  ".local",
			AllowGuest: cfg.AllowGuest,
		},
		ds,
	)

	log.Infof("Starting server at %s", cfg.ListenAddr)
	go srv.Serve(cfg.ListenAddr)
	if cfg.Advertise {
		go bonjour.Advertise(cfg.ListenAddr, cfg.Hostname, cfg.Hostname, shareName, true)
	}

	WaitSignal()
}

func InitLogs(cfg config.AppConfig) {
	log.Infof("debug level %v", cfg.Debug)
	if cfg.Debug {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}

	homeDir, _ := os.UserHomeDir()
	if !cfg.Console {
		log.SetOutput(&lumberjack.Logger{
			Filename:   homeDir + "smb2-go.log",
			MaxSize:    100, // megabytes
			MaxBackups: 3,
			MaxAge:     28,   //days
			Compress:   true, // disabled by default
		})
	} else {
		log.SetOutput(os.Stdout)
	}
}

func WaitSignal() {
	// Ctrl+C handling
	handler := make(chan os.Signal, 1)
	signal.Notify(handler, os.Interrupt)
	for sig := range handler {
		if sig == os.Interrupt {
			bonjour.Shutdown()
			break
		}
	}
}
