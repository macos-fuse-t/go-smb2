package smb2

import (
	"testing"

	logrus "github.com/sirupsen/logrus"
)

func TestSetLogger(t *testing.T) {
	old := log
	t.Cleanup(func() {
		log = old
	})

	logger := logrus.New()
	SetLogger(logger)
	if log != logger {
		t.Fatal("SetLogger() did not replace package logger")
	}

	SetLogger(nil)
	if log != logger {
		t.Fatal("SetLogger(nil) replaced package logger")
	}
}
