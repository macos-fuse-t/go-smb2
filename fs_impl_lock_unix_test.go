//go:build !windows

package main

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"testing"

	"github.com/macos-fuse-t/go-smb2/vfs"
)

const (
	lockHelperModeEnv = "GO_SMB2_LOCK_HELPER_MODE"
	lockHelperPathEnv = "GO_SMB2_LOCK_HELPER_PATH"
)

func TestPassthroughFSLock(t *testing.T) {
	root := t.TempDir()
	path := root + "/locked-file"
	if err := os.WriteFile(path, []byte("test data"), 0600); err != nil {
		t.Fatal(err)
	}

	fs := NewPassthroughFS(root)
	handle, err := fs.Open("locked-file", os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := fs.Close(handle); err != nil {
			t.Errorf("close: %v", err)
		}
	})

	exclusive := vfs.ByteRangeLock{
		Offset:          2,
		Length:          4,
		Type:            vfs.ByteRangeLockExclusive,
		FailImmediately: true,
	}
	if err := fs.Lock(handle, []vfs.ByteRangeLock{exclusive}); err != nil {
		t.Fatalf("exclusive lock: %v", err)
	}
	runLockHelper(t, path, "conflict")

	if err := fs.Lock(handle, []vfs.ByteRangeLock{{
		Offset: 2,
		Length: 4,
		Type:   vfs.ByteRangeLockUnlock,
	}}); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	runLockHelper(t, path, "success")
}

func runLockHelper(t *testing.T, path, mode string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestPassthroughFSLockHelper$")
	cmd.Env = append(os.Environ(), lockHelperModeEnv+"="+mode, lockHelperPathEnv+"="+path)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("lock helper (%s): %v\n%s", mode, err, output)
	}
}

func TestPassthroughFSLockHelper(t *testing.T) {
	mode := os.Getenv(lockHelperModeEnv)
	if mode == "" {
		return
	}

	file, err := os.OpenFile(os.Getenv(lockHelperPathEnv), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	lock := syscall.Flock_t{
		Type:   syscall.F_WRLCK,
		Whence: int16(os.SEEK_SET),
		Start:  2,
		Len:    4,
	}
	err = syscall.FcntlFlock(file.Fd(), syscall.F_SETLK, &lock)
	switch mode {
	case "conflict":
		if !errors.Is(err, syscall.EACCES) && !errors.Is(err, syscall.EAGAIN) {
			t.Fatalf("conflicting lock error = %v, want EACCES or EAGAIN", err)
		}
	case "success":
		if err != nil {
			t.Fatalf("lock after unlock: %v", err)
		}
		lock.Type = syscall.F_UNLCK
		if err := syscall.FcntlFlock(file.Fd(), syscall.F_SETLK, &lock); err != nil {
			t.Fatalf("helper unlock: %v", err)
		}
	default:
		t.Fatalf("unknown helper mode %q", mode)
	}
}
