package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/macos-fuse-t/go-smb2/vfs"
)

func TestPassthroughFSRenameKeepsOpenHandleUsable(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "file.lock"), []byte("data"), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	fs := NewPassthroughFS(root)
	h, err := fs.Open("file.lock", os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer fs.Close(h)

	if err := fs.Rename(h, "file", 1); err != nil {
		t.Fatalf("rename through open handle: %v", err)
	}

	if _, err := fs.GetAttr(h); err != nil {
		t.Fatalf("get attr after rename through open handle: %v", err)
	}

	if err := fs.Unlink(h); err != nil {
		t.Fatalf("unlink renamed file through open handle: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "file")); !os.IsNotExist(err) {
		t.Fatalf("renamed file still exists after unlink: %v", err)
	}
}

func TestPassthroughFSSymlinkReopensHandleOnCreatedLink(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "target"), []byte("data"), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	fs := NewPassthroughFS(root)
	h, err := fs.Open("link", os.O_CREATE|os.O_RDWR|os.O_EXCL, 0644)
	if err != nil {
		t.Fatalf("open placeholder: %v", err)
	}
	defer fs.Close(h)

	attrs, err := fs.Symlink(h, "target", 1)
	if err != nil {
		t.Fatalf("create symlink: %v", err)
	}
	if attrs.GetFileType() != vfs.FileTypeSymlink {
		t.Fatalf("symlink attrs file type = %v, want symlink", attrs.GetFileType())
	}

	handleAttrs, err := fs.GetAttr(h)
	if err != nil {
		t.Fatalf("get attr through symlink handle: %v", err)
	}
	if handleAttrs.GetFileType() != vfs.FileTypeSymlink {
		t.Fatalf("handle attrs file type = %v, want symlink", handleAttrs.GetFileType())
	}

	target, err := os.Readlink(filepath.Join(root, "link"))
	if err != nil {
		t.Fatalf("read created symlink: %v", err)
	}
	if target != "target" {
		t.Fatalf("symlink target = %q, want %q", target, "target")
	}
}
