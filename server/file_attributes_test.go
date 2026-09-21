package smb2

import (
	"testing"

	. "github.com/macos-fuse-t/go-smb2/internal/smb2"
)

func TestUnixModeWithFileAttributesReadOnly(t *testing.T) {
	if got := unixModeWithFileAttributes(0644, FILE_ATTRIBUTE_READONLY); got != 0444 {
		t.Fatalf("readonly mode = %#o, want %#o", got, uint32(0444))
	}
}

func TestUnixModeWithFileAttributesWritable(t *testing.T) {
	if got := unixModeWithFileAttributes(0444, FILE_ATTRIBUTE_NORMAL); got != 0644 {
		t.Fatalf("writable mode = %#o, want %#o", got, uint32(0644))
	}
}
