package smb2

import (
	"testing"

	"github.com/macos-fuse-t/go-smb2/vfs"
)

func TestFilePosixInformationUsesUnixMode(t *testing.T) {
	attrs := vfs.Attributes{}
	attrs.SetFileType(vfs.FileTypeRegularFile)
	attrs.SetInodeNumber(42)
	attrs.SetDeviceNumber(7)
	attrs.SetLinkCount(3)
	attrs.SetSizeBytes(1500)
	attrs.SetDiskSizeBytes(4096)
	attrs.SetPermissions(vfs.NewPermissionsFromMode(0644))
	attrs.SetUnixMode(0644)
	attrs.SetUID(1000)
	attrs.SetGID(1001)

	info := newFilePosixInformationInfo(vfs.DirInfo{Name: "websock_client.h", Attributes: attrs})
	if info.PosixMode != 0100644 {
		t.Fatalf("POSIX mode = %#o, want 0100644", info.PosixMode)
	}
	if info.NumberOfLinks != 3 {
		t.Fatalf("link count = %d, want 3", info.NumberOfLinks)
	}

	buf := make([]byte, info.Size())
	info.Encode(buf)
	if got := le.Uint32(buf[76:]); got != 0100644 {
		t.Fatalf("encoded POSIX mode = %#o, want 0100644", got)
	}
	if got := le.Uint32(buf[80+info.OwnerSID.Size()+info.GroupSID.Size():]); got == 0 {
		t.Fatalf("filename length was not encoded")
	}
}

func TestFilePosixDirectoryInformationStartsWithNextEntryOffset(t *testing.T) {
	attrs := vfs.Attributes{}
	attrs.SetFileType(vfs.FileTypeDirectory)
	attrs.SetInodeNumber(43)
	attrs.SetLinkCount(1)
	attrs.SetSizeBytes(0)
	attrs.SetDiskSizeBytes(0)
	attrs.SetUnixMode(0755)

	entry := newFilePosixDirectoryInformationInfo(vfs.DirInfo{Name: "src", Attributes: attrs})
	buf := make([]byte, entry.Size())
	entry.NextEntryOffset = uint32(entry.Size())
	entry.Encode(buf)

	if got := le.Uint32(buf[:4]); got != uint32(entry.Size()) {
		t.Fatalf("next entry offset = %d, want %d", got, entry.Size())
	}
	if got := le.Uint32(buf[8+76:]); got != 040755 {
		t.Fatalf("encoded directory POSIX mode = %#o, want 040755", got)
	}
	if got := le.Uint32(buf[8+80+entry.Info.OwnerSID.Size()+entry.Info.GroupSID.Size():]); got == 0 {
		t.Fatalf("filename length was not encoded")
	}
}

func TestFileFsPosixInformationEncoding(t *testing.T) {
	info := &FileFsPosixInformationInfo{
		OptimalTransferSize: 4096,
		BlockSize:           4096,
		TotalBlocks:         100,
		BlocksAvailable:     40,
		UserBlocksAvailable: 30,
		TotalFileNodes:      200,
		FreeFileNodes:       150,
		FsIdentifier:        99,
	}
	buf := make([]byte, info.Size())
	info.Encode(buf)

	if got := le.Uint32(buf[:4]); got != 4096 {
		t.Fatalf("optimal transfer size = %d, want 4096", got)
	}
	if got := le.Uint64(buf[48:]); got != 99 {
		t.Fatalf("fs identifier = %d, want 99", got)
	}
}
