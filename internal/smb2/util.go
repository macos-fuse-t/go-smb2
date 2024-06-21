package smb2

import (
	"encoding/binary"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"unicode/utf16"

	"github.com/macos-fuse-t/go-smb2/vfs"
)

var (
	le = binary.LittleEndian
)

func Roundup(x, align int) int {
	return (x + (align - 1)) &^ (align - 1)
}

func Roundup64(x, align int64) int64 {
	return (x + (align - 1)) &^ (align - 1)
}

func UTF16FromString(s string) []uint16 {
	return utf16.Encode([]rune(s))
}

func UTF16ToString(s []uint16) string {
	return string(utf16.Decode(s))
}

func wildcardToRegexp(pattern string) string {
	return "^" + strings.ReplaceAll(strings.ReplaceAll(pattern, "?", "."), "*", ".*") + "$"
}

func MatchWildcard(s, pattern string) bool {
	r, err := regexp.Compile(wildcardToRegexp(pattern))
	if err != nil {
		return false
	}
	return r.MatchString(s)
}

// func DirentName(dirent *syscall.Dirent) string {
// 	nameSlice := (*[256]byte)(unsafe.Pointer(&dirent.Name[0]))

// 	nameLen := 0
// 	for ; nameLen < len(nameSlice) && nameSlice[nameLen] != 0; nameLen++ {
// 	}

// 	return string(nameSlice[:nameLen])
// }

func Align(n int, a int) int {
	return (n + a - 1) &^ (a - 1)
}

func (f *FileId) HandleId() uint64 {
	return le.Uint64(f.Volatile[:]) /* & 0xffffffff*/
}

func (f *FileId) SetHandleId(n uint64) {
	v := n //(uint64(rand.Uint32()) << 32) | n
	le.PutUint64(f.Volatile[:], v)
}

func (f *FileId) NodeId() uint64 {
	return le.Uint64(f.Persistent[:])
}

func (f *FileId) SetNodeId(n uint64) {
	le.PutUint64(f.Persistent[:], n)
}

func ContainsWildcard(s string) bool {
	return strings.Contains(s, "*") || strings.Contains(s, "?")
}

func BirthTimeFromVfs(a *vfs.Attributes) *Filetime {
	if t, ok := a.GetBirthTime(); ok {
		return NsecToFiletime(t.UnixNano())
	}
	return &Filetime{}
}

func AccessTimeFromVfs(a *vfs.Attributes) *Filetime {
	if t, ok := a.GetAccessTime(); ok {
		return NsecToFiletime(t.UnixNano())
	}
	return &Filetime{}
}

func ModifiedTimeFromVfs(a *vfs.Attributes) *Filetime {
	if t, ok := a.GetLastDataModificationTime(); ok {
		return NsecToFiletime(t.UnixNano())
	}
	return &Filetime{}
}

func ChangeTimeFromVfs(a *vfs.Attributes) *Filetime {
	if t, ok := a.GetLastStatusChangeTime(); ok {
		return NsecToFiletime(t.UnixNano())
	}
	return &Filetime{}
}

func SizeFromVfs(a *vfs.Attributes) uint64 {
	if s, ok := a.GetSizeBytes(); ok {
		return s
	}
	return 0
}

func UnixModeFromVfs(a *vfs.Attributes) uint16 {
	if s, ok := a.GetUnixMode(); ok {
		return uint16(s)
	}
	return 0777
}

func DiskSizeFromVfs(a *vfs.Attributes) uint64 {
	if s, ok := a.GetDiskSizeBytes(); ok {
		return s
	}
	return SizeFromVfs(a)
}

func PermissionsFromVfs(a *vfs.Attributes, path string) uint32 {
	perm := uint32(0)
	name := filepath.Base(path)
	if len(name) > 0 && name[0] == '.' {
		perm |= FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_ARCHIVE
	}
	if p, ok := a.GetPermissions(); ok {
		if p&vfs.PermissionsWrite == 0 {
			perm = FILE_ATTRIBUTE_READONLY
		}
	}
	if a.GetFileType() == vfs.FileTypeDirectory {
		perm |= FILE_ATTRIBUTE_DIRECTORY
	}
	if a.GetFileType() == vfs.FileTypeSymlink {
		perm |= FILE_ATTRIBUTE_REPARSE_POINT
	}

	if perm == 0 {
		perm = FILE_ATTRIBUTE_NORMAL
	}
	return perm
}

func MaxAccessFromVfs(a *vfs.Attributes) uint32 {
	maximalAccess := uint32(0)
	unixMode, ok := a.GetUnixMode()
	if !ok {
		unixMode = 0777
	}
	maximalAccess = SYNCHRONIZE

	if unixMode&0404 != 0 {
		maximalAccess |= FILE_READ_ATTRIBUTES | FILE_READ_DATA | FILE_READ_EA
		if unixMode&0400 != 0 {
			maximalAccess |= READ_CONTROL
		}
	}
	if unixMode&0202 != 0 {
		maximalAccess |= FILE_WRITE_ATTRIBUTES | FILE_WRITE_DATA | FILE_WRITE_EA | FILE_APPEND_DATA
		if unixMode&0200 != 0 {
			maximalAccess |= WRITE_DAC | WRITE_OWNER
			maximalAccess |= DELETE | FILE_DELETE_CHILD
		}
	}
	if unixMode&0101 != 0 {
		maximalAccess |= FILE_EXECUTE
	}
	return maximalAccess
}

func PrepareResponse(rsp *PacketHeader, req []byte, status uint32) {
	p := PacketCodec(req)
	rsp.Command = p.Command()
	rsp.CreditRequestResponse = p.CreditRequest()
	rsp.MessageId = p.MessageId()
	rsp.Flags = 1 | (p.Flags() & SMB2_FLAGS_PRIORITY_MASK)
	rsp.Status = status
}

func PrepareAsyncResponse(rsp *PacketHeader, req []byte, asyncId uint64, status uint32) {
	p := PacketCodec(req)
	rsp.Command = p.Command()
	rsp.CreditRequestResponse = p.CreditRequest()
	rsp.MessageId = p.MessageId()
	rsp.Flags = SMB2_FLAGS_SERVER_TO_REDIR
	if asyncId != 0 {
		rsp.Flags |= SMB2_FLAGS_ASYNC_COMMAND
	}
	rsp.Status = status
	rsp.AsyncId = asyncId
}

func IsInvalidFileId(f *FileId) bool {
	inv := [8]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	return f == nil ||
		(reflect.DeepEqual(f.Persistent, inv) && reflect.DeepEqual(f.Volatile, inv))
}

func IsEA(p string) bool {
	return strings.Contains(p, ":")
}

func SplitEA(p string) (string, string) {
	a := strings.Split(p, ":")
	return a[0], a[1]
}
