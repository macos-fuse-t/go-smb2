package smb2

import (
	"errors"
	"testing"

	. "github.com/macos-fuse-t/go-smb2/internal/smb2"
	"github.com/macos-fuse-t/go-smb2/vfs"
)

type deleteDispositionFS struct {
	attrs    vfs.Attributes
	dir      []vfs.DirInfo
	unlinked int
}

func newDeleteDispositionFS(fileType vfs.FileType) *deleteDispositionFS {
	attrs := vfs.Attributes{}
	attrs.SetFileType(fileType)
	attrs.SetInodeNumber(42)
	attrs.SetLinkCount(1)
	return &deleteDispositionFS{attrs: attrs}
}

func (fs *deleteDispositionFS) GetAttr(vfs.VfsHandle) (*vfs.Attributes, error) {
	return &fs.attrs, nil
}

func (fs *deleteDispositionFS) SetAttr(vfs.VfsHandle, *vfs.Attributes) (*vfs.Attributes, error) {
	return nil, errors.New("not implemented")
}

func (fs *deleteDispositionFS) StatFS(vfs.VfsHandle) (*vfs.FSAttributes, error) {
	return nil, errors.New("not implemented")
}

func (fs *deleteDispositionFS) FSync(vfs.VfsHandle) error {
	return errors.New("not implemented")
}

func (fs *deleteDispositionFS) Flush(vfs.VfsHandle) error {
	return errors.New("not implemented")
}

func (fs *deleteDispositionFS) Open(string, int, int) (vfs.VfsHandle, error) {
	return 0, errors.New("not implemented")
}

func (fs *deleteDispositionFS) Close(vfs.VfsHandle) error {
	return nil
}

func (fs *deleteDispositionFS) Lookup(vfs.VfsHandle, string) (*vfs.Attributes, error) {
	return nil, errors.New("not implemented")
}

func (fs *deleteDispositionFS) Mkdir(string, int) (*vfs.Attributes, error) {
	return nil, errors.New("not implemented")
}

func (fs *deleteDispositionFS) Read(vfs.VfsHandle, []byte, uint64, int) (int, error) {
	return 0, errors.New("not implemented")
}

func (fs *deleteDispositionFS) Write(vfs.VfsHandle, []byte, uint64, int) (int, error) {
	return 0, errors.New("not implemented")
}

func (fs *deleteDispositionFS) OpenDir(string) (vfs.VfsHandle, error) {
	return 0, errors.New("not implemented")
}

func (fs *deleteDispositionFS) ReadDir(vfs.VfsHandle, int, int) ([]vfs.DirInfo, error) {
	return fs.dir, nil
}

func (fs *deleteDispositionFS) Readlink(vfs.VfsHandle) (string, error) {
	return "", errors.New("not implemented")
}

func (fs *deleteDispositionFS) Unlink(vfs.VfsHandle) error {
	fs.unlinked++
	return nil
}

func (fs *deleteDispositionFS) Truncate(vfs.VfsHandle, uint64) error {
	return errors.New("not implemented")
}

func (fs *deleteDispositionFS) Rename(vfs.VfsHandle, string, int) error {
	return errors.New("not implemented")
}

func (fs *deleteDispositionFS) Symlink(vfs.VfsHandle, string, int) (*vfs.Attributes, error) {
	return nil, errors.New("not implemented")
}

func (fs *deleteDispositionFS) Link(vfs.VfsNode, vfs.VfsNode, string) (*vfs.Attributes, error) {
	return nil, errors.New("not implemented")
}

func (fs *deleteDispositionFS) Listxattr(vfs.VfsHandle) ([]string, error) {
	return nil, errors.New("not implemented")
}

func (fs *deleteDispositionFS) Getxattr(vfs.VfsHandle, string, []byte) (int, error) {
	return 0, errors.New("not implemented")
}

func (fs *deleteDispositionFS) Setxattr(vfs.VfsHandle, string, []byte) error {
	return errors.New("not implemented")
}

func (fs *deleteDispositionFS) Removexattr(vfs.VfsHandle, string) error {
	return errors.New("not implemented")
}

func newDeleteDispositionTree(fs vfs.VFSFileSystem) *fileTree {
	return &fileTree{
		treeConn: treeConn{
			session: &session{
				conn: &conn{
					serverCtx: &Server{
						opens:         map[uint64]*Open{},
						deletePending: map[uint64]bool{},
					},
				},
			},
		},
		fs: fs,
	}
}

func TestPosixDeleteDispositionUnlinksImmediately(t *testing.T) {
	fs := newDeleteDispositionFS(vfs.FileTypeRegularFile)
	tree := newDeleteDispositionTree(fs)
	fileId := &FileId{}
	fileId.SetHandleId(7)
	open := &Open{durableFileId: 42, posixSemantics: true}

	if status := tree.applyDeleteDisposition(fileId, open); status != 0 {
		t.Fatalf("status = %#x, want success", status)
	}
	if fs.unlinked != 1 {
		t.Fatalf("unlink count = %d, want 1", fs.unlinked)
	}
	if tree.conn.serverCtx.isDeletePending(42) {
		t.Fatalf("POSIX delete left inode delete-pending")
	}
}

func TestWindowsDeleteDispositionMarksDeletePending(t *testing.T) {
	fs := newDeleteDispositionFS(vfs.FileTypeRegularFile)
	tree := newDeleteDispositionTree(fs)
	fileId := &FileId{}
	fileId.SetHandleId(7)
	open := &Open{durableFileId: 42}

	if status := tree.applyDeleteDisposition(fileId, open); status != 0 {
		t.Fatalf("status = %#x, want success", status)
	}
	if fs.unlinked != 0 {
		t.Fatalf("unlink count = %d, want 0", fs.unlinked)
	}
	if !tree.conn.serverCtx.isDeletePending(42) {
		t.Fatalf("Windows delete did not mark inode delete-pending")
	}
}

func TestPosixDeleteOnCloseUnlinksAndBypassesDeletePending(t *testing.T) {
	fs := newDeleteDispositionFS(vfs.FileTypeRegularFile)
	tree := newDeleteDispositionTree(fs)
	fileId := &FileId{}
	fileId.SetHandleId(7)
	open := &Open{durableFileId: 42, deleteOnClose: true, posixSemantics: true}

	if err := tree.applyPosixDeleteOnClose(fileId, open); err != nil {
		t.Fatal(err)
	}
	if fs.unlinked != 1 {
		t.Fatalf("unlink count = %d, want 1", fs.unlinked)
	}
	if open.deleteOnClose {
		t.Fatalf("POSIX delete-on-close left Windows delete-on-close flag set")
	}
	if tree.conn.serverCtx.closeOpen(open) {
		t.Fatalf("closeOpen requested delayed unlink after POSIX delete-on-close")
	}
	if tree.conn.serverCtx.isDeletePending(42) {
		t.Fatalf("POSIX delete-on-close left inode delete-pending")
	}
}
