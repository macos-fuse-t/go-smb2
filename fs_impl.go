package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/fsnotify/fsnotify"
	"github.com/macos-fuse-t/go-smb2/stats"
	"github.com/macos-fuse-t/go-smb2/vfs"
	"github.com/pkg/xattr"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

type OpenFile struct {
	path    string
	isDir   bool
	f       *os.File
	h       vfs.VfsHandle
	watcher *fsnotify.Watcher
	dirPos  int
}

type PassthroughFS struct {
	rootPath  string
	openFiles sync.Map
	//watcher   *fsnotify.Watcher
}

func NewPassthroughFS(rootPath string) *PassthroughFS {
	//watcher, _ := fsnotify.NewWatcher()
	return &PassthroughFS{
		rootPath:  rootPath,
		openFiles: sync.Map{},
		//watcher:   watcher,
	}
}

func (fs *PassthroughFS) GetAttr(handle vfs.VfsHandle) (*vfs.Attributes, error) {
	p := fs.rootPath
	if handle != 0 {
		v, ok := fs.openFiles.Load(handle)
		if !ok {
			log.Errorf("GetAttr: filehandle not found %d", handle)
			return nil, fmt.Errorf("bad handle")
		}
		open := v.(*OpenFile)
		p = open.path
	}

	info, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}

	a, err := fileInfoToAttr(info)
	if err != nil {
		return nil, err
	}

	return a, nil
}

func (fs *PassthroughFS) SetAttr(handle vfs.VfsHandle, a *vfs.Attributes) (*vfs.Attributes, error) {
	if handle == 0 {
		return nil, fmt.Errorf("bad handle")
	}

	v, ok := fs.openFiles.Load(handle)
	if !ok {
		log.Errorf("SetAttr: filehandle not found %d", handle)
		return nil, fmt.Errorf("bad handle")
	}
	open := v.(*OpenFile)

	oldAttrs, err := fs.GetAttr(handle)
	if err != nil {
		log.Errorf("SetAttr: failed to read vfs.Attributes")
		return nil, fmt.Errorf("failed to read attributese")
	}

	atime, atimeSet := a.GetAccessTime()
	if !atimeSet {
		atime, _ = oldAttrs.GetAccessTime()
	}
	mtime, mtimeSet := a.GetLastDataModificationTime()
	if !mtimeSet {
		mtime, _ = oldAttrs.GetLastDataModificationTime()
	}

	if atimeSet || mtimeSet {
		os.Chtimes(open.path, atime, mtime)
	}

	if mode, mSet := a.GetUnixMode(); mSet {
		os.Chmod(open.path, os.FileMode(mode))
	}

	return nil, nil
}

func (fs *PassthroughFS) StatFS(handle vfs.VfsHandle) (*vfs.FSAttributes, error) {
	var statfs unix.Statfs_t
	if err := unix.Statfs(fs.rootPath, &statfs); err != nil {
		log.Errorf("statfs")
		return nil, err
	}

	a := vfs.FSAttributes{}
	a.SetAvailableBlocks(statfs.Bavail)
	a.SetBlockSize(uint64(statfs.Bsize))
	a.SetBlocks(statfs.Bavail)
	a.SetFiles(statfs.Files)
	a.SetFreeBlocks(statfs.Bfree)
	a.SetFreeFiles(statfs.Ffree)
	a.SetIOSize(uint64(statfs.Bsize))
	return &a, nil
}

func (fs *PassthroughFS) FSync(handle vfs.VfsHandle) error {
	if handle == 0 {
		return fmt.Errorf("bad handle")
	}

	v, ok := fs.openFiles.Load(handle)
	if !ok {
		log.Errorf("FSync: filehandle not found %d", handle)
		return fmt.Errorf("bad handle")
	}
	open := v.(*OpenFile)
	return open.f.Sync()
}

func (fs *PassthroughFS) Flush(handle vfs.VfsHandle) error {
	return nil
}

func (fs *PassthroughFS) Mknod(vfs.VfsNode, string, int, int) (*vfs.Attributes, error) {
	return nil, nil
}

func (fs *PassthroughFS) Create(vfs.VfsNode, string, int, int) (*vfs.Attributes, vfs.VfsHandle, error) {
	return nil, 0, nil
}

func randint64() uint64 {
	var b [8]byte
	rand.Read(b[:])
	return uint64(binary.LittleEndian.Uint64(b[:]))
}

func (fs *PassthroughFS) Open(p string, flags int, mode int) (vfs.VfsHandle, error) {
	p = path.Join(fs.rootPath, p)

	var f *os.File
	var err error
	if flags&0x200000 != 0 {
		// O_SYMLINK, O_PATH
		var fd int
		fd, err = syscall.Open(p, 0x200000, 0)
		f = os.NewFile(uintptr(fd), p)
	} else {
		f, err = os.OpenFile(p, flags, os.FileMode(mode))
	}

	if err != nil {
		log.Errorf("open %s: %v, flags %x", p, err, flags)
		return 0, err
	}

	log.Debugf("open %s success: %d", p, f.Fd())
	h := vfs.VfsHandle(randint64())
	fs.openFiles.Store(vfs.VfsHandle(h), &OpenFile{f: f, h: h, path: p})

	stats.AddOpen(p)

	return h, nil
}

func (fs *PassthroughFS) Close(handle vfs.VfsHandle) error {
	v, ok := fs.openFiles.Load(handle)
	if !ok {
		log.Errorf("Close: filehandle not found %d", handle)
		return fmt.Errorf("bad handle")
	}
	open := v.(*OpenFile)

	fs.RemoveNotify(handle)

	open.f.Close()
	fs.openFiles.Delete(handle)

	log.Debugf("closing %d", handle)

	return nil
}

func (fs *PassthroughFS) Lookup(handle vfs.VfsHandle, name string) (*vfs.Attributes, error) {

	p := fs.rootPath
	if handle != 0 {
		v, ok := fs.openFiles.Load(handle)
		if !ok {
			log.Errorf("Lookup: filehandle not found %d", handle)
			return nil, fmt.Errorf("bad handle")
		}
		open := v.(*OpenFile)
		p = open.path
	}

	info, err := os.Lstat(path.Join(p, name))
	if err != nil {
		return nil, err
	}

	a, err := fileInfoToAttr(info)
	if err != nil {
		return nil, err
	}
	return a, nil
}

func (fs *PassthroughFS) Mkdir(p string, mode int) (*vfs.Attributes, error) {
	p = path.Join(fs.rootPath, p)
	if err := os.Mkdir(p, os.FileMode(mode)); err != nil {
		return nil, err
	}

	info, err := os.Stat(p)
	if err != nil {
		return nil, err
	}

	a, err := fileInfoToAttr(info)
	if err != nil {
		return nil, err
	}

	stats.AddMkdir(p)

	return a, nil
}

func (fs *PassthroughFS) Read(handle vfs.VfsHandle, buf []byte, offset uint64, flags int) (int, error) {
	if handle == 0 {
		return 0, fmt.Errorf("bad handle")
	}

	v, ok := fs.openFiles.Load(handle)
	if !ok {
		log.Errorf("Read: filehandle not found %d", handle)
		return 0, fmt.Errorf("bad handle")
	}
	open := v.(*OpenFile)

	stats.AddReadBytes(open.path, uint64(len(buf)))

	return open.f.ReadAt(buf, int64(offset))
}

func (fs *PassthroughFS) Write(handle vfs.VfsHandle, buf []byte, offset uint64, flags int) (int, error) {
	if handle == 0 {
		return 0, fmt.Errorf("bad handle")
	}

	v, ok := fs.openFiles.Load(handle)
	if !ok {
		log.Errorf("Write: filehandle not found %d", handle)
		return 0, fmt.Errorf("bad handle")
	}
	open := v.(*OpenFile)

	stats.AddWriteBytes(open.path, uint64(len(buf)))

	return open.f.WriteAt(buf, int64(offset))
}

func getExtendedFileInfo(info os.DirEntry) (*vfs.DirInfo, error) {
	stat, err := info.Info()
	if err != nil {
		return nil, err
	}

	i := vfs.DirInfo{
		Name: info.Name(),
	}

	a, err := fileInfoToAttr(stat)
	if err != nil {
		return nil, err
	}
	i.Attributes = *a

	return &i, nil
}

func (fs *PassthroughFS) OpenDir(p string) (vfs.VfsHandle, error) {
	p = path.Join(fs.rootPath, p)
	f, err := os.OpenFile(p, 0, 0)
	if err != nil {
		log.Errorf("OpenDir %s: %v", p, err)
		return 0, err
	}
	log.Debugf("open %s success: %d", p, f.Fd())
	h := vfs.VfsHandle(randint64())
	fs.openFiles.Store(h, &OpenFile{f: f, h: h, path: p, isDir: true})

	return h, nil
}

func (fs *PassthroughFS) readDir(open *OpenFile, pos int, maxEntries int) ([]vfs.DirInfo, error) {
	var results []vfs.DirInfo
	if pos != 0 {
		open.f.Seek(0, 0)
		open.dirPos = 0
	}

	if open.dirPos == 0 {
		attrs, err := fs.GetAttr(open.h)
		if err != nil {
			return nil, err
		}

		if open.dirPos == 0 {
			results = append(results,
				vfs.DirInfo{
					Name:       ".",
					Attributes: *attrs,
				},
				vfs.DirInfo{
					Name:       "..",
					Attributes: *attrs,
				})
		}
	}

	entries, err := open.f.ReadDir(maxEntries)
	if err != nil && (err != io.EOF || open.dirPos != 0) {
		log.Debugf("ReadDir: err %v", err)
		return nil, err
	}
	for _, entry := range entries {
		info, err := getExtendedFileInfo(entry)
		if err != nil {
			log.Errorf("getExtendedFileInfo: %v", err)
			return nil, err
		}
		results = append(results, *info)
	}
	open.dirPos = 1

	return results, nil
}

func (fs *PassthroughFS) ReadDir(handle vfs.VfsHandle, pos int, maxEntries int) ([]vfs.DirInfo, error) {
	log.Debugf("ReadDir: %v, pos %d", handle, pos)
	if handle == 0 {
		return nil, nil
	}

	v, ok := fs.openFiles.Load(handle)
	if !ok {
		log.Errorf("ReadDir: filehandle not found %d", handle)
		return nil, fmt.Errorf("bad handle")
	}
	open := v.(*OpenFile)

	return fs.readDir(open, pos, maxEntries)
}

func (fs *PassthroughFS) Readlink(handle vfs.VfsHandle) (string, error) {
	if handle == 0 {
		return "", fmt.Errorf("bad handle")
	}

	v, ok := fs.openFiles.Load(handle)
	if !ok {
		log.Errorf("readlink: filehandle not found %d", handle)
		return "", fmt.Errorf("bad handle")
	}
	open := v.(*OpenFile)
	return os.Readlink(open.path)
}

func (fs *PassthroughFS) Unlink(handle vfs.VfsHandle) error {
	if handle == 0 {
		return fmt.Errorf("bad handle")
	}

	v, ok := fs.openFiles.Load(handle)
	if !ok {
		log.Errorf("write: filehandle not found %d", handle)
		return fmt.Errorf("bad handle")
	}
	open := v.(*OpenFile)
	log.Debugf("removing %s", open.path)

	stats.AddDelete(open.path)

	return os.Remove(open.path)
}

func (fs *PassthroughFS) Rmdir(vfs.VfsNode, string) error {
	return nil
}

func (fs *PassthroughFS) Rename(from vfs.VfsHandle, to string, flags int) error {
	if from == 0 {
		return fmt.Errorf("bad handle")
	}

	v, ok := fs.openFiles.Load(from)
	if !ok {
		log.Errorf("rename: filehandle not found %d", from)
		return fmt.Errorf("bad handle")
	}
	open := v.(*OpenFile)

	// flags == 1 : replace if exists
	if flags == 0 {
		if _, err := os.Stat(to); err == nil {
			return fmt.Errorf("already exists")
		}
	}

	stats.AddRename(open.path)

	log.Debugf("rename: %s to %s", open.path, path.Join(fs.rootPath, to))
	return os.Rename(open.path, path.Join(fs.rootPath, to))
}

func (fs *PassthroughFS) Symlink(targetHandle vfs.VfsHandle, source string, flag int) (*vfs.Attributes, error) {
	v, ok := fs.openFiles.Load(targetHandle)
	if !ok {
		log.Errorf("symlink: filehandle not found %d", targetHandle)
		return nil, fmt.Errorf("bad handle")
	}
	open := v.(*OpenFile)

	targetDir := filepath.Dir(open.path)
	sourceDir := filepath.Dir(path.Clean(path.Join(targetDir, source)))

	target := open.path
	curDir, _ := os.Getwd()
	if flag != 0 {
		os.Chdir(targetDir)
		target = path.Base(open.path)
	}
	log.Debugf("td %s sd %s, t %s s %s", targetDir, sourceDir, target, source)
	if targetDir == sourceDir && target == source {
		log.Errorf("can't create symlink for the same file")
		return nil, fmt.Errorf("already exists")
	}
	os.Remove(open.path)

	log.Debugf("symlink %s -> %s", source, target)
	err := os.Symlink(source, target)
	if flag != 0 {
		os.Chdir(curDir)
	}

	if err != nil {
		log.Errorf("symlink failed: %s -> %s, %v", source, target, err)
		return nil, err
	}

	info, err := os.Lstat(open.path)
	if err != nil {
		return nil, err
	}

	a, err := fileInfoToAttr(info)
	if err != nil {
		return nil, err
	}

	stats.AddSymlink(open.path)

	return a, err
}

func (fs *PassthroughFS) Link(vfs.VfsNode, vfs.VfsNode, string) (*vfs.Attributes, error) {
	return nil, nil
}

func (fs *PassthroughFS) Listxattr(handle vfs.VfsHandle) ([]string, error) {
	if handle == 0 {
		return nil, fmt.Errorf("bad handle")
	}

	v, ok := fs.openFiles.Load(handle)
	if !ok {
		log.Errorf("listxattr: filehandle not found %d", handle)
		return nil, fmt.Errorf("bad handle")
	}
	open := v.(*OpenFile)

	stats.AddXattrList(open.path)

	return xattr.FList(open.f)
}

func (fs *PassthroughFS) Getxattr(handle vfs.VfsHandle, key string, val []byte) (int, error) {
	if handle == 0 {
		return 0, fmt.Errorf("getxattr: bad handle")
	}

	o, ok := fs.openFiles.Load(handle)
	if !ok {
		log.Errorf("getxattr: filehandle not found %d", handle)
		return 0, fmt.Errorf("bad handle")
	}
	open := o.(*OpenFile)

	v, err := xattr.FGet(open.f, key)
	if err != nil {
		return 0, err
	}

	n := len(v)
	if val != nil {
		n = copy(val, v)
	}

	stats.AddXattrRead(open.path)
	return n, nil
}

func (fs *PassthroughFS) Setxattr(handle vfs.VfsHandle, key string, val []byte) error {
	if handle == 0 {
		return fmt.Errorf("setxattr: bad handle")
	}

	v, ok := fs.openFiles.Load(handle)
	if !ok {
		log.Errorf("setxattr: filehandle not found %d", handle)
		return fmt.Errorf("bad handle")
	}
	open := v.(*OpenFile)

	stats.AddXattrWrite(open.path)
	return xattr.FSet(open.f, key, val)
}

func (fs *PassthroughFS) Removexattr(handle vfs.VfsHandle, key string) error {
	if handle == 0 {
		return fmt.Errorf("setxattr: bad handle")
	}

	v, ok := fs.openFiles.Load(handle)
	if !ok {
		log.Errorf("setxattr: filehandle not found %d", handle)
		return fmt.Errorf("bad handle")
	}
	open := v.(*OpenFile)

	stats.AddXattrDelete(open.path)
	return xattr.FRemove(open.f, key)
}

func (fs *PassthroughFS) Truncate(handle vfs.VfsHandle, len uint64) error {
	v, ok := fs.openFiles.Load(handle)
	if !ok {
		log.Errorf("truncate: filehandle not found %d", handle)
		return fmt.Errorf("bad handle")
	}
	open := v.(*OpenFile)

	stats.AddDelete(open.path)

	return os.Truncate(open.path, int64(len))
}

func fileInfoToAttr(stat os.FileInfo) (*vfs.Attributes, error) {
	sysStat, ok := vfs.CompatStat(stat)
	if !ok {
		return nil, fmt.Errorf("failed to convert to syscall.Stat_t")
	}

	a := vfs.Attributes{}
	a.SetInodeNumber(sysStat.Ino)
	a.SetSizeBytes(uint64(stat.Size()))
	a.SetDiskSizeBytes(uint64(sysStat.Blocks * 512))
	a.SetUnixMode(uint32(stat.Mode()))
	a.SetPermissions(vfs.NewPermissionsFromMode(uint32(stat.Mode().Perm())))
	a.SetAccessTime(sysStat.Atime)
	a.SetLastDataModificationTime(stat.ModTime())
	a.SetBirthTime(sysStat.Btime)
	a.SetLastStatusChangeTime(sysStat.Ctime)
	if stat.IsDir() {
		a.SetFileType(vfs.FileTypeDirectory)
	} else if stat.Mode()&os.ModeSymlink != 0 {
		a.SetFileType(vfs.FileTypeSymlink)
	} else {
		a.SetFileType(vfs.FileTypeRegularFile)
	}
	return &a, nil
}

func (fs *PassthroughFS) RegisterNotify(handle vfs.VfsHandle, ch chan *vfs.NotifyEvent) error {
	if handle == 0 {
		return fmt.Errorf("bad handle")
	}

	v, ok := fs.openFiles.Load(handle)
	if !ok {
		log.Errorf("RegisterNotify: filehandle not found %d", handle)
		return fmt.Errorf("bad handle")
	}
	open := v.(*OpenFile)

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Errorf("failed creating a new watcher: %v", err)
		return err
	}
	open.watcher = watcher
	go fs.eventListener(handle, open, ch)
	return watcher.Add(open.path)
}

func (fs *PassthroughFS) RemoveNotify(handle vfs.VfsHandle) error {
	log.Debugf("RemoveNotify %d", handle)
	if handle == 0 {
		return fmt.Errorf("bad handle")
	}

	v, ok := fs.openFiles.Load(handle)
	if !ok {
		log.Errorf("RegisterNotify: filehandle not found %d", handle)
		return fmt.Errorf("bad handle")
	}
	open := v.(*OpenFile)
	if open.watcher != nil {
		open.watcher.Close()
	}
	//open.watcher = nil

	return nil
}

func (fs *PassthroughFS) eventListener(handle vfs.VfsHandle, open *OpenFile, ch chan *vfs.NotifyEvent) {
	// Start listening for events.
	for {
		select {
		case event, ok := <-open.watcher.Events:
			if !ok {
				log.Errorf("watcher closed")
				return
			}
			log.Errorf("watcher event: %+v", event)
			//n, _ := strconv.Unquote(event.Name)
			p := filepath.Base(event.Name)
			if p != "" {
				log.Errorf("watcher event sending: %s", p)
				ch <- &vfs.NotifyEvent{Handle: handle, Name: p}
			}
			//if event.Has(fsnotify.Write) {
			//	log.Println("modified file:", event.Name)
			//}
		case err, ok := <-open.watcher.Errors:
			if !ok {
				log.Errorf("watcher closed")
				return
			}
			log.Errorf("watcher error: %v", err)
		}
	}
}
