package vfs

type VfsNode uint64
type VfsHandle uint64

const VFS_ROOT_NODE = VfsNode(1)

type EntryReply struct {
	Node       VfsNode
	Generation uint64
	Attrs      Attributes
}

type DirInfo struct {
	Name string
	Attributes
}

type VFSFileSystem interface {
	GetAttr(VfsHandle) (*Attributes, error)
	SetAttr(VfsHandle, *Attributes) (*Attributes, error)

	StatFS(VfsHandle) (*FSAttributes, error)

	FSync(VfsHandle) error
	Flush(VfsHandle) error

	//Mknod(VfsNode, string, int, int) (*EntryReply, error)
	//Create(VfsNode, string, int, int) (*EntryReply, VfsHandle, error)

	Open(string, int, int) (VfsHandle, error) //int: flag, int: os.FileMode
	Close(VfsHandle) error

	Lookup(VfsHandle, string) (*Attributes, error)

	Mkdir(string, int) (*Attributes, error) //int: os.FileMode

	Read(VfsHandle, []byte, uint64, int) (int, error)  //[]byte: buf, uint64: offset
	Write(VfsHandle, []byte, uint64, int) (int, error) //[]byte: data, uint64: offset, int: flag

	OpenDir(string) (VfsHandle, error)
	ReadDir(VfsHandle, int, int) ([]DirInfo, error) //int: pos, int: length

	Readlink(VfsHandle) (string, error)

	Remove(VfsHandle) error

	//Rmdir(VfsNode, string) error

	Truncate(VfsHandle, uint64) error    //uint64: size
	Rename(VfsHandle, string, int) error //int:0x01 ReplaceIfExists

	Symlink(VfsHandle, string, int) (*Attributes, error) //int: flag
	Link(VfsNode, VfsNode, string) (*Attributes, error)  //not implement

	Listxattr(VfsHandle) ([]string, error)
	Getxattr(VfsHandle, string, []byte) (int, error)
	Setxattr(VfsHandle, string, []byte) error
	Removexattr(VfsHandle, string) error

	//RegisterNotify(VfsHandle, chan *NotifyEvent) error
	//RemoveNotify(VfsHandle) error
}

// ShareMask is a bitmask of operations that are permitted
type ShareMask uint32

const (
	// ShareMaskRead permits calls to VirtualRead().
	ShareMaskRead ShareMask = 1 << iota
	// ShareMaskWrite permits calls to VirtualWrite().
	ShareMaskWrite
)

type NotifyEvent struct {
	EvType uint8
	Handle VfsHandle
	Name   string
}
