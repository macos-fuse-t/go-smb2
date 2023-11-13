package vfs

type FileType int

const (
	// FileTypeRegularFile means the file is a regular file.
	FileTypeRegularFile FileType = iota
	// FileTypeDirectory means the file is a directory.
	FileTypeDirectory
	// FileTypeSymlink means the file is a symbolic link.
	FileTypeSymlink
	// FileTypeBlockDevice means the file is a block device.
	FileTypeBlockDevice
	// FileTypeCharacterDevice means the file is a character device.
	FileTypeCharacterDevice
	// FileTypeFIFO means the file is a FIFO.
	FileTypeFIFO
	// FileTypeSocket means the file is a socket.
	FileTypeSocket
	// FileTypeOther means the file is neither a regular file, a
	// directory or symbolic link.
	FileTypeNamedAttributeDir
	FileTypeNamedAttribute
	// FileTypeOther means the file is neither a regular file, a
	// directory or symbolic link.
	FileTypeOther
)
