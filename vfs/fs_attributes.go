package vfs

// AttributesMask is a bitmask of status attributes that need to be
// requested through Node.VirtualGetAttributes().
type FSAttributesMask uint32

const (
	AttributesMaskBlockSize FSAttributesMask = 1 << iota
	AttributesMaskIOSize
	AttributesMaskBlocks
	AttributesMaskFreeBlocks
	AttributesMaskAvailableBlocks
	AttributesMaskFileNodes
	AttributesMaskFreeFileNodes
)

type FSAttributes struct {
	fieldsPresent FSAttributesMask
	bsize         uint64 //block size
	iosize        uint64 // optimal transfer block size
	blocks        uint64 // total data blocks in file system
	bfree         uint64 // free blocks in fs
	bavail        uint64 // free blocks avail to non-superuser
	files         uint64 // total file nodes in file system
	ffree         uint64 // free file nodes in fs
}

func (a *FSAttributes) GetBlockSize() (uint64, bool) {
	return a.bsize, a.fieldsPresent&AttributesMaskBlockSize != 0
}

func (a *FSAttributes) SetBlockSize(bsize uint64) *FSAttributes {
	a.bsize = bsize
	a.fieldsPresent |= AttributesMaskBlockSize
	return a
}

func (a *FSAttributes) GetIOkSize() (uint64, bool) {
	return a.iosize, a.fieldsPresent&AttributesMaskIOSize != 0
}

func (a *FSAttributes) SetIOSize(iosize uint64) *FSAttributes {
	a.iosize = iosize
	a.fieldsPresent |= AttributesMaskIOSize
	return a
}

func (a *FSAttributes) GetBlocks() (uint64, bool) {
	return a.blocks, a.fieldsPresent&AttributesMaskBlocks != 0
}

func (a *FSAttributes) SetBlocks(blocks uint64) *FSAttributes {
	a.blocks = blocks
	a.fieldsPresent |= AttributesMaskBlocks
	return a
}

func (a *FSAttributes) GetFreeBlocks() (uint64, bool) {
	return a.bfree, a.fieldsPresent&AttributesMaskFreeBlocks != 0
}

func (a *FSAttributes) SetFreeBlocks(freeBlocks uint64) *FSAttributes {
	a.bfree = freeBlocks
	a.fieldsPresent |= AttributesMaskFreeBlocks
	return a
}

func (a *FSAttributes) GetAvailableBlocks() (uint64, bool) {
	return a.bavail, a.fieldsPresent&AttributesMaskAvailableBlocks != 0
}

func (a *FSAttributes) SetAvailableBlocks(availBlocks uint64) *FSAttributes {
	a.bavail = availBlocks
	a.fieldsPresent |= AttributesMaskAvailableBlocks
	return a
}

func (a *FSAttributes) GetFiles() (uint64, bool) {
	return a.files, a.fieldsPresent&AttributesMaskFileNodes != 0
}

func (a *FSAttributes) SetFiles(files uint64) *FSAttributes {
	a.files = files
	a.fieldsPresent |= AttributesMaskFileNodes
	return a
}

func (a *FSAttributes) GetFreeFiles() (uint64, bool) {
	return a.ffree, a.fieldsPresent&AttributesMaskFreeFileNodes != 0
}

func (a *FSAttributes) SetFreeFiles(freeFiles uint64) *FSAttributes {
	a.ffree = freeFiles
	a.fieldsPresent |= AttributesMaskFreeFileNodes
	return a
}
