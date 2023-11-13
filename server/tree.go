package smb2

type treeConn struct {
	*session
	treeId     uint32
	shareFlags uint32
	path       string

	// shareType  uint8
	// capabilities uint32
	// maximalAccess uint32
}

type treeOps interface {
	getTree() *treeConn
	create(ctx *compoundContext, pkt []byte) error
	close(ctx *compoundContext, pkt []byte) error
	flush(ctx *compoundContext, pkt []byte) error
	write(ctx *compoundContext, pkt []byte) error
	read(ctx *compoundContext, pkt []byte) error
	ioctl(ctx *compoundContext, pkt []byte) error
	cancel(ctx *compoundContext, pkt []byte) error
	queryDirectory(ctx *compoundContext, pkt []byte) error
	changeNotify(ctx *compoundContext, pkt []byte) error
	queryInfo(ctx *compoundContext, pkt []byte) error
	setInfo(ctx *compoundContext, pkt []byte) error
	lock(ctx *compoundContext, pkt []byte) error
	oplockBreak(ctx *compoundContext, pkt []byte) error
}
