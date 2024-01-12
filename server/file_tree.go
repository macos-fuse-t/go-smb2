package smb2

import (
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"syscall"
	"time"

	. "github.com/macos-fuse-t/go-smb2/internal/erref"
	. "github.com/macos-fuse-t/go-smb2/internal/smb2"
	"github.com/macos-fuse-t/go-smb2/vfs"
	log "github.com/sirupsen/logrus"
)

const (
	O_SHLOCK = 0x10
	O_EXLOCK = 0x20
)

type fileTree struct {
	treeConn
	fs vfs.VFSFileSystem

	openFiles      map[uint64]bool
	aaplExtensions bool

	ioReadSem  chan struct{}
	ioWriteSem chan struct{}
}

func (t *fileTree) getTree() *treeConn {
	return &t.treeConn
}

func (t *fileTree) create(ctx *compoundContext, pkt []byte) error {
	log.Debugf("fileTreeCreate")

	c := t.session.conn

	res, err := accept(SMB2_CREATE, pkt)
	if err != nil {
		return err
	}

	r := CreateRequestDecoder(res)
	if r.IsInvalid() {
		return &InvalidRequestError{"broken create format"}
	}

	log.Debugf("create name: %s, options %d, disp %d", r.Name(), r.CreateOptions(), r.CreateDisposition())

	rsp := new(CreateResponse)
	rsp.FileId = &FileId{}
	PrepareResponse(&rsp.PacketHeader, pkt, 0)

	name := r.Name()
	if name == "" {
		name = "/"
	} else {
		name = strings.ReplaceAll(name, "\\", "/")
	}

	isEA := IsEA(name)
	eaKey := ""
	if isEA {
		name, eaKey = SplitEA(name)
	}

	if r.SmbCreateFlags() != 0 {
		log.Errorf("Create flags: %d", r.SmbCreateFlags())
	}

	attrs, err := t.fs.Lookup(0, name)
	fileExists := err == nil
	isDir := fileExists && attrs.GetFileType() == vfs.FileTypeDirectory
	flags := 0
	createDir := r.CreateOptions()&FILE_DIRECTORY_FILE != 0
	err = nil
	isSymlink := fileExists && (attrs.GetFileType() == vfs.FileTypeSymlink) && (r.CreateOptions()&FILE_OPEN_REPARSE_POINT == 0)
	d := r.CreateDisposition()

	if fileExists && !isDir && createDir {
		status := STATUS_OBJECT_NAME_COLLISION
		if d != FILE_CREATE {
			status = STATUS_NOT_A_DIRECTORY
		}
		log.Errorf("requested file exists and it's not a directory")
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(status))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	if isEA && !fileExists {
		log.Errorf("attempt to read ea from non-exsiting file: %s", name)
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_NO_SUCH_FILE))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	action := FILE_OPENED
	switch d {
	case FILE_OPEN_IF:
		flags = os.O_CREATE
		if !fileExists && createDir {
			_, err = t.fs.Mkdir(name, 0777)
			isDir = true
		}

		if !fileExists {
			action = FILE_CREATED
		}
	case FILE_OPEN:
		if !fileExists {
			log.Errorf("Open: doesn't exists: %s", r.Name())
			rsp := new(ErrorResponse)
			PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_NO_SUCH_FILE))
			return c.sendPacket(rsp, &t.treeConn, ctx)
		}
	case FILE_CREATE:
		if fileExists {
			log.Debugf("Open: already exists: %s", r.Name())
			rsp := new(ErrorResponse)
			PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_OBJECT_NAME_EXISTS))
			return c.sendPacket(rsp, &t.treeConn, ctx)
		}

		if createDir {
			_, err = t.fs.Mkdir(name, 0777)
			isDir = true
		}
		action = FILE_CREATED
		flags = os.O_CREATE | os.O_EXCL
	case FILE_OVERWRITE:
		if !fileExists {
			log.Errorf("Open: doesn't exists: overwrite: %s", r.Name())
			rsp := new(ErrorResponse)
			PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_NO_SUCH_FILE))
			return c.sendPacket(rsp, &t.treeConn, ctx)
		}
		action = FILE_OVERWRITTEN
		flags = os.O_CREATE | os.O_TRUNC
	case FILE_OVERWRITE_IF:
		action = FILE_CREATED
		if fileExists {
			action = FILE_OVERWRITTEN
		}
		flags = os.O_CREATE | os.O_TRUNC
	case FILE_SUPERSEDE:
		action = FILE_CREATED
		if fileExists {
			action = FILE_SUPERSEDED
		}
		flags = os.O_CREATE
	}

	if err != nil {
		log.Errorf("mkdir() failed")
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_ACCESS_DENIED))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	lockLevel := r.RequestedOplockLevel()
	lockState := LOCKSTATE_NONE
	switch lockLevel {
	case SMB2_OPLOCK_LEVEL_II:
		flags |= O_SHLOCK
		lockState = LOCKSTATE_HELD
	case SMB2_OPLOCK_LEVEL_EXCLUSIVE:
		flags |= O_EXLOCK
		lockState = LOCKSTATE_HELD
	case SMB2_OPLOCK_LEVEL_LEASE:
		break
	default:
		lockLevel = 0
	}

	access := r.DesiredAccess()
	var h vfs.VfsHandle
	if !isDir {
		if access&(FILE_WRITE_DATA|GENERIC_WRITE) != 0 {
			flags |= os.O_RDWR
		} else {
			flags |= os.O_RDONLY
		}

		if isEA {
			flags = 0
		}

		if r.CreateOptions()&FILE_OPEN_REPARSE_POINT != 0 {
			flags |= 0x200000 // O_SYMLINK, O_PATH
		}

		h, err = t.fs.Open(name, flags, 0644)
		log.Debugf("open file: %d, err %v", flags, err)
	} else {
		h, err = t.fs.OpenDir(name)
		log.Debugf("open dir, err %v", err)
	}

	if err == nil {
		attrs, err = t.fs.GetAttr(h)
	}
	if err != nil {
		log.Errorf("open failed: %v, co %x", err, r.CreateOptions())
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_ACCESS_DENIED))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	if isEA {
		if status, err := t.handleCreateEA(d, h, eaKey); err != nil {
			log.Debugf("handleCreateEA failed, disp %d, key %s", d, eaKey)
			t.fs.Close(h)
			rsp := new(ErrorResponse)
			PrepareResponse(&rsp.PacketHeader, pkt, status)
			return c.sendPacket(rsp, &t.treeConn, ctx)
		}
	}

	node := attrs.GetInodeNumber()
	rsp.FileId.SetHandleId(uint64(h))
	rsp.FileId.SetNodeId(node)

	rsp.OplockLevel = lockLevel
	rsp.CreateAction = uint32(action)
	rsp.FileAttributes = PermissionsFromVfs(attrs, name)
	rsp.CreationTime = BirthTimeFromVfs(attrs)
	rsp.LastAccessTime = AccessTimeFromVfs(attrs)
	rsp.LastWriteTime = ModifiedTimeFromVfs(attrs)
	rsp.ChangeTime = ChangeTimeFromVfs(attrs)
	if !isEA {
		rsp.EndofFile = int64(SizeFromVfs(attrs))
		rsp.AllocationSize = int64(DiskSizeFromVfs(attrs))
	} else {
		len, _ := t.fs.Getxattr(h, eaKey, nil)
		rsp.EndofFile = int64(len)
		rsp.AllocationSize = int64(len)
	}

	open := &Open{
		fileId:            rsp.FileId.HandleId(),
		durableFileId:     rsp.FileId.NodeId(),
		session:           t.session,
		tree:              &t.treeConn,
		oplockLevel:       lockLevel,
		grantedAccess:     access,
		oplockState:       lockState,
		pathName:          name,
		createOptions:     r.CreateOptions(),
		createDisposition: r.CreateDisposition(),
		fileAttributes:    rsp.FileAttributes,
		isEa:              isEA,
		eaKey:             eaKey,
		isSymlink:         isSymlink,
	}

	cc := r.CreateContexts()
	for len(cc) > 0 {
		res := CreateContextDecoder(cc)
		switch res.Name() {
		case "MxAc":
			if enc, err := t.handleMaxAccessCC(attrs); err == nil {
				rsp.Contexts = append(rsp.Contexts, enc)
			}
		case "AAPL":
			t.aaplExtensions = true
			if enc, err := t.handleAAPLCC(res.Buffer()); err == nil {
				rsp.Contexts = append(rsp.Contexts, enc)
			}
		case "DH2Q":
			if enc, err := t.handleDH2Q(res.Buffer(), open); err == nil {
				rsp.Contexts = append(rsp.Contexts, enc)
			}
		case "RqLs":
			if enc, err := t.handleRqLs(res.Buffer(), open); err == nil {
				rsp.Contexts = append(rsp.Contexts, enc)
			}
		case "QFid":
			if enc, err := t.handleQFid(res.Buffer(), open); err == nil {
				rsp.Contexts = append(rsp.Contexts, enc)
			}
		}

		cc = cc[res.Next():]
		if res.Next() == 0 {
			break
		}
	}

	if ctx != nil {
		ctx.fileId = rsp.FileId
	}

	t.conn.serverCtx.addOpen(open)

	return c.sendPacket(rsp, &t.treeConn, ctx)
}

func (t *fileTree) handleQFid(pkt []byte, open *Open) (Encoder, error) {
	attrRoot, _ := t.fs.GetAttr(0)

	return &CreateContext{
		Name: "QFid",
		Data: &DiskIdResponse{
			DiskFileId: open.durableFileId,
			VolumeId:   attrRoot.GetInodeNumber(),
		},
	}, nil
}

func (t *fileTree) handleDH2Q(pkt []byte, open *Open) (Encoder, error) {
	r := DurableHandleRequest2Decoder(pkt)
	timeout := r.Timeout()
	if timeout == 0 {
		timeout = serverDurableHandleTimeout
	}

	open.isPersistent = (r.Flags() & SMB2_DHANDLE_FLAG_PERSISTENT) != 0
	open.isDurable = open.isPersistent
	open.durableOpenTimeout = time.Duration(timeout) * time.Millisecond
	copy(open.createGuid[:], r.CreateGuid())

	return &CreateContext{
		Name: "DH2Q",
		Data: &DurableHandleResponse2{
			Timeout: timeout,
			Flags:   r.Flags(),
		},
	}, nil
}

func (t *fileTree) handleRqLs(pkt []byte, open *Open) (Encoder, error) {
	if len(pkt) == 32 {
		r := LeaseRequestDecoder(pkt)
		return &CreateContext{
			Name: "RqLs",
			Data: &LeaseResponse{
				LeaseKey:      r.LeaseKey(),
				LeaseState:    r.LeaseState(),
				LeaseFlags:    r.LeaseFlags(),
				LeaseDuration: r.LeaseDuration(),
			},
		}, nil
	}

	r := LeaseRequest2Decoder(pkt)
	return &CreateContext{
		Name: "RqLs",
		Data: &LeaseResponse2{
			LeaseResponse: LeaseResponse{
				LeaseKey:      r.LeaseKey(),
				LeaseState:    r.LeaseState(),
				LeaseFlags:    r.LeaseFlags(),
				LeaseDuration: r.LeaseDuration(),
			},
			ParentLeaseKey: r.ParentLeaseKey(),
			Epoch:          1,
		},
	}, nil
}

func (t *fileTree) handleCreateEA(disp uint32, h vfs.VfsHandle, eaKey string) (uint32, error) {
	var err error = nil
	status := uint32(0)

	// special cases for Apple
	if eaKey == "AFP_AfpInfo" {
		return 0, nil
	}

	switch disp {
	case FILE_OPEN_IF:
		// open or create
		if _, err = t.fs.Getxattr(h, eaKey, nil); err != nil {
			if err = t.fs.Setxattr(h, eaKey, nil); err != nil {
				status = uint32(STATUS_OPEN_FAILED)
			}
		}
	case FILE_OPEN:
		// open exisiting
		if _, err = t.fs.Getxattr(h, eaKey, nil); err != nil {
			status = uint32(STATUS_OBJECT_NAME_NOT_FOUND)
		}
	case FILE_CREATE:
		// if exists fail, otherwise create
		if _, err = t.fs.Getxattr(h, eaKey, nil); err == nil {
			status = uint32(STATUS_OBJECT_NAME_EXISTS)
			err = fmt.Errorf("already exists")
			break
		}
		if err = t.fs.Setxattr(h, eaKey, nil); err != nil {
			status = uint32(STATUS_OPEN_FAILED)
		}
	case FILE_OVERWRITE:
		// error if doesn't exists
		if _, err = t.fs.Getxattr(h, eaKey, nil); err != nil {
			status = uint32(STATUS_OBJECT_NAME_NOT_FOUND)
		}
		if err = t.fs.Setxattr(h, eaKey, nil); err != nil {
			status = uint32(STATUS_OPEN_FAILED)
		}
	case FILE_SUPERSEDE, FILE_OVERWRITE_IF:
		err = t.fs.Setxattr(h, eaKey, nil)
	}

	if err != nil && status == 0 {
		status = uint32(STATUS_OPEN_FAILED)
	}
	return status, err
}

// https://github.com/openzfs/openzfs/blob/master/usr/src/uts/common/smbsrv/smb2_aapl.h
func (t *fileTree) handleAAPLCC(pkt []byte) (Encoder, error) {
	r := AAPLServerQueryRequestDecoder(pkt)
	switch r.CommandCode() {
	case AAPL_SERVER_QUERY:
		rsp := CreateContext{
			Name: "AAPL",
			Data: &AAPLServerQueryResponse{
				CommandCode: AAPL_SERVER_QUERY,
				ReplyBitmap: AAPL_SERVER_CAPS | AAPL_VOLUME_CAPS | AAPL_MODEL_INFO,
				ServerCaps:  AAPL_SUPPORTS_READDIR_ATTR | /*AAPL_SUPPORTS_OSX_COPYFILE |*/ AAPL_UNIX_BASED | AAPL_SUPPORTS_NFS_ACE,
				VolumeCaps:/*AAPL_SUPPORT_RESOLVE_ID |*/ AAPL_CASE_SENSITIVE | AAPL_SUPPORTS_FULL_SYNC,
				ModelString: "CloudMachine",
			},
		}
		return rsp, nil
	case AAPL_RESOLVE_ID:
	}

	return nil, fmt.Errorf("not supported command")
}

func (t *fileTree) handleMaxAccessCC(attrs *vfs.Attributes) (Encoder, error) {
	ccMaxAccess := CreateContext{
		Name: "MxAc",
		Data: CreateContextMaximalAccessResponse{
			QueryStatus:   0,
			MaximalAccess: MaxAccessFromVfs(attrs),
		},
	}
	return ccMaxAccess, nil
}

func (t *fileTree) close(ctx *compoundContext, pkt []byte) error {
	c := t.session.conn

	res, err := accept(SMB2_CLOSE, pkt)
	if err != nil {
		return err
	}

	r := CloseRequestDecoder(res)
	if r.IsInvalid() {
		return &InvalidRequestError{"broken close request"}
	}

	fileId := r.FileId().Decode()
	status := uint32(0)
	if ctx != nil && ctx.fileId != nil {
		fileId = ctx.fileId
		if ctx.lastStatus != 0 {
			status = ctx.lastStatus
		}
	}

	if IsInvalidFileId(fileId) {
		log.Errorf("Close: invalid fileid")
		rsp := new(ErrorResponse)
		PrepareResponse(rsp.Header(), pkt, uint32(STATUS_INVALID_HANDLE))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	rsp := new(CloseResponse)
	PrepareResponse(&rsp.PacketHeader, pkt, 0)

	rsp.Status = status

	if r.Flags()&SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB != 0 {
		a, err := t.fs.GetAttr(vfs.VfsHandle(fileId.HandleId()))
		if err != nil {
			log.Errorf("Close: GetAttr() failed")
			goto send
		}

		open := t.conn.serverCtx.getOpen(fileId.HandleId())
		if open == nil {
			log.Errorf("close: no open")
			goto send
		}
		rsp.CloseFlags = SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB
		rsp.CreationTime = BirthTimeFromVfs(a)
		rsp.LastAccessTime = AccessTimeFromVfs(a)
		rsp.LastWriteTime = ModifiedTimeFromVfs(a)
		rsp.ChangeTime = ChangeTimeFromVfs(a)
		rsp.EndofFile = int64(SizeFromVfs(a))
		rsp.AllocationSize = int64(DiskSizeFromVfs(a))
		rsp.FileAttributes = PermissionsFromVfs(a, open.pathName)
	}
send:
	t.conn.serverCtx.deleteOpen(fileId.HandleId())
	t.fs.Close(vfs.VfsHandle(fileId.HandleId()))

	return c.sendPacket(rsp, &t.treeConn, ctx)
}

func (t *fileTree) flush(ctx *compoundContext, pkt []byte) error {
	log.Debugf("flush")

	c := t.session.conn

	res, _ := accept(SMB2_FLUSH, pkt)
	r := FlushRequestDecoder(res)

	fileId := r.FileId().Decode()
	if ctx != nil && ctx.fileId != nil {
		fileId = ctx.fileId
	}

	if IsInvalidFileId(fileId) {
		log.Errorf("flush: invalid fileid")
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_INVALID_HANDLE))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	t.fs.Flush(vfs.VfsHandle(fileId.HandleId()))

	rsp := new(FlushResponse)
	PrepareResponse(&rsp.PacketHeader, pkt, 0)
	return c.sendPacket(rsp, &t.treeConn, ctx)
}

func (t *fileTree) readEA(ctx *compoundContext, fileId *FileId, open *Open, buf []byte, pkt []byte) error {
	c := t.session.conn

	status := uint32(0) //STATUS_END_OF_FILE
	n, err := t.fs.Getxattr(vfs.VfsHandle(fileId.HandleId()), open.eaKey, buf)

	if err != nil {
		status = uint32(STATUS_ACCESS_DENIED)
	} else if n == 0 {
		status = uint32(STATUS_END_OF_FILE)
	}

	if status != 0 {
		// special cases for Apple
		if open.eaKey == "AFP_AfpInfo" && len(buf) == 60 {
			info := AfpInfo{
				Signature: [4]byte{'A', 'F', 'P', '_'},
				Version:   [4]byte{0x00, 0x01, 0x00, 0x00},
			}
			info.Encode(buf)
			n = 60
			//t.fs.Setxattr(h, open.eaKey, buf)
		} else {
			rsp := new(ErrorResponse)
			PrepareResponse(rsp.Header(), pkt, status)
			return c.sendPacket(rsp, &t.treeConn, ctx)
		}
	}

	rsp := new(ReadResponse)
	PrepareResponse(&rsp.PacketHeader, pkt, 0)
	rsp.DataRemaining = 0
	rsp.Data = buf[:n]
	return c.sendPacket(rsp, &t.treeConn, ctx)

}

func (t *fileTree) read(ctx *compoundContext, pkt []byte) error {
	log.Debugf("read")
	c := t.session.conn

	res, _ := accept(SMB2_READ, pkt)
	r := ReadRequestDecoder(res)

	fileId := r.FileId().Decode()
	if ctx != nil && ctx.fileId != nil {
		fileId = ctx.fileId
	}

	if IsInvalidFileId(fileId) {
		log.Errorf("read: invalid fileid")
		rsp := new(ErrorResponse)
		PrepareResponse(rsp.Header(), pkt, uint32(STATUS_INVALID_HANDLE))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	open := t.conn.serverCtx.getOpen(fileId.HandleId())
	if open == nil {
		log.Errorf("read: no open")
		rsp := new(ErrorResponse)
		PrepareResponse(rsp.Header(), pkt, uint32(STATUS_INVALID_HANDLE))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	// async read
	asyncId := randint64()
	if ctx != nil || open.isEa {
		return t.readImpl(ctx, pkt, fileId, open, 0)
	}

	go func() {
		t.ioReadSem <- struct{}{}
		defer func() { <-t.ioReadSem }()

		rsp := new(ErrorResponse)
		PrepareAsyncResponse(rsp.Header(), pkt, asyncId, uint32(STATUS_PENDING))
		c.sendPacket(rsp, &t.treeConn, ctx)

		t.readImpl(ctx, pkt, fileId, open, asyncId)
	}()
	return nil
}

func (t *fileTree) readImpl(ctx *compoundContext, pkt []byte, fileId *FileId, open *Open, asyncId uint64) error {
	c := t.session.conn

	res, _ := accept(SMB2_READ, pkt)
	r := ReadRequestDecoder(res)

	buf := make([]byte, r.Length())
	var n int
	var err error

	if open.isEa {
		return t.readEA(ctx, fileId, open, buf, pkt)
	}

	n, err = t.fs.Read(vfs.VfsHandle(fileId.HandleId()), buf, r.Offset(), 0)
	if err != nil && n == 0 {
		status := STATUS_ACCESS_DENIED
		if err == io.EOF {
			if !open.isEa {
				status = STATUS_END_OF_FILE
			} else {
				status = STATUS_OBJECT_NAME_NOT_FOUND
			}
		} else {
			log.Errorf("Read: %v", err)
		}
		rsp := new(ErrorResponse)
		PrepareAsyncResponse(rsp.Header(), pkt, asyncId, uint32(status))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	rsp := new(ReadResponse)
	PrepareAsyncResponse(&rsp.PacketHeader, pkt, asyncId, 0)
	rsp.DataRemaining = 0
	rsp.Data = buf[:n]

	log.Debugf("read async %d finished", asyncId)
	return c.sendPacket(rsp, &t.treeConn, ctx)
}

func (t *fileTree) write(ctx *compoundContext, pkt []byte) error {
	log.Debugf("write")

	c := t.session.conn

	res, _ := accept(SMB2_WRITE, pkt)
	r := WriteRequestDecoder(res)

	fileId := r.FileId().Decode()
	if ctx != nil && ctx.fileId != nil {
		fileId = ctx.fileId
	}

	if IsInvalidFileId(fileId) {
		log.Errorf("write: invalid fileid")
		rsp := new(ErrorResponse)
		PrepareResponse(rsp.Header(), pkt, uint32(STATUS_INVALID_HANDLE))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	open := t.conn.serverCtx.getOpen(fileId.HandleId())
	if open == nil {
		log.Errorf("write: no open")
		rsp := new(ErrorResponse)
		PrepareResponse(rsp.Header(), pkt, uint32(STATUS_INVALID_HANDLE))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	// async write
	asyncId := randint64()
	if ctx != nil || open.isEa {
		return t.writeImpl(ctx, pkt, fileId, open, 0)
	}

	go func() {

		t.ioWriteSem <- struct{}{}
		defer func() { <-t.ioWriteSem }()

		rsp := new(ErrorResponse)
		PrepareAsyncResponse(rsp.Header(), pkt, asyncId, uint32(STATUS_PENDING))
		c.sendPacket(rsp, &t.treeConn, ctx)

		t.writeImpl(ctx, pkt, fileId, open, asyncId)
	}()
	return nil
}

func (t *fileTree) writeImpl(ctx *compoundContext, pkt []byte, fileId *FileId, open *Open, asyncId uint64) error {

	var n int
	var err error

	c := t.session.conn

	res, _ := accept(SMB2_WRITE, pkt)
	r := WriteRequestDecoder(res)

	if open.isEa {
		log.Debugf("write ea: key %s, val %s", open.eaKey, r.Data())
		// ignore xattr errors
		t.fs.Setxattr(vfs.VfsHandle(fileId.HandleId()), open.eaKey, r.Data())
		n = len(r.Data())
	} else {
		log.Debugf("Write: %d offset %d", r.Length(), r.Offset())
		n, err = t.fs.Write(vfs.VfsHandle(fileId.HandleId()), r.Data(), r.Offset(), int(r.Flags()))
	}

	if err != nil || n == 0 {
		log.Errorf("Write failed: %v", err)
		status := STATUS_IO_DEVICE_ERROR
		rsp := new(ErrorResponse)
		PrepareAsyncResponse(rsp.Header(), pkt, asyncId, uint32(status))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	rsp := new(WriteResponse)
	PrepareAsyncResponse(&rsp.PacketHeader, pkt, asyncId, 0)
	rsp.Count = uint32(n)

	return c.sendPacket(rsp, &t.treeConn, ctx)
}

func (t *fileTree) lock(ctx *compoundContext, pkt []byte) error {
	log.Errorf("Lock")
	c := t.session.conn

	//rsp := new(ErrorResponse)
	//PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_NOT_SUPPORTED))
	rsp := new(LockResponse)
	PrepareResponse(&rsp.PacketHeader, pkt, 0)

	return c.sendPacket(rsp, &t.treeConn, ctx)
}

func (t *fileTree) handleReparsePointReq(ctx *compoundContext, pkt []byte) error {
	c := t.session.conn

	res, _ := accept(SMB2_IOCTL, pkt)
	r := IoctlRequestDecoder(res)

	rd := SymbolicLinkReparseDataBufferDecoder(r.Data())
	if rd.IsInvalid() {
		log.Errorf("handleReparsePointReq: reparse tag not supported: 0x%x", rd.ReparseTag())
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_NOT_SUPPORTED))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	fileId := r.FileId().Decode()
	if ctx != nil && ctx.fileId != nil {
		fileId = ctx.fileId
	}
	if IsInvalidFileId(fileId) {
		log.Errorf("handleReparsePointReq: invalid fileid")
		rsp := new(ErrorResponse)
		PrepareResponse(rsp.Header(), pkt, uint32(STATUS_INVALID_HANDLE))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	log.Debugf("handleReparsePointReq: subst name %s", rd.SubstituteName())
	source := strings.ReplaceAll(rd.SubstituteName(), "\\", "/")
	_, err := t.fs.Symlink(vfs.VfsHandle(fileId.HandleId()), source, int(rd.Flags()))
	if err != nil {
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_ACCESS_DENIED))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	rsp := new(IoctlResponse)
	rsp.CtlCode = FSCTL_SET_REPARSE_POINT
	rsp.FileId = fileId
	PrepareResponse(&rsp.PacketHeader, pkt, 0)
	return c.sendPacket(rsp, &t.treeConn, ctx)
}

func (t *fileTree) handleGetReparsePointReq(ctx *compoundContext, pkt []byte) error {
	c := t.session.conn

	res, _ := accept(SMB2_IOCTL, pkt)
	r := IoctlRequestDecoder(res)

	fileId := r.FileId().Decode()
	if ctx != nil && ctx.fileId != nil {
		fileId = ctx.fileId
	}
	if IsInvalidFileId(fileId) {
		log.Errorf("handleReparsePointReq: invalid fileid")
		rsp := new(ErrorResponse)
		PrepareResponse(rsp.Header(), pkt, uint32(STATUS_INVALID_HANDLE))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	l, err := t.fs.Readlink(vfs.VfsHandle(fileId.HandleId()))
	if err != nil {
		log.Errorf("handleGetReparsePointReq: Readlink() failed: %v", err)
		rsp := new(ErrorResponse)
		PrepareResponse(rsp.Header(), pkt, uint32(STATUS_ACCESS_DENIED))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	l = strings.ReplaceAll(l, "/", "\\")
	out := &SymbolicLinkReparseDataBuffer{
		SubstituteName: l,
		PrintName:      l,
	}
	if !path.IsAbs(l) {
		out.Flags = SYMLINK_FLAG_RELATIVE
	}

	rsp := new(IoctlResponse)
	rsp.CtlCode = FSCTL_GET_REPARSE_POINT
	rsp.FileId = fileId
	rsp.Output = out

	PrepareResponse(&rsp.PacketHeader, pkt, 0)
	return c.sendPacket(rsp, &t.treeConn, ctx)
}

func (t *fileTree) handleDeleteReparsePointReq(ctx *compoundContext, pkt []byte) error {
	c := t.session.conn

	res, _ := accept(SMB2_IOCTL, pkt)
	r := IoctlRequestDecoder(res)

	fileId := r.FileId().Decode()
	if ctx != nil && ctx.fileId != nil {
		fileId = ctx.fileId
	}
	if IsInvalidFileId(fileId) {
		log.Errorf("handleDeleteReparsePointReq: invalid fileid")
		rsp := new(ErrorResponse)
		PrepareResponse(rsp.Header(), pkt, uint32(STATUS_INVALID_HANDLE))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	err := t.fs.Unlink(vfs.VfsHandle(fileId.HandleId()))
	if err != nil {
		log.Errorf("handleDeleteReparsePointReq: Readlink() failed: %v", err)
		rsp := new(ErrorResponse)
		PrepareResponse(rsp.Header(), pkt, uint32(STATUS_ACCESS_DENIED))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	rsp := new(IoctlResponse)
	rsp.CtlCode = FSCTL_GET_REPARSE_POINT
	rsp.FileId = fileId

	PrepareResponse(&rsp.PacketHeader, pkt, 0)
	return c.sendPacket(rsp, &t.treeConn, ctx)
}

func (t *fileTree) handleCreateOrGetObjectId(ctx *compoundContext, pkt []byte) error {
	c := t.session.conn

	res, _ := accept(SMB2_IOCTL, pkt)
	r := IoctlRequestDecoder(res)

	fileId := r.FileId().Decode()
	if ctx != nil && ctx.fileId != nil {
		fileId = ctx.fileId
	}
	if IsInvalidFileId(fileId) {
		log.Errorf("handleCreateOrGetObjectId: invalid fileid")
		rsp := new(ErrorResponse)
		PrepareResponse(rsp.Header(), pkt, uint32(STATUS_INVALID_HANDLE))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	attrRoot, _ := t.fs.GetAttr(0)

	id := &FileObjectId1{
		ObjectId:      FileId{Persistent: fileId.Persistent},
		BirthObjectId: FileId{Persistent: fileId.Persistent},
	}
	le.PutUint64(id.BirthVolumeId.Persistent[:], attrRoot.GetInodeNumber())

	rsp := new(IoctlResponse)
	rsp.CtlCode = FSCTL_CREATE_OR_GET_OBJECT_ID
	rsp.FileId = fileId
	rsp.Output = id

	PrepareResponse(&rsp.PacketHeader, pkt, 0)
	return c.sendPacket(rsp, &t.treeConn, ctx)
}

func (t *fileTree) ioctl(ctx *compoundContext, pkt []byte) error {
	log.Debugf("Ioctl")

	c := t.session.conn

	res, _ := accept(SMB2_IOCTL, pkt)
	r := IoctlRequestDecoder(res)

	switch r.CtlCode() {
	case FSCTL_SET_REPARSE_POINT:
		return t.handleReparsePointReq(ctx, pkt)
	case FSCTL_GET_REPARSE_POINT:
		return t.handleGetReparsePointReq(ctx, pkt)
	case FSCTL_DELETE_REPARSE_POINT:
		return t.handleDeleteReparsePointReq(ctx, pkt)
	case FSCTL_CREATE_OR_GET_OBJECT_ID:
		return t.handleCreateOrGetObjectId(ctx, pkt)
	}

	log.Errorf("ioctl: code %d", r.CtlCode())
	/*rsp := new(IoctlResponse)
	rsp.CtlCode = r.CtlCode()
	rsp.FileId = r.FileId().Decode()
	*/
	rsp := new(ErrorResponse)
	PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_NOT_SUPPORTED))

	return c.sendPacket(rsp, &t.treeConn, ctx)
}

func (t *fileTree) cancel(ctx *compoundContext, pkt []byte) error {
	log.Errorf("Cancel")
	c := t.session.conn

	rsp := new(ErrorResponse)
	PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_NOT_SUPPORTED))

	return c.sendPacket(rsp, &t.treeConn, ctx)
}

func newFileDirectoryInformationInfo(d vfs.DirInfo) FileDirectoryInformationInfo {
	info := FileDirectoryInformationInfo{
		FileIndex: 0,
		FileName:  d.Name,
	}

	info.CreationTime = *BirthTimeFromVfs(&d.Attributes)
	info.LastAccessTime = *AccessTimeFromVfs(&d.Attributes)
	info.LastWriteTime = *ModifiedTimeFromVfs(&d.Attributes)
	info.ChangeTime = *ChangeTimeFromVfs(&d.Attributes)
	info.EndOfFile = SizeFromVfs(&d.Attributes)
	info.AllocationSize = DiskSizeFromVfs(&d.Attributes)
	info.FileAttributes = PermissionsFromVfs(&d.Attributes, d.Name)
	return info
}

func newFileFullDirectoryInformationInfo(d vfs.DirInfo) FileFullDirectoryInformationInfo {
	info := FileFullDirectoryInformationInfo{
		FileIndex: 0,
		FileName:  d.Name,
	}

	info.CreationTime = *BirthTimeFromVfs(&d.Attributes)
	info.LastAccessTime = *AccessTimeFromVfs(&d.Attributes)
	info.LastWriteTime = *ModifiedTimeFromVfs(&d.Attributes)
	info.ChangeTime = *ChangeTimeFromVfs(&d.Attributes)
	info.EndOfFile = SizeFromVfs(&d.Attributes)
	info.AllocationSize = DiskSizeFromVfs(&d.Attributes)
	info.FileAttributes = PermissionsFromVfs(&d.Attributes, d.Name)
	if info.FileAttributes&FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		info.EaSize = IO_REPARSE_TAG_SYMLINK
	}
	return info
}

func newFileIdFullDirectoryInformationInfo(d vfs.DirInfo) FileIdFullDirectoryInformationInfo {
	info := FileIdFullDirectoryInformationInfo{
		FileIndex: 0,
		FileName:  d.Name,
	}

	info.CreationTime = *BirthTimeFromVfs(&d.Attributes)
	info.LastAccessTime = *AccessTimeFromVfs(&d.Attributes)
	info.LastWriteTime = *ModifiedTimeFromVfs(&d.Attributes)
	info.ChangeTime = *ChangeTimeFromVfs(&d.Attributes)
	info.EndOfFile = SizeFromVfs(&d.Attributes)
	info.AllocationSize = DiskSizeFromVfs(&d.Attributes)
	info.FileAttributes = PermissionsFromVfs(&d.Attributes, d.Name)
	if info.FileAttributes&FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		info.EaSize = IO_REPARSE_TAG_SYMLINK
	}
	return info
}

func newFileIdBothDirectoryInformationInfo(d vfs.DirInfo) FileIdBothDirectoryInformationInfo {
	info := FileIdBothDirectoryInformationInfo{
		FileIndex: 0,
		FileName:  d.Name,
		FileId:    d.GetInodeNumber(),
	}

	info.CreationTime = *BirthTimeFromVfs(&d.Attributes)
	info.LastAccessTime = *AccessTimeFromVfs(&d.Attributes)
	info.LastWriteTime = *ModifiedTimeFromVfs(&d.Attributes)
	info.ChangeTime = *ChangeTimeFromVfs(&d.Attributes)
	info.EndOfFile = SizeFromVfs(&d.Attributes)
	info.AllocationSize = DiskSizeFromVfs(&d.Attributes)
	info.FileAttributes = PermissionsFromVfs(&d.Attributes, d.Name)

	if info.FileAttributes&FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		info.EaSize = IO_REPARSE_TAG_SYMLINK
	}

	return info
}

func newFileBothDirectoryInformationInfo(d vfs.DirInfo) FileBothDirectoryInformationInfo {
	info := FileBothDirectoryInformationInfo{
		FileIndex: 0,
		FileName:  d.Name,
	}

	info.CreationTime = *BirthTimeFromVfs(&d.Attributes)
	info.LastAccessTime = *AccessTimeFromVfs(&d.Attributes)
	info.LastWriteTime = *ModifiedTimeFromVfs(&d.Attributes)
	info.ChangeTime = *ChangeTimeFromVfs(&d.Attributes)
	info.EndOfFile = SizeFromVfs(&d.Attributes)
	info.AllocationSize = DiskSizeFromVfs(&d.Attributes)
	info.FileAttributes = PermissionsFromVfs(&d.Attributes, d.Name)

	if info.FileAttributes&FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		info.EaSize = IO_REPARSE_TAG_SYMLINK
	}

	return info
}

func newFileIdBothDirectoryInformationInfo2(d vfs.DirInfo) FileIdBothDirectoryInformationInfo2 {
	info := FileIdBothDirectoryInformationInfo2{
		FileIndex: 0,
		MaxAccess: MaxAccessFromVfs(&d.Attributes),
		FileName:  d.Name,
		FileId:    d.GetInodeNumber(),
		UnixMode:  UnixModeFromVfs(&d.Attributes),
	}

	info.CreationTime = *BirthTimeFromVfs(&d.Attributes)
	info.LastAccessTime = *AccessTimeFromVfs(&d.Attributes)
	info.LastWriteTime = *ModifiedTimeFromVfs(&d.Attributes)
	info.ChangeTime = *ChangeTimeFromVfs(&d.Attributes)
	info.EndOfFile = SizeFromVfs(&d.Attributes)
	info.AllocationSize = DiskSizeFromVfs(&d.Attributes)
	info.FileAttributes = PermissionsFromVfs(&d.Attributes, d.Name)

	if info.FileAttributes&FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		info.MaxAccess = IO_REPARSE_TAG_SYMLINK
	}

	return info
}

func (t *fileTree) makeItem(class uint8, d vfs.DirInfo) Encoder {
	switch class {
	case FileBothDirectoryInformation:
		return newFileBothDirectoryInformationInfo(d)
	case FileIdBothDirectoryInformation:
		if t.aaplExtensions {
			return newFileIdBothDirectoryInformationInfo2(d)
		}
		return newFileIdBothDirectoryInformationInfo(d)
	case FileDirectoryInformation:
		return newFileDirectoryInformationInfo(d)
	case FileFullDirectoryInformation:
		return newFileFullDirectoryInformationInfo(d)
	case FileIdFullDirectoryInformation:
		return newFileIdFullDirectoryInformationInfo(d)
	default:
		log.Errorf("bad info class %d", class)
	}
	return nil
}

func (t *fileTree) queryDirectory(ctx *compoundContext, pkt []byte) error {
	log.Debugf("QueryDirectory")

	c := t.session.conn

	res, _ := accept(SMB2_QUERY_DIRECTORY, pkt)
	r := QueryDirectoryRequestDecoder(res)

	switch r.FileInfoClass() {
	case FileIdBothDirectoryInformation, FileFullDirectoryInformation,
		FileDirectoryInformation, FileIdFullDirectoryInformation, FileBothDirectoryInformation:
		break
	default:
		log.Errorf("wrong info class %d", r.FileInfoClass())
	}

	log.Debugf("search patter: %s", r.FileName())
	fileId := r.FileId().Decode()
	if ctx != nil && ctx.fileId != nil {
		fileId = ctx.fileId
	}

	if IsInvalidFileId(fileId) {
		log.Errorf("queryDirectory: invalid fileid")
		rsp := new(ErrorResponse)
		PrepareResponse(rsp.Header(), pkt, uint32(STATUS_INVALID_HANDLE))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	out := &FileInformationInfoResponse{}
	Status := uint32(0)
	if ctx != nil && ctx.lastStatus != 0 {
		Status = ctx.lastStatus
	}

	pos := 0
	if r.Flags()&RESTART_SCANS != 0 {
		pos = 1
	}

	name := r.FileName()
	if Status == 0 {
		Status = uint32(STATUS_NO_SUCH_FILE)

		if !ContainsWildcard(name) {
			if attrs, err := t.fs.Lookup(vfs.VfsHandle(fileId.HandleId()), name); err == nil {
				log.Debugf("lookup %s success", name)
				d := vfs.DirInfo{Name: name, Attributes: *attrs}
				info := t.makeItem(r.FileInfoClass(), d)
				out.Items = append(out.Items, info)
				Status = 0
			}
		} else {
			dir, err := t.fs.ReadDir(vfs.VfsHandle(fileId.HandleId()), pos, 1000)
			if err == nil {
				for _, d := range dir {
					if MatchWildcard(d.Name, r.FileName()) {
						info := t.makeItem(r.FileInfoClass(), d)
						out.Items = append(out.Items, info)
						Status = 0

						if r.Flags()&RETURN_SINGLE_ENTRY != 0 {
							break
						}
					}
				}
			} else {
				if err == io.EOF {
					Status = uint32(STATUS_NO_MORE_FILES)
				} else {
					log.Errorf("queryDirectory: err %v", err)
					Status = uint32(STATUS_ACCESS_DENIED)
				}
			}
		}
	} else {
		out = nil
	}

	var rsp Packet
	if Status != 0 {
		rsp = new(ErrorResponse)
		PrepareResponse(rsp.Header(), pkt, Status)
	} else {
		rsp = &QueryDirectoryResponse{Output: out}
		PrepareResponse(rsp.Header(), pkt, Status)
	}

	return c.sendPacket(rsp, &t.treeConn, ctx)
}

func (t *fileTree) changeNotify(ctx *compoundContext, pkt []byte) error {
	log.Debugf("ChangeNotify")

	c := t.session.conn

	/*res, _ := accept(SMB2_CHANGE_NOTIFY, pkt)
	r := ChangeNotifyRequestDecoder(res)

	fileId := r.FileId().Decode()
	if ctx != nil && ctx.fileId != nil {
		fileId = ctx.fileId
	}
	if IsInvalidFileId(fileId) {
		log.Errorf("ChangeNotify: invalid fileid")
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_INVALID_HANDLE))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	log.Errorf("ChangeNotify: %d", fileId.HandleId())

	open := t.serverCtx.getOpen(fileId.HandleId())
	if open == nil {
		log.Errorf("ChangeNotify: open not found")
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_INVALID_HANDLE))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	open.notifyReq = pkt

	ch := make(chan *vfs.NotifyEvent)
	t.fs.RegisterNotify(vfs.VfsHandle(fileId.HandleId()), ch)
	go func(ctx *compoundContext, ch chan *vfs.NotifyEvent, isDir bool, pkt []byte) {
		ev := <-ch
		if ev != nil {
			log.Errorf("notification received: %v, %v", isDir, ev)
			if isDir {
				rsp := new(ChangeNotifyResponse)
				rsp.Output = &FileNotifyInformationInfo{
					Action:   FILE_ACTION_ADDED,
					FileName: strings.ReplaceAll(ev.Name, "/", "\\"),
				}
				log.Errorf("Sending notification: %s", strings.ReplaceAll(ev.Name, "/", "\\"))
				PrepareResponse(&rsp.PacketHeader, pkt, 0)
				rsp.Flags |= SMB2_FLAGS_ASYNC_COMMAND
				//c.sendPacket(rsp, &t.treeConn, ctx)
			}
		}
		t.fs.RemoveNotify(vfs.VfsHandle(fileId.HandleId()))
		close(ch)
	}(ctx, ch, open.fileAttributes&FILE_ATTRIBUTE_DIRECTORY != 0, open.notifyReq)*/

	rsp := new(ErrorResponse)
	PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_ACCESS_DENIED))
	return c.sendPacket(rsp, &t.treeConn, ctx)
}

func (t *fileTree) queryInfoFileSystem(ctx *compoundContext, pkt []byte) error {
	c := t.session.conn

	res, _ := accept(SMB2_QUERY_INFO, pkt)
	r := QueryInfoRequestDecoder(res)

	log.Debugf("queryInfoFileSystem: class %d", r.FileInfoClass())

	s, _ := t.fs.StatFS(0)
	bs := uint32(512)
	if b, ok := s.GetBlockSize(); ok {
		bs = uint32(b)
	}
	au := int64(-1)
	if val, ok := s.GetAvailableBlocks(); ok {
		au = int64(val)
	}
	ta := int64(-1)
	if val, ok := s.GetBlocks(); ok {
		ta = int64(val)
	}

	var info Encoder
	switch r.FileInfoClass() {
	case FileFsVolumeInformation:
		info = &FileFsVolumeInformationInfo{
			VolumeLabel: t.path,
		}
	case FileFsSizeInformation:
		info = &FileFsSizeInformationInfo{
			TotalAllocationUnits:     ta,
			AvailableAllocationUnits: au,
			SectorsPerAllocationUnit: bs / 512,
			BytesPerSector:           512,
		}
	case FileFsDeviceInformation:
		info = &FileFsDeviceInformationInfo{
			DeviceType: FILE_DEVICE_DISK,
		}
	case FileFsAttributeInformation:
		attrs := FILE_SUPPORTS_OPEN_BY_FILE_ID |
			FILE_SUPPORTS_OBJECT_IDS |
			FILE_CASE_SENSITIVE_SEARCH |
			FILE_CASE_PRESERVED_NAMES |
			FILE_PERSISTENT_ACLS |
			FILE_SUPPORTS_SPARSE_FILES |
			FILE_UNICODE_ON_DISK |
			FILE_SUPPORTS_HARD_LINKS |
			FILE_SUPPORTS_REPARSE_POINTS
		if t.conn.serverCtx.xattrs {
			attrs |= FILE_SUPPORTS_EXTENDED_ATTRIBUTES | FILE_NAMED_STREAMS
		}
		info = &FileFsAttributeInformationInfo{
			FileSystemAttributes:       uint32(attrs),
			MaximumComponentNameLength: 255,
			FileSystemName:             "APFS",
		}
	case FileFsFullSizeInformation:
		info = &FileFsFullSizeInformationInfo{
			TotalAllocationUnits:           ta,
			CallerAvailableAllocationUnits: au,
			ActualAvailableAllocationUnits: au,
			SectorsPerAllocationUnit:       bs / 512,
			BytesPerSector:                 512,
		}
	case FileFsObjectIdInformation:
		fileId := r.FileId().Decode()
		if ctx != nil && ctx.fileId != nil {
			fileId = ctx.fileId
		}
		attrRoot, _ := t.fs.GetAttr(0)
		id := &FileObjectId1{
			ObjectId:      FileId{Persistent: fileId.Persistent},
			BirthObjectId: FileId{Persistent: fileId.Persistent},
		}
		le.PutUint64(id.BirthVolumeId.Persistent[:], attrRoot.GetInodeNumber())
		info = id
	default:
		log.Errorf("queryInfoFileSystem: unsupported type %d", r.FileInfoClass())
		return &InvalidRequestError{"unsupported query class"}
	}

	rsp := new(QueryInfoResponse)
	PrepareResponse(&rsp.PacketHeader, pkt, 0)
	rsp.Output = info

	return c.sendPacket(rsp, &t.treeConn, ctx)
}

func (t *fileTree) queryInfoFile(ctx *compoundContext, pkt []byte) error {
	c := t.session.conn

	res, _ := accept(SMB2_QUERY_INFO, pkt)
	r := QueryInfoRequestDecoder(res)

	log.Debugf("queryInfoFile: class %d", r.FileInfoClass())

	fileId := r.FileId().Decode()
	if ctx != nil && ctx.fileId != nil {
		fileId = ctx.fileId
	}

	if IsInvalidFileId(fileId) {
		log.Errorf("queryInfoFile: invalid fileid")
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_INVALID_HANDLE))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	open := t.conn.serverCtx.getOpen(fileId.HandleId())
	if open == nil {
		log.Errorf("queryInfoFile: open not found")
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_INVALID_HANDLE))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	name := open.pathName
	a, err := t.fs.GetAttr(vfs.VfsHandle(fileId.HandleId()))
	if err != nil {
		log.Errorf("queryInfoFile: GetAttr() failed")
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_INVALID_HANDLE))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	isDir := uint8(0)
	if a.GetFileType() == vfs.FileTypeDirectory {
		isDir = 1
	}

	var info Encoder
	switch r.FileInfoClass() {
	case FileAllInformation:
		info = &FileAllInformationInfo{
			BasicInformation: FileBasicInformationInfo{
				CreationTime:   *BirthTimeFromVfs(a),
				LastAccessTime: *AccessTimeFromVfs(a),
				LastWriteTime:  *ModifiedTimeFromVfs(a),
				ChangeTime:     *ChangeTimeFromVfs(a),
				FileAttributes: PermissionsFromVfs(a, open.pathName),
			},
			StandardInformation: FileStandardInformationInfo{
				EndOfFile:      int64(SizeFromVfs(a)),
				AllocationSize: int64(DiskSizeFromVfs(a)),
				Directory:      isDir,
			},
			Internal: FileInternalInformationInfo{
				IndexNumber: int64(a.GetInodeNumber()),
			},
			EaInformation: FileEaInformationInfo{},
			AccessInformation: FileAccessInformationInfo{
				AccessFlags: MaxAccessFromVfs(a),
			},
			PositionInformation: FilePositionInformationInfo{},
			ModeInformation: FileModeInformationInfo{
				Mode: FILE_SYNCHRONOUS_IO_ALERT,
			},
			AlignmentInformation: FileAlignmentInformationInfo{},
			NameInformation: FileAlternateNameInformationInfo{
				FileName: strings.ReplaceAll(name, "/", "\\"),
			},
		}
	case FileEaInformation:
		info = &FileEaInformationInfo{}
	case FileStreamInformation:
		if isDir == 1 {
			break
		}

		xattrs, err := t.fs.Listxattr(vfs.VfsHandle(fileId.HandleId()))
		items := FileStreamInformationInfoItems{
			FileStreamInformationInfo{
				NextEntryOffset:      0,
				StreamSize:           SizeFromVfs(a),
				StreamAllocationSize: DiskSizeFromVfs(a),
				StreamName:           "::$DATA",
			},
		}

		log.Debugf("queryInfoFile: xattrs ret %v, err %v", xattrs, err)
		if err == nil && t.conn.serverCtx.xattrs {
			for _, ea := range xattrs {
				l, err := t.fs.Getxattr(vfs.VfsHandle(fileId.HandleId()), ea, nil)
				if err == nil {
					item := FileStreamInformationInfo{
						StreamSize:           uint64(l),
						StreamAllocationSize: uint64(l),
						StreamName:           fmt.Sprintf(":%s:$DATA", ea),
					}
					items = append(items, item)
				}
			}
		}
		info = items
	case FileNetworkOpenInformation:
		info = &FileNetworkOpenInformationInfo{
			CreationTime:   *BirthTimeFromVfs(a),
			LastAccessTime: *AccessTimeFromVfs(a),
			LastWriteTime:  *ModifiedTimeFromVfs(a),
			ChangeTime:     *ChangeTimeFromVfs(a),
			AllocationSize: int64(DiskSizeFromVfs(a)),
			EndOfFile:      int64(SizeFromVfs(a)),
			FileAttributes: PermissionsFromVfs(a, open.pathName),
		}
	case FileNormalizedNameInformation:
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_NOT_SUPPORTED))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	case FileInternalInformation:
		info = &FileInternalInformationInfo{
			int64(a.GetInodeNumber()),
		}
	default:
		log.Error("unsupported type")
		return &InvalidRequestError{"unsupported query class"}
	}

	rsp := new(QueryInfoResponse)
	PrepareResponse(&rsp.PacketHeader, pkt, 0)
	rsp.Output = info

	return c.sendPacket(rsp, &t.treeConn, ctx)
}

func (t *fileTree) queryInfoSec(ctx *compoundContext, pkt []byte) error {
	c := t.session.conn

	res, _ := accept(SMB2_QUERY_INFO, pkt)
	r := QueryInfoRequestDecoder(res)

	fileId := r.FileId().Decode()
	if ctx != nil && ctx.fileId != nil {
		fileId = ctx.fileId
	}

	if IsInvalidFileId(fileId) {
		log.Errorf("queryInfoSec: invalid fileid")
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_INVALID_HANDLE))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	attrs, err := t.fs.GetAttr(vfs.VfsHandle(fileId.HandleId()))
	if err != nil {
		log.Errorf("queryInfoSec: GetAttr() failed")
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_INVALID_HANDLE))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	sd := SecurityDescriptor{}
	if r.AdditionalInformation()&OWNER_SECURITY_INFORMATION != 0 {
		uid, _ := attrs.GetUID()
		sd.OwnerSid = SIDFromUid(uid)
	}
	if r.AdditionalInformation()&GROUP_SECUIRTY_INFORMATION != 0 {
		gid, _ := attrs.GetGID()
		sd.GroupSid = SIDFromGid(gid)
	}
	if r.AdditionalInformation()&DACL_SECUIRTY_INFORMATION != 0 {
		uid, _ := attrs.GetUID()
		gid, _ := attrs.GetGID()
		mode, _ := attrs.GetUnixMode()
		switch attrs.GetFileType() {
		case vfs.FileTypeDirectory:
			mode |= syscall.S_IFDIR
		case vfs.FileTypeSymlink:
			mode |= syscall.S_IFLNK
		default:
			mode |= syscall.S_IFREG
		}
		sd.Dacl = &ACL{
			ACE{ //OWner
				Sid:  SIDFromUid(uid),
				Type: ACCESS_ALLOWED_ACE_TYPE,
				Mask: UnixModeToAceMask(uint8((mode & 0700) >> 6)),
			},
			ACE{ // Group
				Sid:  SIDFromGid(gid),
				Type: ACCESS_ALLOWED_ACE_TYPE,
				Mask: UnixModeToAceMask(uint8((mode & 0070) >> 3)),
			},
			ACE{ // Everyone
				Sid:  &SID{IdentifierAuthority: WORLD_SID_AUTHORITY, SubAuthority: []uint32{0}},
				Type: ACCESS_ALLOWED_ACE_TYPE,
				Mask: UnixModeToAceMask(uint8(mode & 0007)),
			},
			ACE{ // Mode
				Sid:  SIDFromMode(mode),
				Type: ACCESS_DENIED_ACE_TYPE,
				Mask: 0,
			},
		}
	}

	rsp := new(QueryInfoResponse)
	PrepareResponse(&rsp.PacketHeader, pkt, 0)
	rsp.Output = &sd

	//rsp := new(ErrorResponse)
	//PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_NOT_SUPPORTED))

	return c.sendPacket(rsp, &t.treeConn, ctx)
}

func (t *fileTree) queryInfo(ctx *compoundContext, pkt []byte) error {
	log.Debugf("QueryInfo")

	c := t.session.conn

	res, err := accept(SMB2_QUERY_INFO, pkt)
	if err != nil {
		return err
	}

	r := QueryInfoRequestDecoder(res)
	if r.IsInvalid() {
		return &InvalidRequestError{"broken quety info format"}
	}

	log.Debugf("query info type: %d", r.InfoType())
	switch r.InfoType() {
	case SMB2_0_INFO_FILE:
		return t.queryInfoFile(ctx, pkt)
	case SMB2_0_INFO_FILESYSTEM:
		return t.queryInfoFileSystem(ctx, pkt)
	case SMB2_0_INFO_SECURITY:
		return t.queryInfoSec(ctx, pkt)
	case SMB2_0_INFO_QUOTA:
		log.Errorf("SMB2_0_INFO_QUOTA unsupported")
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_NOT_SUPPORTED))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	return nil
}

func (t *fileTree) setBasicInfo(ctx *compoundContext, fileId *FileId, pkt []byte) error {
	c := t.session.conn

	res, _ := accept(SMB2_SET_INFO, pkt)
	r := SetInfoRequestDecoder(res)
	info := FileBasicInformationInfoDecoder(r.Buffer())

	a := new(vfs.Attributes)

	ns := info.LastAccessTime().Nanoseconds()
	if ns != 0 {
		seconds := ns / 1e9
		nanoseconds := ns % 1e9
		a.SetAccessTime(time.Unix(seconds, nanoseconds))
	}
	ns = info.LastWriteTime().Nanoseconds()
	if ns != 0 {
		seconds := ns / 1e9
		nanoseconds := ns % 1e9
		a.SetLastDataModificationTime(time.Unix(seconds, nanoseconds))
	}
	ns = info.ChangeTime().Nanoseconds()
	if ns != 0 {
		seconds := ns / 1e9
		nanoseconds := ns % 1e9
		a.SetLastStatusChangeTime(time.Unix(seconds, nanoseconds))
	}
	ns = info.CreationTime().Nanoseconds()
	if ns != 0 {
		seconds := ns / 1e9
		nanoseconds := ns % 1e9
		a.SetBirthTime(time.Unix(seconds, nanoseconds))
	}

	if _, err := t.fs.SetAttr(vfs.VfsHandle(fileId.HandleId()), a); err != nil && !c.serverCtx.ignoreSetAttrErr {
		log.Errorf("SetAttr failed: %v", err)
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_NOT_SUPPORTED))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	rsp := new(SetInfoResponse)
	PrepareResponse(&rsp.PacketHeader, pkt, 0)
	return c.sendPacket(rsp, &t.treeConn, ctx)
}

func (t *fileTree) setEndOfFileInfo(ctx *compoundContext, fileId *FileId, pkt []byte) error {
	c := t.session.conn

	res, _ := accept(SMB2_SET_INFO, pkt)
	r := SetInfoRequestDecoder(res)
	info := FileEndOfFileInformationDecoder(r.Buffer())
	t.fs.Truncate(vfs.VfsHandle(fileId.HandleId()), uint64(info.EndOfFile()))

	rsp := new(SetInfoResponse)
	PrepareResponse(&rsp.PacketHeader, pkt, 0)
	return c.sendPacket(rsp, &t.treeConn, ctx)
}

func (t *fileTree) setDispositionInfo(ctx *compoundContext, fileId *FileId, pkt []byte) error {
	c := t.session.conn

	if err := t.fs.Unlink(vfs.VfsHandle(fileId.HandleId())); err != nil {
		log.Errorf("Delete failed: %v", err)
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_NOT_SUPPORTED))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	rsp := new(SetInfoResponse)
	PrepareResponse(&rsp.PacketHeader, pkt, 0)
	return c.sendPacket(rsp, &t.treeConn, ctx)
}

func (t *fileTree) setDispositionInfoEa(ctx *compoundContext, fileId *FileId, eaKey string, pkt []byte) error {
	c := t.session.conn

	if err := t.fs.Removexattr(vfs.VfsHandle(fileId.HandleId()), eaKey); err != nil {
		log.Errorf("removexattr failed: %v", err)
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_NOT_FOUND))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	rsp := new(SetInfoResponse)
	PrepareResponse(&rsp.PacketHeader, pkt, 0)
	return c.sendPacket(rsp, &t.treeConn, ctx)
}

func (t *fileTree) setRename(ctx *compoundContext, fileId *FileId, pkt []byte) error {
	c := t.session.conn

	res, _ := accept(SMB2_SET_INFO, pkt)
	r := SetInfoRequestDecoder(res)
	info := FileRenameInformationInfoDecoder(r.Buffer())

	log.Debugf("setRename %s, root %d", info.FileName(), info.RootDirectory())
	to := strings.ReplaceAll(info.FileName(), "\\", "/")
	if err := t.fs.Rename(vfs.VfsHandle(fileId.HandleId()), to, int(info.ReplaceIfExists())); err != nil {
		log.Errorf("rename failed: %v", err)
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_ACCESS_DENIED))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	rsp := new(SetInfoResponse)
	PrepareResponse(&rsp.PacketHeader, pkt, 0)
	return c.sendPacket(rsp, &t.treeConn, ctx)
}

func (t *fileTree) setSecInfo(ctx *compoundContext, fileId *FileId, pkt []byte) error {
	log.Debugf("setSecInfo")
	c := t.session.conn

	res, _ := accept(SMB2_SET_INFO, pkt)
	r := SetInfoRequestDecoder(res)
	sd := SecurityDescriptorDecoder(r.Buffer())
	daclBuf := sd.Dacl()
	if daclBuf == nil {
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_NOT_SUPPORTED))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	dacl := AclDecoder(daclBuf)
	aceBuf := dacl.Aces()
	foundNfsSid := false
	for i := 0; i < int(dacl.AceCount()); i++ {
		ace := AceDecoder(aceBuf)
		sidBuf := ace.Sid()
		sid := SidDecoder(sidBuf)
		if sid.SubAuthorityCount() == 3 && sid.SubAuthority()[0] == 88 && sid.SubAuthority()[1] == 3 {
			// NFS Mode Sid
			foundNfsSid = true
			mode := sid.SubAuthority()[2]

			a := &vfs.Attributes{}
			a.SetUnixMode(mode | 0600) // Owner can always read/write
			if _, err := t.fs.SetAttr(vfs.VfsHandle(fileId.HandleId()), a); err != nil {
				log.Errorf("SetAttr failed: %v", err)
				rsp := new(ErrorResponse)
				PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_ACCESS_DENIED))
				return c.sendPacket(rsp, &t.treeConn, ctx)
			}
			break
		}

		aceBuf = aceBuf[ace.Size():]
	}

	if !foundNfsSid {
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_ACCESS_DENIED))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	rsp := &SetInfoResponse{}
	PrepareResponse(&rsp.PacketHeader, pkt, 0)

	return c.sendPacket(rsp, &t.treeConn, ctx)
}

func (t *fileTree) setInfo(ctx *compoundContext, pkt []byte) error {
	log.Debugf("SetInfo")
	c := t.session.conn

	res, _ := accept(SMB2_SET_INFO, pkt)
	r := SetInfoRequestDecoder(res)

	fileId := r.FileId().Decode()
	if ctx != nil && ctx.fileId != nil {
		fileId = ctx.fileId
	}

	if IsInvalidFileId(fileId) {
		log.Errorf("SetInfo: invalid fileid")
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_INVALID_HANDLE))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	open := t.conn.serverCtx.getOpen(fileId.HandleId())
	if open == nil {
		log.Errorf("delete: no open")
		rsp := new(ErrorResponse)
		PrepareResponse(rsp.Header(), pkt, uint32(STATUS_INVALID_HANDLE))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	log.Debugf("SetInfo: %d class", r.FileInfoClass())

	switch r.InfoType() {
	case SMB2_0_INFO_SECURITY:
		return t.setSecInfo(ctx, fileId, pkt)
	}

	status := uint32(0)
	switch r.FileInfoClass() {
	case FileBasicInformation:
		if !open.isEa {
			return t.setBasicInfo(ctx, fileId, pkt)
		}
	case FileEndOfFileInformation:
		if !open.isEa {
			return t.setEndOfFileInfo(ctx, fileId, pkt)
		}
	case FileDispositionInformation:
		if open.isEa {
			return t.setDispositionInfoEa(ctx, fileId, open.eaKey, pkt)
		}
		return t.setDispositionInfo(ctx, fileId, pkt)
	case FileRenameInformation:
		if !open.isEa {
			return t.setRename(ctx, fileId, pkt)
		}
		status = uint32(STATUS_NOT_SUPPORTED)
	case FileAllocationInformation:
		rsp := &SetInfoResponse{}
		PrepareResponse(&rsp.PacketHeader, pkt, 0)
		return c.sendPacket(rsp, &t.treeConn, ctx)
	default:
		status = uint32(STATUS_NOT_SUPPORTED)
		log.Errorf("unsupported class %d in SetInfo", r.FileInfoClass())
	}

	rsp := new(ErrorResponse)
	PrepareResponse(&rsp.PacketHeader, pkt, status)

	return c.sendPacket(rsp, &t.treeConn, ctx)
}

func (t *fileTree) oplockBreak(ctx *compoundContext, pkt []byte) error {
	log.Errorf("OplockBreak")
	c := t.session.conn

	rsp := new(ErrorResponse)
	PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_NOT_SUPPORTED))

	return c.sendPacket(rsp, &t.treeConn, ctx)
}
