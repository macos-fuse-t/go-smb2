package smb2

import (
	"reflect"

	. "github.com/macos-fuse-t/go-smb2/internal/erref"
	. "github.com/macos-fuse-t/go-smb2/internal/smb2"
	log "github.com/sirupsen/logrus"
)

type ipcTree struct {
	treeConn
	shares []string

	dceReq []byte
}

func (t *ipcTree) getTree() *treeConn {
	return &t.treeConn
}

func (t *ipcTree) create(ctx *compoundContext, pkt []byte) error {
	c := t.session.conn

	res, err := accept(SMB2_CREATE, pkt)
	if err != nil {
		return err
	}

	r := CreateRequestDecoder(res)
	if r.IsInvalid() {
		return &InvalidRequestError{"broken create format"}
	}

	log.Debugf("create name: %s", r.Name())
	rsp := new(CreateResponse)
	PrepareResponse(&rsp.PacketHeader, pkt, 0)

	rsp.FileAttributes = FILE_ATTRIBUTE_NORMAL
	rsp.CreateAction = 1
	rsp.CreationTime = &Filetime{}
	rsp.LastAccessTime = &Filetime{}
	rsp.LastWriteTime = &Filetime{}
	rsp.ChangeTime = &Filetime{}

	if r.Name() != "srvsvc" {
		rsp.Status = uint32(STATUS_NOT_SUPPORTED)
	} else {
		rsp.FileId = &SRVSVC_GUID
	}
	return c.sendPacket(rsp, &t.treeConn, ctx)
}

func (t *ipcTree) close(ctx *compoundContext, pkt []byte) error {
	c := t.session.conn

	res, err := accept(SMB2_CLOSE, pkt)
	if err != nil {
		return err
	}

	r := CloseRequestDecoder(res)
	if r.IsInvalid() {
		return &InvalidRequestError{"broken close request"}
	}

	if !reflect.DeepEqual(r.FileId().Persistent(), SRVSVC_GUID.Persistent[:]) {
		return &InvalidRequestError{"bad file in close request"}
	}

	rsp := new(CloseResponse)
	PrepareResponse(&rsp.PacketHeader, pkt, 0)

	rsp.FileAttributes = FILE_ATTRIBUTE_NORMAL
	rsp.CreationTime = &Filetime{}
	rsp.LastAccessTime = &Filetime{}
	rsp.LastWriteTime = &Filetime{}
	rsp.ChangeTime = &Filetime{}

	return c.sendPacket(rsp, &t.treeConn, ctx)
}

func (t *ipcTree) flush(ctx *compoundContext, pkt []byte) error {
	return &InvalidRequestError{"invalid flush request for ipcTree"}
}

func (t *ipcTree) write(ctx *compoundContext, pkt []byte) error {
	c := t.session.conn

	res, _ := accept(SMB2_WRITE, pkt)
	r := WriteRequestDecoder(res)

	t.dceReq = r.Data()
	rsp := new(WriteResponse)
	PrepareResponse(&rsp.PacketHeader, pkt, 0)
	rsp.Count = uint32(len(t.dceReq))
	return c.sendPacket(rsp, &t.treeConn, ctx)
}

func (t *ipcTree) read(ctx *compoundContext, pkt []byte) error {
	c := t.session.conn

	rsp := new(ReadResponse)
	PrepareResponse(&rsp.PacketHeader, pkt, 0)
	if t.dceReq == nil {
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	dceReq := DCERequestDecoder(t.dceReq)
	if dceReq.IsInvalid() {
		log.Errorf("dceReq is invalid")
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, 0)
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	var rpc Encoder
	var err error

	switch dceReq.Header().PacketType {
	case PacketTypeBind:
		rpc, err = t.ipcTreeBindReq(ctx, t.dceReq)
	case PacketTypeRequest:
		rpc, err = t.ipcTreeReq(ctx, t.dceReq)
	default:
		err = &InvalidRequestError{"invalid read request for ipcTree"}
	}

	if err != nil {
		log.Errorf("error handling dce request: %v", err)
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_DATA_ERROR))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	t.dceReq = nil

	rsp.Data = make([]byte, rpc.Size())
	rpc.Encode(rsp.Data)
	return c.sendPacket(rsp, &t.treeConn, ctx)
}

func (t *ipcTree) ipcTreeBindReq(ctx *compoundContext, pkt []byte) (Encoder, error) {

	dceReq := DCERequestDecoder(pkt)
	bindReq := DCEBindRequestDecoder(pkt)

	ctxRsp := []ContextResponseItem{}
	for _, item := range bindReq.CtxItems() {
		rspItem := ContextResponseItem{}

		if !UUIDIsEqual(item.InterfaceUUID, SRVSVC_UUID) {
			rspItem.Result = 1
			log.Errorf("unsupported interface in bind req")
		}
		if len(item.TransferSyntaxes) != 1 {
			log.Errorf("too many transfer items in bind req")
			rspItem.Result = 2
		}
		transfer := item.TransferSyntaxes[0]
		if !UUIDIsEqual(transfer.SyntaxUUID, NDR_UUID) {
			//log.Errorf("bad transfer syntax in bind req")
			rspItem.Result = 2
		}

		if rspItem.Result == 0 {
			rspItem.TransferUUID = item.TransferSyntaxes[0].SyntaxUUID[:]
			ver := uint32(item.TransferSyntaxes[0].VersionMinor)<<16 | uint32(item.TransferSyntaxes[0].VersionMajor)
			rspItem.TransferVersion = ver
		}
		ctxRsp = append(ctxRsp, rspItem)
	}

	rpc := new(DCEBindAck)
	rpc.AssocGroupID = 0xcc21
	rpc.MaxRecvFragSize = bindReq.MaxRecvFragSize()
	rpc.MaxSendFragSize = bindReq.MaxSendFragSize()
	rpc.CallID = dceReq.Header().CallID
	rpc.SecAddr = append([]byte("\\pipe\\srvsvc"), 0)
	rpc.SecAddrLen = 13
	rpc.CtxCount = uint8(len(ctxRsp))
	rpc.CtxItems = ctxRsp

	return rpc, nil
}

func (t *ipcTree) ipcTreeReq(ctx *compoundContext, pkt []byte) (Encoder, error) {

	dceReq := DCERequestDecoder(pkt)
	req := DCERequestReqDecoder(pkt)

	var data Encoder
	switch req.Opnum() {
	case OpNetShareEnumAll:
		data = MakeNetShareEnumAllResponse(t.shares)
	case OpNetShareGetInfo:
		infoReq := NetShareGetInfoRequestDecoder(req.Data())
		data = MakeGetInfoShareResponse(infoReq.ShareName())
	default:
		return nil, &InvalidRequestError{"unsupported opnum in rpc request"}
	}

	rpc := new(DCERequestRes)
	rpc.CallID = dceReq.Header().CallID
	rpc.Data = data

	return rpc, nil
}

func (t *ipcTree) ioctl(ctx *compoundContext, pkt []byte) error {
	c := t.session.conn

	res, err := accept(SMB2_IOCTL, pkt)
	if err != nil {
		return err
	}

	r := IoctlRequestDecoder(res)
	if r.IsInvalid() {
		return &InvalidRequestError{"broken ioctl request"}
	}

	switch r.CtlCode() {
	case FSCTL_PIPE_TRANSCEIVE:
		break
	case FSCTL_DFS_GET_REFERRALS:
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_FS_DRIVER_REQUIRED))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	default:
		return &InvalidRequestError{"cannot handle ctl code"}
	}

	if !reflect.DeepEqual(r.FileId().Persistent(), SRVSVC_GUID.Persistent[:]) ||
		!reflect.DeepEqual(r.FileId().Volatile(), SRVSVC_GUID.Volatile[:]) {
		return &InvalidRequestError{"srvsvc uuid doesn't match"}
	}

	var rpc Encoder

	dceReq := DCERequestDecoder(r.Data())
	switch dceReq.Header().PacketType {
	case PacketTypeRequest:
		rpc, err = t.ipcTreeReq(ctx, r.Data())
	case PacketTypeBind:
		rpc, err = t.ipcTreeBindReq(ctx, r.Data())
	default:
		return &InvalidRequestError{"unsupported packet type"}
	}

	if err != nil {
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_ACCESS_DENIED))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	rsp := new(IoctlResponse)
	PrepareResponse(&rsp.PacketHeader, pkt, 0)

	rsp.CtlCode = FSCTL_PIPE_TRANSCEIVE
	rsp.FileId = &SRVSVC_GUID
	rsp.Output = rpc

	return c.sendPacket(rsp, &t.treeConn, ctx)
}

func (t *ipcTree) cancel(ctx *compoundContext, pkt []byte) error {
	return &InvalidRequestError{"invalid cancel request for ipcTree"}
}

func (t *ipcTree) queryDirectory(ctx *compoundContext, pkt []byte) error {
	return &InvalidRequestError{"invalid queryDirectory request for ipcTree"}
}

func (t *ipcTree) changeNotify(ctx *compoundContext, pkt []byte) error {
	return &InvalidRequestError{"invalid changeNotify request for ipcTree"}
}

func (t *ipcTree) queryInfo(ctx *compoundContext, pkt []byte) error {
	c := t.session.conn
	rsp := new(ErrorResponse)
	PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_NOT_SUPPORTED))
	return c.sendPacket(rsp, &t.treeConn, ctx)
}

func (t *ipcTree) setInfo(ctx *compoundContext, pkt []byte) error {
	return &InvalidRequestError{"invalid setInfo request for ipcTree"}
}

func (t *ipcTree) lock(ctx *compoundContext, pkt []byte) error {
	return &InvalidRequestError{"invalid lock request for ipcTree"}
}

func (t *ipcTree) oplockBreak(ctx *compoundContext, pkt []byte) error {
	return &InvalidRequestError{"invalid oplockBreak request for ipcTree"}
}
