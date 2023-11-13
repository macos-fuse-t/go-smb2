package smb2

import (
	"reflect"

	"github.com/macos-fuse-t/go-smb2/internal/utf16le"
)

// MSRPC Packet Types
const (
	PacketTypeRequest  uint8 = 0
	PacketTypeResponse uint8 = 2
	PacketTypeBind     uint8 = 11
	PacketTypeBindAck  uint8 = 12
)

const (
	OpNetShareEnumAll uint16 = 15
	OpNetShareGetInfo uint16 = 16
)

const (
	StypeDisktree    uint32 = 0x00000000 // Disk drive
	StypePrintq      uint32 = 0x00000001 // Print queue
	StypeDevice      uint32 = 0x00000002 // Communication device
	StypeIPC         uint32 = 0x00000003 // Interprocess communication (IPC)
	StypeClusterFS   uint32 = 0x02000000 // A cluster share
	StypeClusterSOFS uint32 = 0x04000000 // A Scale-Out cluster share
	StypeClusterDFS  uint32 = 0x08000000 // A DFS share in a cluster
	StypeSpecial     uint32 = 0x80000000 // Special share reserved for interprocess communication (IPC$) or remote administration of the server (ADMIN$). Can also refer to administrative shares such as C$, D$, E$, and so forth.
	StypeTemporary   uint32 = 0x40000000 // A temporary share that is not persisted for creation each time the file server initializes.
)

type UUID [16]byte

var (
	SRVSVC_UUID = UUID{0xc8, 0x4f, 0x32, 0x4b, 0x70, 0x16, 0xd3, 0x01, 0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88}
	NDR_UUID    = UUID{0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60}
)

type DCEHeader struct {
	Version            byte
	VersionMinor       byte
	PacketType         byte
	PacketFlags        byte
	DataRepresentation [4]byte
	FragLength         uint16
	AuthLength         uint16
	CallID             uint32
}

type DCEFault struct {
	StatusCode  uint32
	FaultString string
}

type DCERPCBinding struct {
	ProtocolSequence string
	NetworkAddress   string
	Endpoint         string
	InterfaceUUID    UUID
	Version          string
	Options          map[string]string
}

type DCEBindRequest struct {
	DCEHeader
	MaxSendFragSize uint16
	MaxRecvFragSize uint16
	AssocGroupID    uint32
	NumCtxItems     byte
	Reserved        byte
	Reserved2       uint16

	CtxItems []ContextRequestItem
}

type DCEBindAck struct {
	DCEHeader
	MaxSendFragSize uint16
	MaxRecvFragSize uint16
	AssocGroupID    uint32
	SecAddrLen      uint16
	SecAddr         []byte
	Align           []byte
	CtxCount        byte
	Reserved        byte
	Reserved2       uint16
	CtxItems        []ContextResponseItem
}

type ContextRequestItem struct {
	ContextID           uint16
	TransferSyntaxCount uint8
	Reserved            byte
	InterfaceUUID       UUID
	VersionMajor        uint16
	VersionMinor        uint16
	TransferSyntaxes    []TransferSyntax
}

type ContextResponseItem struct { // 24 bytes size
	Result          uint32
	TransferUUID    []byte
	TransferVersion uint32
}

type TransferSyntax struct {
	SyntaxUUID   UUID
	VersionMajor uint16
	VersionMinor uint16
}

type DCERequestReq struct { // 24 + len of Buffer
	DCEHeader // 16 bytes
	AllocHint uint32
	ContextId uint16
	Opnum     uint16
	Buffer    []byte // Always start at an 8-byte boundary
}

type DCERequestRes struct {
	DCEHeader
	AllocHint   uint32
	ContextId   uint16
	CancelCount byte
	Reserved    byte
	Data        Encoder
}

type NetShareEnumAllResponse struct {
	Level        uint32
	Ctr          NetShareCtr
	TotalEntries uint32
	Resume       ResumeHandle
	WindowsError uint32
}

type ResumeHandle struct {
	Handle uint32
}

type NetShareCtr struct {
	Ctr     uint32
	Pointer Encoder
}

type NetShareCtr1 struct {
	Count uint32
	Info  *NetShareInfo1
}

type NetShareInfo1 struct {
	Count   uint32
	Pointer []ShareInfo1
}

type ShareInfo1 struct {
	Name    *UnicodeStr
	Type    uint32
	Comment *UnicodeStr
}

type UnicodeStr struct {
	MaxCount      uint32
	Offset        uint32
	ActualCount   uint32
	EncodedString []byte
	Padding       []byte
}

type DCERequestDecoder []byte

func (r DCERequestDecoder) IsInvalid() bool {
	return len(r) < 16
}

func (r DCERequestDecoder) Header() *DCEHeader {
	hdr := DCEHeader{}
	hdr.Version = r[0]
	hdr.VersionMinor = r[1]
	hdr.PacketType = r[2]
	hdr.PacketFlags = r[3]
	copy(hdr.DataRepresentation[:], r[4:])
	hdr.FragLength = le.Uint16(r[8:10])
	hdr.AuthLength = le.Uint16(r[10:12])
	hdr.CallID = le.Uint32(r[12:16])
	return &hdr
}

type DCEBindRequestDecoder []byte

func (r DCEBindRequestDecoder) MaxSendFragSize() uint16 {
	return le.Uint16(r[16:18])
}

func (r DCEBindRequestDecoder) MaxRecvFragSize() uint16 {
	return le.Uint16(r[18:20])
}

func (r DCEBindRequestDecoder) AssocGroupID() uint32 {
	return le.Uint32(r[20:24])
}

func (r DCEBindRequestDecoder) NumCtxItems() byte {
	return r[24]
}

func (r DCEBindRequestDecoder) CtxItems() []ContextRequestItem {
	ctxItems := []ContextRequestItem{}

	off := 28
	for i := 0; i < int(r.NumCtxItems()); i++ {
		item := ContextRequestItem{}
		item.ContextID = le.Uint16(r[off : off+2])
		item.TransferSyntaxCount = r[off+2]
		copy(item.InterfaceUUID[:], r[off+4:])
		item.VersionMajor = le.Uint16(r[off+20 : off+22])
		item.VersionMinor = le.Uint16(r[off+22 : off+24])

		off += 24

		for j := 0; j < int(item.TransferSyntaxCount); j++ {
			t := TransferSyntax{}
			copy(t.SyntaxUUID[:], r[off:])
			t.VersionMajor = le.Uint16(r[off+16 : off+18])
			t.VersionMinor = le.Uint16(r[off+18 : off+20])
			item.TransferSyntaxes = append(item.TransferSyntaxes, t)

			off += 20
		}
		ctxItems = append(ctxItems, item)
	}
	return ctxItems
}

func (hdr *DCEHeader) encodeHeader(pkt []byte) {
	pkt[0] = hdr.Version
	pkt[1] = hdr.VersionMinor
	pkt[2] = hdr.PacketType
	pkt[3] = hdr.PacketFlags
	copy(pkt[4:], hdr.DataRepresentation[:])
	le.PutUint16(pkt[8:10], hdr.FragLength)
	le.PutUint16(pkt[10:12], hdr.AuthLength)
	le.PutUint32(pkt[12:16], hdr.CallID)
}

func (r *DCEBindAck) Size() int {
	return Align(30+int(r.SecAddrLen), 2) + int(r.CtxCount)*24
}

func (r *DCEBindAck) Encode(pkt []byte) {
	r.Version = 5
	r.VersionMinor = 0
	r.PacketType = PacketTypeBindAck
	r.PacketFlags = 3
	r.DataRepresentation[0] = 0x10
	if r.MaxRecvFragSize == 0 {
		r.MaxRecvFragSize = 5840
	}
	if r.MaxSendFragSize == 0 {
		r.MaxSendFragSize = 5840
	}
	r.FragLength = uint16(r.Size())

	r.encodeHeader(pkt)

	le.PutUint16(pkt[16:18], r.MaxSendFragSize)
	le.PutUint16(pkt[18:20], r.MaxRecvFragSize)
	le.PutUint32(pkt[20:24], r.AssocGroupID)
	le.PutUint16(pkt[24:26], r.SecAddrLen)
	copy(pkt[26:], r.SecAddr)
	pkt[39] = 0
	pkt[40] = r.CtxCount

	off := 44
	for _, item := range r.CtxItems {
		le.PutUint32(pkt[off:off+4], item.Result)
		copy(pkt[off+4:], item.TransferUUID)
		le.PutUint32(pkt[off+20:off+24], item.TransferVersion)
		off += 24
	}
}

func (r *DCERequestRes) Size() int {
	if r.Data == nil {
		return 24
	}
	return 24 + r.Data.Size()
}

func (r *DCERequestRes) Encode(pkt []byte) {
	r.Version = 5
	r.VersionMinor = 0
	r.PacketType = PacketTypeResponse
	r.PacketFlags = 3
	r.DataRepresentation[0] = 0x10
	r.FragLength = uint16(r.Size())

	r.encodeHeader(pkt)

	le.PutUint32(pkt[16:20], r.AllocHint)
	le.PutUint16(pkt[20:22], r.ContextId)
	pkt[22] = r.CancelCount
	if r.Data != nil {
		r.Data.Encode(pkt[24:])
	}

}

type DCERequestReqDecoder []byte

func (r DCERequestReqDecoder) AllocHint() uint32 {
	return le.Uint32(r[16:20])
}

func (r DCERequestReqDecoder) ContextId() uint16 {
	return le.Uint16(r[20:22])
}

func (r DCERequestReqDecoder) Opnum() uint16 {
	return le.Uint16(r[22:24])
}

func (r DCERequestReqDecoder) Data() []byte {
	return r[24:]
}

func UUIDIsEqual(uuid1 UUID, uuid2 UUID) bool {
	return reflect.DeepEqual(uuid1, uuid2)
}

func (s *UnicodeStr) Size() int {
	return 12 + Align(int(s.ActualCount*2), 4)
}

func (s *UnicodeStr) Encode(pkt []byte) {
	le.PutUint32(pkt[0:], s.MaxCount)
	le.PutUint32(pkt[4:8], s.Offset)
	le.PutUint32(pkt[8:12], s.ActualCount)
	copy(pkt[12:], s.EncodedString)
}

func (n *NetShareInfo1) Size() int {
	s := 4
	for _, i := range n.Pointer {
		s += i.Comment.Size() + i.Name.Size() + 12
	}
	return s
}

func (n *NetShareInfo1) Encode(pkt []byte) {
	le.PutUint32(pkt[0:4], n.Count)

	off := 4
	for _, i := range n.Pointer {
		le.PutUint32(pkt[off:], refId())
		off += 4
		le.PutUint32(pkt[off:], i.Type)
		off += 4
		le.PutUint32(pkt[off:], refId())
		off += 4
	}

	for _, i := range n.Pointer {
		i.Name.Encode(pkt[off:])
		off += i.Name.Size()
		i.Comment.Encode(pkt[off:])
		off += i.Comment.Size()
	}
}

func (n *NetShareCtr1) Size() int {
	return n.Info.Size() + 8
}

func (n *NetShareCtr1) Encode(pkt []byte) {
	le.PutUint32(pkt[0:], n.Count)
	le.PutUint32(pkt[4:8], refId())
	n.Info.Encode(pkt[8:])
}

func (n *NetShareCtr) Size() int {
	if n.Ctr == 1 {
		return 8 + n.Pointer.(*NetShareCtr1).Size()
	}
	return 0
}

func (n *NetShareCtr) Encode(pkt []byte) {
	le.PutUint32(pkt[0:], n.Ctr)
	le.PutUint32(pkt[4:], refId())
	n.Pointer.Encode(pkt[8:])
}

func (r NetShareEnumAllResponse) Size() int {
	return 20 + r.Ctr.Size()
}

func (r NetShareEnumAllResponse) Encode(pkt []byte) {
	le.PutUint32(pkt[0:], r.Level)
	r.Ctr.Encode(pkt[4:])
	off := 4 + r.Ctr.Size()
	le.PutUint32(pkt[off:off+4], r.TotalEntries)
	le.PutUint32(pkt[off+4:off+8], refId())
	le.PutUint32(pkt[off+8:off+12], r.Resume.Handle)
	le.PutUint32(pkt[off+12:off+16], r.WindowsError)
}

var _refId = uint32(0x10000)

func refId() uint32 {
	r := _refId
	_refId++
	return r
}

func makeUnicodeStr(s string) *UnicodeStr {
	// Requires traling zero?
	str := string(append([]byte(s), 0))
	u := UnicodeStr{}
	b := utf16le.EncodeStringToBytes(str)
	u.MaxCount = uint32(len(str))
	u.ActualCount = uint32(len(str))
	u.EncodedString = b
	return &u
}

func MakeNetShareEnumAllResponse(shares []string) *NetShareEnumAllResponse {
	rsp := NetShareEnumAllResponse{
		Level: 1,
		Ctr: NetShareCtr{
			Ctr: 1,
			Pointer: &NetShareCtr1{
				Count: uint32(len(shares)),
				Info: &NetShareInfo1{
					Count: uint32(len(shares)),
				},
			},
		},
		TotalEntries: uint32(len(shares)),
		Resume:       ResumeHandle{},
	}

	ctr := rsp.Ctr.Pointer.(*NetShareCtr1)
	for _, share := range shares {
		info := ShareInfo1{
			Name:    makeUnicodeStr(share),
			Type:    StypeDisktree,
			Comment: makeUnicodeStr(""),
		}
		ctr.Info.Pointer = append(ctr.Info.Pointer, info)
	}

	return &rsp
}

type NetShareGetInfoRequestDecoder []byte

func (r NetShareGetInfoRequestDecoder) ServerName() string {
	len1 := int(le.Uint32(r[12:]))
	if 16+len1*2 > len(r) {
		return ""
	}
	return utf16le.DecodeToString(r[16 : 16+len1*2])
}

func (r NetShareGetInfoRequestDecoder) ShareName() string {
	off := 16 + Align(len(r.ServerName()), 2)*2
	len1 := int(le.Uint32(r[off+8:]))
	if off+off+12+len1*2 > len(r) {
		return ""
	}
	return utf16le.DecodeToString(r[off+12 : off+12+len1*2])
}

func (r NetShareGetInfoRequestDecoder) Level() uint32 {
	off := 28 + Align(len(r.ServerName()), 2)*2 + Align(len(r.ShareName()), 2)*2
	if off > len(r) {
		return 0
	}
	return le.Uint32(r[off:])
}

type NetShareGetInfoResponse struct {
	Level        uint32
	Pointer      Encoder
	WindowsError uint32
}

type NetShareGetInfo1 struct {
	Name    *UnicodeStr
	Type    uint32
	Comment *UnicodeStr
}

func MakeGetInfoShareResponse(share string) *NetShareGetInfoResponse {
	return &NetShareGetInfoResponse{
		Level: 1,
		Pointer: &NetShareGetInfo1{
			Name:    makeUnicodeStr(share),
			Type:    StypeDisktree,
			Comment: makeUnicodeStr("comment"),
		},
	}
}

func (n *NetShareGetInfoResponse) Size() int {
	return n.Pointer.Size() + 12
}

func (n *NetShareGetInfoResponse) Encode(pkt []byte) {
	le.PutUint32(pkt[0:], n.Level)
	le.PutUint32(pkt[4:], refId())
	n.Pointer.Encode(pkt[8:])
	off := 8 + n.Pointer.Size()
	le.PutUint32(pkt[off:], n.WindowsError)
}

func (n *NetShareGetInfo1) Size() int {
	return n.Comment.Size() + n.Name.Size() + 12
}

func (n *NetShareGetInfo1) Encode(pkt []byte) {
	off := 0
	le.PutUint32(pkt[off:], refId())
	off += 4
	le.PutUint32(pkt[off:], n.Type)
	off += 4
	le.PutUint32(pkt[off:], refId())
	off += 4

	n.Name.Encode(pkt[off:])
	off += n.Name.Size()
	n.Comment.Encode(pkt[off:])
	off += n.Comment.Size()
}
