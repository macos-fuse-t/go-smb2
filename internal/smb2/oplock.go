package smb2

const (
	SMB2_LEASE_NONE           = 0x00
	SMB2_LEASE_READ_CACHING   = 0x01
	SMB2_LEASE_HANDLE_CACHING = 0x02
	SMB2_LEASE_WRITE_CACHING  = 0x04

	SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED = 0x01
	SMB2_OPLOCK_BREAK_ACK_SIZE                = 24
	SMB2_LEASE_BREAK_ACK_SIZE                 = 36
)

type OplockBreakNotification struct {
	PacketHeader
	OplockLevel uint8
	FileId      *FileId
}

func (c *OplockBreakNotification) Header() *PacketHeader {
	return &c.PacketHeader
}

func (c *OplockBreakNotification) Size() int {
	return 64 + 24
}

func (c *OplockBreakNotification) Encode(pkt []byte) {
	c.Command = SMB2_OPLOCK_BREAK
	c.encodeHeader(pkt)

	res := pkt[64:]
	le.PutUint16(res[:2], 24)
	res[2] = c.OplockLevel
	res[3] = 0
	le.PutUint32(res[4:8], 0)
	c.FileId.Encode(res[8:24])
}

type OplockBreakAcknowledgmentDecoder []byte

func (r OplockBreakAcknowledgmentDecoder) IsInvalid() bool {
	return len(r) < SMB2_OPLOCK_BREAK_ACK_SIZE || r.StructureSize() != SMB2_OPLOCK_BREAK_ACK_SIZE
}

func (r OplockBreakAcknowledgmentDecoder) StructureSize() uint16 {
	return le.Uint16(r[:2])
}

func (r OplockBreakAcknowledgmentDecoder) OplockLevel() uint8 {
	return r[2]
}

func (r OplockBreakAcknowledgmentDecoder) FileId() FileIdDecoder {
	return FileIdDecoder(r[8:24])
}

type LeaseBreakNotificationDecoder []byte

func (r LeaseBreakNotificationDecoder) IsInvalid() bool {
	return len(r) < 44 || r.StructureSize() != 44
}

func (r LeaseBreakNotificationDecoder) StructureSize() uint16 {
	return le.Uint16(r[:2])
}

func (r LeaseBreakNotificationDecoder) NewEpoch() uint16 {
	return le.Uint16(r[2:4])
}

func (r LeaseBreakNotificationDecoder) Flags() uint32 {
	return le.Uint32(r[4:8])
}

func (r LeaseBreakNotificationDecoder) LeaseKey() Guid {
	var ret Guid
	copy(ret[:], r[8:24])
	return ret
}

func (r LeaseBreakNotificationDecoder) CurrentLeaseState() uint32 {
	return le.Uint32(r[24:28])
}

func (r LeaseBreakNotificationDecoder) NewLeaseState() uint32 {
	return le.Uint32(r[28:32])
}

type OplockBreakResponse struct {
	PacketHeader
	OplockLevel uint8
	FileId      *FileId
}

func (c *OplockBreakResponse) Header() *PacketHeader {
	return &c.PacketHeader
}

func (c *OplockBreakResponse) Size() int {
	return 64 + 24
}

func (c *OplockBreakResponse) Encode(pkt []byte) {
	c.Command = SMB2_OPLOCK_BREAK
	c.encodeHeader(pkt)

	res := pkt[64:]
	le.PutUint16(res[:2], 24)
	res[2] = c.OplockLevel
	res[3] = 0
	le.PutUint32(res[4:8], 0)
	c.FileId.Encode(res[8:24])
}

type LeaseBreakNotification struct {
	PacketHeader
	NewEpoch          uint16
	Flags             uint32
	LeaseKey          Guid
	CurrentLeaseState uint32
	NewLeaseState     uint32
	BreakReason       uint32
	AccessMaskHint    uint32
	ShareMaskHint     uint32
}

func (c *LeaseBreakNotification) Header() *PacketHeader {
	return &c.PacketHeader
}

func (c *LeaseBreakNotification) Size() int {
	return 64 + 44
}

func (c *LeaseBreakNotification) Encode(pkt []byte) {
	c.Command = SMB2_OPLOCK_BREAK
	c.encodeHeader(pkt)

	res := pkt[64:]
	le.PutUint16(res[:2], 44)
	le.PutUint16(res[2:4], c.NewEpoch)
	le.PutUint32(res[4:8], c.Flags)
	copy(res[8:24], c.LeaseKey[:])
	le.PutUint32(res[24:28], c.CurrentLeaseState)
	le.PutUint32(res[28:32], c.NewLeaseState)
	le.PutUint32(res[32:36], c.BreakReason)
	le.PutUint32(res[36:40], c.AccessMaskHint)
	le.PutUint32(res[40:44], c.ShareMaskHint)
}

type LeaseBreakAcknowledgmentDecoder []byte

func (r LeaseBreakAcknowledgmentDecoder) IsInvalid() bool {
	return len(r) < SMB2_LEASE_BREAK_ACK_SIZE || r.StructureSize() != SMB2_LEASE_BREAK_ACK_SIZE
}

func (r LeaseBreakAcknowledgmentDecoder) StructureSize() uint16 {
	return le.Uint16(r[:2])
}

func (r LeaseBreakAcknowledgmentDecoder) LeaseKey() Guid {
	var ret Guid
	copy(ret[:], r[8:24])
	return ret
}

func (r LeaseBreakAcknowledgmentDecoder) LeaseState() uint32 {
	return le.Uint32(r[24:28])
}

type LeaseBreakResponse struct {
	PacketHeader
	LeaseKey      Guid
	LeaseState    uint32
	LeaseDuration uint64
}

func (c *LeaseBreakResponse) Header() *PacketHeader {
	return &c.PacketHeader
}

func (c *LeaseBreakResponse) Size() int {
	return 64 + 36
}

func (c *LeaseBreakResponse) Encode(pkt []byte) {
	c.Command = SMB2_OPLOCK_BREAK
	c.encodeHeader(pkt)

	res := pkt[64:]
	le.PutUint16(res[:2], 36)
	le.PutUint16(res[2:4], 0)
	le.PutUint32(res[4:8], 0)
	copy(res[8:24], c.LeaseKey[:])
	le.PutUint32(res[24:28], c.LeaseState)
	le.PutUint64(res[28:36], c.LeaseDuration)
}
