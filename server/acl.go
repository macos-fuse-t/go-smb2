package smb2

import "github.com/macos-fuse-t/go-smb2/internal/smb2"

type SID_IDENTIFIER_AUTHORITY [6]byte

var NULL_SID_AUTHORITY = SID_IDENTIFIER_AUTHORITY{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
var WORLD_SID_AUTHORITY = SID_IDENTIFIER_AUTHORITY{0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
var LOCAL_SID_AUTHORITY = SID_IDENTIFIER_AUTHORITY{0x00, 0x00, 0x00, 0x00, 0x00, 0x02}
var CREATOR_SID_AUTHORITY = SID_IDENTIFIER_AUTHORITY{0x00, 0x00, 0x00, 0x00, 0x00, 0x03}
var SECURITY_NT_AUTHORITY = SID_IDENTIFIER_AUTHORITY{0x00, 0x00, 0x00, 0x00, 0x00, 0x05}

const (
	ACCESS_ALLOWED_ACE_TYPE = 0x00
	ACCESS_DENIED_ACE_TYPE  = 0x01
)

const (
	ACL_REVISION = 0x02
)

type SecurityDescriptor struct {
	OwnerSid *SID
	GroupSid *SID
	Sacl     *ACL
	Dacl     *ACL
}

func (d *SecurityDescriptor) Size() int {
	s := 20
	if d.OwnerSid != nil {
		s += d.OwnerSid.Size()
	}
	if d.GroupSid != nil {
		s += d.GroupSid.Size()
	}
	if d.Sacl != nil {
		s += d.Sacl.Size()
	}
	if d.Dacl != nil {
		s += d.Dacl.Size()
	}
	return s
}

func (d *SecurityDescriptor) Encode(b []uint8) {
	control := uint16(1 << 15) // Self-Relative
	if d.Sacl != nil {
		control |= (1 << 4) // SP

	}
	if d.Dacl != nil {
		control |= (1 << 2) // DP

	}
	b[0] = 1 //Revision
	le.PutUint16(b[2:], control)

	offset := 20
	if d.OwnerSid != nil {
		le.PutUint32(b[4:], uint32(offset)) // OffsetOwner
		d.OwnerSid.Encode(b[offset:])
		offset += d.OwnerSid.Size()
	}

	if d.GroupSid != nil {
		le.PutUint32(b[8:], uint32(offset)) // OffsetGroup
		d.GroupSid.Encode(b[offset:])
		offset += d.GroupSid.Size()
	}

	if d.Sacl != nil {
		le.PutUint32(b[12:], uint32(offset)) // OffsetSacl
		d.Sacl.Encode(b[offset:])
		offset += d.Sacl.Size()
	}

	if d.Dacl != nil {
		le.PutUint32(b[16:], uint32(offset)) // OffsetDacl
		d.Dacl.Encode(b[offset:])
		offset += d.Dacl.Size()
	}
}

type SID struct {
	IdentifierAuthority SID_IDENTIFIER_AUTHORITY
	SubAuthority        []uint32
}

func SIDFromUid(uid uint32) *SID {
	return &SID{
		IdentifierAuthority: SECURITY_NT_AUTHORITY,
		SubAuthority:        []uint32{88, 1, uid},
	}
}

func SIDFromGid(gid uint32) *SID {
	return &SID{
		IdentifierAuthority: SECURITY_NT_AUTHORITY,
		SubAuthority:        []uint32{88, 2, gid},
	}
}

func SIDFromMode(mode uint32) *SID {
	return &SID{
		IdentifierAuthority: SECURITY_NT_AUTHORITY,
		SubAuthority:        []uint32{88, 3, mode},
	}
}

func (s *SID) Size() int {
	return 8 + len(s.SubAuthority)*4
}

func (s *SID) Encode(b []uint8) {
	b[0] = 1                          //Revision
	b[1] = uint8(len(s.SubAuthority)) //SubAuthorityCount
	copy(b[2:], s.IdentifierAuthority[:])
	for i, sa := range s.SubAuthority {
		le.PutUint32(b[8+i*4:], sa)
	}
}

type ACE struct {
	Sid  *SID
	Type uint8
	Mask uint32
}

func (a *ACE) Size() int {
	return 8 + a.Sid.Size()
}

func (a *ACE) Encode(b []uint8) {
	b[0] = a.Type
	b[1] = uint8(0) // Flags
	le.PutUint16(b[2:], uint16(a.Size()))
	le.PutUint32(b[4:], a.Mask)
	a.Sid.Encode(b[8:])
}

type ACL []ACE

func (a *ACL) Size() int {
	s := 0
	for _, ace := range *a {
		s += ace.Size()
	}
	return 8 + s
}

func (a *ACL) Encode(b []uint8) {
	b[0] = ACL_REVISION //Revision
	le.PutUint16(b[2:], uint16(a.Size()))
	le.PutUint16(b[4:], uint16(len(*a)))

	off := 8
	for _, ace := range *a {
		ace.Encode(b[off:])
		off += ace.Size()
	}
}

// rwx -> mask
func UnixModeToAceMask(mode uint8) uint32 {
	mask := uint32(0)
	if mode&1 != 0 {
		mask |= smb2.FILE_EXECUTE | smb2.FILE_READ_ATTRIBUTES | smb2.SYNCHRONIZE |
			smb2.READ_CONTROL
	}
	if mode&2 != 0 {
		mask |= smb2.FILE_WRITE_DATA | smb2.FILE_WRITE_ATTRIBUTES | smb2.FILE_WRITE_EA | smb2.WRITE_DAC | smb2.DELETE |
			smb2.READ_CONTROL
	}
	if mode&4 != 0 {
		mask |= smb2.FILE_READ_DATA | smb2.FILE_READ_ATTRIBUTES | smb2.FILE_READ_EA | smb2.READ_CONTROL
	}
	return mask
}

type SecurityDescriptorDecoder []byte

func (sd SecurityDescriptorDecoder) Revision() uint8 {
	return sd[0]
}

func (sd SecurityDescriptorDecoder) Control() uint16 {
	return le.Uint16(sd[2:])
}

func (sd SecurityDescriptorDecoder) OffsetOwner() uint32 {
	return le.Uint32(sd[4:])
}

func (sd SecurityDescriptorDecoder) OffsetGroup() uint32 {
	return le.Uint32(sd[8:])
}

func (sd SecurityDescriptorDecoder) OffsetSacl() uint32 {
	return le.Uint32(sd[12:])
}

func (sd SecurityDescriptorDecoder) OffsetDacl() uint32 {
	return le.Uint32(sd[16:])
}

func (sd SecurityDescriptorDecoder) OwnerSid() []byte {
	off := sd.OffsetOwner()
	if off == 0 {
		return nil
	}
	return sd[off:]
}

func (sd SecurityDescriptorDecoder) GroupSid() []byte {
	off := sd.OffsetGroup()
	if off == 0 {
		return nil
	}
	return sd[off:]
}

func (sd SecurityDescriptorDecoder) Sacl() []byte {
	off := sd.OffsetSacl()
	if off == 0 {
		return nil
	}
	return sd[off:]
}

func (sd SecurityDescriptorDecoder) Dacl() []byte {
	off := sd.OffsetDacl()
	if off == 0 {
		return nil
	}
	return sd[off:]
}

type AclDecoder []byte

func (a AclDecoder) Revision() uint8 {
	return a[0]
}

func (a AclDecoder) AclSize() uint16 {
	return le.Uint16(a[2:])
}

func (a AclDecoder) AceCount() uint16 {
	return le.Uint16(a[4:])
}

func (a AclDecoder) Aces() []byte {
	return a[8:]
}

type AceDecoder []byte

func (a AceDecoder) Type() uint8 {
	return a[0]
}

func (a AceDecoder) Flags() uint8 {
	return a[1]
}

func (a AceDecoder) Size() uint16 {
	return le.Uint16(a[2:])
}

func (a AceDecoder) Mask() uint32 {
	return le.Uint32(a[4:])
}

func (a AceDecoder) Sid() []byte {
	return a[8:]
}
