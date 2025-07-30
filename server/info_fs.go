package smb2

import (
	"encoding/binary"

	. "github.com/macos-fuse-t/go-smb2/internal/smb2"
	"github.com/macos-fuse-t/go-smb2/internal/utf16le"
)

var le = binary.LittleEndian

const (
	FILE_CASE_SENSITIVE_SEARCH        = 0x00000001
	FILE_CASE_PRESERVED_NAMES         = 0x00000002
	FILE_UNICODE_ON_DISK              = 0x00000004
	FILE_PERSISTENT_ACLS              = 0x00000008
	FILE_FILE_COMPRESSION             = 0x00000010
	FILE_VOLUME_QUOTAS                = 0x00000020
	FILE_SUPPORTS_SPARSE_FILES        = 0x00000040
	FILE_SUPPORTS_REPARSE_POINTS      = 0x00000080
	FILE_SUPPORTS_REMOTE_STORAGE      = 0x00000100
	FILE_VOLUME_IS_COMPRESSED         = 0x00008000
	FILE_SUPPORTS_OBJECT_IDS          = 0x00010000
	FILE_SUPPORTS_ENCRYPTION          = 0x00020000
	FILE_NAMED_STREAMS                = 0x00040000
	FILE_READ_ONLY_VOLUME             = 0x00080000
	FILE_SEQUENTIAL_WRITE_ONCE        = 0x00100000
	FILE_SUPPORTS_TRANSACTIONS        = 0x00200000
	FILE_SUPPORTS_HARD_LINKS          = 0x00400000
	FILE_SUPPORTS_EXTENDED_ATTRIBUTES = 0x00800000
	FILE_SUPPORTS_OPEN_BY_FILE_ID     = 0x01000000
	FILE_SUPPORTS_USN_JOURNAL         = 0x02000000
)

const (
	FILE_SUPERSEDED  = 0x00000000
	FILE_OPENED      = 0x00000001
	FILE_CREATED     = 0x00000002
	FILE_OVERWRITTEN = 0x00000003
)

type FileAccessInformationInfo struct {
	AccessFlags uint32
}

func (i *FileAccessInformationInfo) Size() int {
	return 4
}

func (i *FileAccessInformationInfo) Encode(pkt []byte) {
	le.PutUint32(pkt[:], i.AccessFlags)
}

type FileAlignmentInformationInfo struct {
	AlignmentRequirement uint32
}

func (i *FileAlignmentInformationInfo) Size() int {
	return 4
}

func (i *FileAlignmentInformationInfo) Encode(pkt []byte) {
	le.PutUint32(pkt[:], i.AlignmentRequirement)
}

type FileAllInformationInfo struct {
	BasicInformation     FileBasicInformationInfo
	StandardInformation  FileStandardInformationInfo
	Internal             FileInternalInformationInfo
	EaInformation        FileEaInformationInfo
	AccessInformation    FileAccessInformationInfo
	PositionInformation  FilePositionInformationInfo
	ModeInformation      FileModeInformationInfo
	AlignmentInformation FileAlignmentInformationInfo
	NameInformation      FileAlternateNameInformationInfo
}

func (i *FileAllInformationInfo) Size() int {
	return i.BasicInformation.Size() +
		i.StandardInformation.Size() +
		i.Internal.Size() +
		i.EaInformation.Size() +
		i.AccessInformation.Size() +
		i.PositionInformation.Size() +
		i.ModeInformation.Size() +
		i.AlignmentInformation.Size() +
		i.NameInformation.Size()
}

func (i *FileAllInformationInfo) Encode(pkt []byte) {
	off := 0
	i.BasicInformation.Encode(pkt[off:])
	off += i.BasicInformation.Size()

	i.StandardInformation.Encode(pkt[off:])
	off += i.StandardInformation.Size()

	i.Internal.Encode(pkt[off:])
	off += i.Internal.Size()

	i.EaInformation.Encode(pkt[off:])
	off += i.EaInformation.Size()

	i.AccessInformation.Encode(pkt[off:])
	off += i.AccessInformation.Size()

	i.PositionInformation.Encode(pkt[off:])
	off += i.PositionInformation.Size()

	i.ModeInformation.Encode(pkt[off:])
	off += i.ModeInformation.Size()

	i.AlignmentInformation.Encode(pkt[off:])
	off += i.AlignmentInformation.Size()

	i.NameInformation.Encode(pkt[off:])
	off += i.NameInformation.Size()
}

type FileAlternateNameInformationInfo struct {
	FileName string
}

func (i *FileAlternateNameInformationInfo) Size() int {
	return utf16le.EncodedStringLen(i.FileName) + 4
}

func (i *FileAlternateNameInformationInfo) Encode(pkt []byte) {
	le.PutUint32(pkt[:], uint32(utf16le.EncodedStringLen(i.FileName)))
	utf16le.EncodeString(pkt[4:], i.FileName)
}

type FileAttributeTagInformationInfo struct {
	FileAttributes uint32
	ReparseTag     uint32
}

type FileBasicInformationInfo struct {
	CreationTime   Filetime
	LastAccessTime Filetime
	LastWriteTime  Filetime
	ChangeTime     Filetime
	FileAttributes uint32
	Pad            uint32
}

func (i *FileBasicInformationInfo) Size() int {
	return 40
}

func (i *FileBasicInformationInfo) Encode(pkt []byte) {
	i.CreationTime.Encode(pkt[0:])
	i.LastAccessTime.Encode(pkt[8:])
	i.LastWriteTime.Encode(pkt[16:])
	i.ChangeTime.Encode(pkt[24:])
	le.PutUint32(pkt[32:], i.FileAttributes)
}

type FileBasicInformationInfoDecoder []byte

func (f FileBasicInformationInfoDecoder) CreationTime() *Filetime {
	return FiletimeDecoder(f[0:8]).Decode()
}

func (f FileBasicInformationInfoDecoder) LastAccessTime() *Filetime {
	return FiletimeDecoder(f[8:16]).Decode()
}

func (f FileBasicInformationInfoDecoder) LastWriteTime() *Filetime {
	return FiletimeDecoder(f[16:24]).Decode()
}

func (f FileBasicInformationInfoDecoder) ChangeTime() *Filetime {
	return FiletimeDecoder(f[24:32]).Decode()
}

func (f FileBasicInformationInfoDecoder) FileAttributes() uint32 {
	return le.Uint32(f[32:36])
}

type FileCompressionInformationInfo struct {
	CompressedFileSize   int64
	CompressionFormat    uint16
	CompressionUnitShift uint8
	ChunkShift           uint8
	ClusterShift         uint8
	Reserved             [3]uint8 // Placeholder for alignment and future use
}

type FileEaInformationInfo struct {
	EaSize uint32
}

func (i *FileEaInformationInfo) Size() int {
	return 4
}

func (i *FileEaInformationInfo) Encode(pkt []byte) {
	le.PutUint32(pkt[:], i.EaSize)
}

type FileFullEaInformationInfo struct {
	NextEntryOffset uint32
	Flags           uint8
	EaNameLength    uint8
	EaValueLength   uint16
	EaName          string
}

type FileIdInformationInfo struct {
	FileId int64
}

func (i *FileIdInformationInfo) Size() int {
	return 8
}

func (i *FileIdInformationInfo) Encode(pkt []byte) {
	le.PutUint64(pkt[:], uint64(i.FileId))
}

type FileInternalInformationInfo struct {
	IndexNumber int64
}

func (i *FileInternalInformationInfo) Size() int {
	return 8
}

func (i *FileInternalInformationInfo) Encode(pkt []byte) {
	le.PutUint64(pkt[:], uint64(i.IndexNumber))
}

type FileModeInformationInfo struct {
	Mode uint32
}

func (i *FileModeInformationInfo) Size() int {
	return 4
}

func (i *FileModeInformationInfo) Encode(pkt []byte) {
	le.PutUint32(pkt[:], i.Mode)
}

type FileNetworkOpenInformationInfo struct {
	CreationTime   Filetime
	LastAccessTime Filetime
	LastWriteTime  Filetime
	ChangeTime     Filetime
	AllocationSize int64
	EndOfFile      int64
	FileAttributes uint32
}

func (i *FileNetworkOpenInformationInfo) Size() int {
	return 56
}

func (i *FileNetworkOpenInformationInfo) Encode(pkt []byte) {
	i.CreationTime.Encode(pkt[0:])
	i.LastAccessTime.Encode(pkt[8:])
	i.LastWriteTime.Encode(pkt[16:])
	i.ChangeTime.Encode(pkt[24:])
	le.PutUint64(pkt[32:], uint64(i.AllocationSize))
	le.PutUint64(pkt[40:], uint64(i.EndOfFile))
	le.PutUint32(pkt[48:], i.FileAttributes)
}

type FileNormalizedNameInformationInfo struct {
	NormalizedName string
}

type FilePipeInformationInfo struct {
	ReadModeMessage uint32
	CompletionMode  uint32
}

type FilePipeLocalInformationInfo struct {
	NamedPipeType          uint32
	NamedPipeConfiguration uint32
	MaximumInstances       uint32
	CurrentInstances       uint32
	InboundQuota           uint32
	ReadDataAvailable      uint32
	OutboundQuota          uint32
	WriteQuotaAvailable    uint32
	NamedPipeState         uint32
	NamedPipeEnd           uint32
}

type FilePipeRemoteInformationInfo struct {
	CollectDataTime int64
	ByteCount       uint32
}

type FilePositionInformationInfo struct {
	CurrentByteOffset int64
}

func (i *FilePositionInformationInfo) Size() int {
	return 8
}

func (i *FilePositionInformationInfo) Encode(pkt []byte) {
	le.PutUint64(pkt[:], uint64(i.CurrentByteOffset))
}

type FileNamesInformationInfo struct {
	NextEntryOffset uint32
	FileIndex       uint32
	FileName        string
}

func (i FileNamesInformationInfo) Size() int {
	return Align(12+int(utf16le.EncodedStringLen(i.FileName)), 8)
}

func (i FileNamesInformationInfo) Encode(pkt []byte) {
	le.PutUint32(pkt[0:], i.NextEntryOffset)
	le.PutUint64(pkt[4:], uint64(i.FileIndex))
	le.PutUint32(pkt[8:], uint32(utf16le.EncodedStringLen(i.FileName)))
	utf16le.EncodeString(pkt[12:], i.FileName)
}

type FileStandardInformationInfo struct {
	AllocationSize int64
	EndOfFile      int64
	NumberOfLinks  uint32
	DeletePending  byte
	Directory      byte
	Pad            [2]byte
}

func (i *FileStandardInformationInfo) Size() int {
	return 24
}

func (i *FileStandardInformationInfo) Encode(pkt []byte) {
	le.PutUint64(pkt[:], uint64(i.AllocationSize))
	le.PutUint64(pkt[8:], uint64(i.EndOfFile))
	le.PutUint32(pkt[16:], i.NumberOfLinks)
	pkt[20] = i.DeletePending
	pkt[21] = i.Directory
}

type FileStreamInformationInfo struct {
	NextEntryOffset uint32
	//StreamNameLength     uint32
	StreamSize           uint64
	StreamAllocationSize uint64
	StreamName           string
}

func (i *FileStreamInformationInfo) Size() int {
	return Roundup(24+utf16le.EncodedStringLen(i.StreamName), 8)
}

func (i *FileStreamInformationInfo) Encode(pkt []byte) {
	le.PutUint32(pkt[0:], i.NextEntryOffset)
	le.PutUint32(pkt[4:], uint32(utf16le.EncodedStringLen(i.StreamName)))
	le.PutUint64(pkt[8:], uint64(i.StreamSize))
	le.PutUint64(pkt[16:], uint64(i.StreamAllocationSize))
	utf16le.EncodeString(pkt[24:], i.StreamName)
}

type FileStreamInformationInfoItems []FileStreamInformationInfo

func (i FileStreamInformationInfoItems) Size() int {
	s := 0
	for _, item := range i {
		s += item.Size()
	}
	return s
}

func (i FileStreamInformationInfoItems) Encode(pkt []byte) {
	off := uint32(0)
	for n, item := range i {
		if n < len(i)-1 {
			item.NextEntryOffset = uint32(item.Size())
		}
		item.Encode(pkt[off:])
		off += item.NextEntryOffset
	}
}

type FileFsAttributeInformationInfo struct {
	FileSystemAttributes       uint32
	MaximumComponentNameLength uint32
	//FileSystemNameLength       uint32
	FileSystemName string
}

func (i *FileFsAttributeInformationInfo) Size() int {
	return Align(12+utf16le.EncodedStringLen(i.FileSystemName), 8)
}

func (i *FileFsAttributeInformationInfo) Encode(pkt []byte) {
	le.PutUint32(pkt[0:], i.FileSystemAttributes)
	le.PutUint32(pkt[4:], i.MaximumComponentNameLength)
	le.PutUint32(pkt[8:], uint32(utf16le.EncodedStringLen(i.FileSystemName)))
	utf16le.EncodeString(pkt[12:], i.FileSystemName)
}

type FileFsControlInformationInfo struct {
	FreeSpaceStartFiltering int64
	FreeSpaceThreshold      int64
	FreeSpaceStopFiltering  int64
	DefaultQuotaThreshold   int64
	DefaultQuotaLimit       int64
	FileSystemControlFlags  uint32
}

const (
	FILE_DEVICE_CD_ROM = 0x00000002
	FILE_DEVICE_DISK   = 0x00000007
)

const (
	FILE_REMOVABLE_MEDIA                     = 0x00000001
	FILE_READ_ONLY_DEVICE                    = 0x00000002
	FILE_FLOPPY_DISKETTE                     = 0x00000004
	FILE_WRITE_ONCE_MEDIA                    = 0x00000008
	FILE_REMOTE_DEVICE                       = 0x00000010
	FILE_DEVICE_IS_MOUNTED                   = 0x00000020
	FILE_VIRTUAL_VOLUME                      = 0x00000040
	FILE_DEVICE_SECURE_OPEN                  = 0x00000100
	FILE_CHARACTERISTIC_TS_DEVICE            = 0x00001000
	FILE_CHARACTERISTIC_WEBDAV_DEVICE        = 0x00002000
	FILE_DEVICE_ALLOW_APPCONTAINER_TRAVERSAL = 0x00020000
	FILE_PORTABLE_DEVICE                     = 0x0004000
)

type FileFsDeviceInformationInfo struct {
	DeviceType      uint32
	Characteristics uint32
}

func (i *FileFsDeviceInformationInfo) Size() int {
	return 8
}

func (i *FileFsDeviceInformationInfo) Encode(pkt []byte) {
	le.PutUint32(pkt[:], i.DeviceType)
	le.PutUint32(pkt[4:], i.Characteristics)
}

type FileFsFullSizeInformationInfo struct {
	TotalAllocationUnits           int64
	CallerAvailableAllocationUnits int64
	ActualAvailableAllocationUnits int64
	SectorsPerAllocationUnit       uint32
	BytesPerSector                 uint32
}

func (i *FileFsFullSizeInformationInfo) Size() int {
	return 32
}

func (i *FileFsFullSizeInformationInfo) Encode(pkt []byte) {
	le.PutUint64(pkt[0:], uint64(i.TotalAllocationUnits))
	le.PutUint64(pkt[8:], uint64(i.CallerAvailableAllocationUnits))
	le.PutUint64(pkt[18:], uint64(i.ActualAvailableAllocationUnits))
	le.PutUint32(pkt[24:], i.SectorsPerAllocationUnit)
	le.PutUint32(pkt[28:], i.BytesPerSector)
}

type FileFsObjectIdInformationInfo struct {
	FileSystemObjectId [16]byte // Typically UUIDs are 16 bytes
	ExtendedInfo       [48]byte // Extended information, could be an array of bytes or further structured
}

type FileFsSectorSizeInformationInfo struct {
	LogicalBytesPerSector                                 uint32
	PhysicalBytesPerSectorForAtomicity                    uint32
	PhysicalBytesPerSectorForPerformance                  uint32
	FileSystemEffectivePhysicalBytesPerSectorForAtomicity uint32
	Flags                                                 uint32
	ByteOffsetForSectorAlignment                          uint32
	ByteOffsetForPartitionAlignment                       uint32
}

type FileFsSizeInformationInfo struct {
	TotalAllocationUnits     int64
	AvailableAllocationUnits int64
	SectorsPerAllocationUnit uint32
	BytesPerSector           uint32
}

func (i *FileFsSizeInformationInfo) Size() int {
	return 24
}

func (i *FileFsSizeInformationInfo) Encode(pkt []byte) {
	le.PutUint64(pkt[0:], uint64(i.TotalAllocationUnits))
	le.PutUint64(pkt[8:], uint64(i.AvailableAllocationUnits))
	le.PutUint32(pkt[16:], i.SectorsPerAllocationUnit)
	le.PutUint32(pkt[20:], i.BytesPerSector)
}

type FileFsVolumeInformationInfo struct {
	VolumeCreationTime Filetime
	VolumeSerialNumber uint32
	//VolumeLabelLength  uint32
	SupportsObjects bool
	VolumeLabel     string
}

func (i FileFsVolumeInformationInfo) Size() int {
	return Align(18+utf16le.EncodedStringLen(i.VolumeLabel), 8)
}

func (i FileFsVolumeInformationInfo) Encode(pkt []byte) {
	i.VolumeCreationTime.Encode(pkt[:])
	le.PutUint32(pkt[8:], i.VolumeSerialNumber)
	le.PutUint32(pkt[12:], uint32(utf16le.EncodedStringLen(i.VolumeLabel)))
	utf16le.EncodeString(pkt[18:], i.VolumeLabel)

}

type FileDirectoryInformationInfo struct {
	NextEntryOffset uint32 // Byte offset of the next file or directory entry, 0 if this is the last entry
	FileIndex       uint32
	CreationTime    Filetime
	LastAccessTime  Filetime
	LastWriteTime   Filetime
	ChangeTime      Filetime
	EndOfFile       uint64
	AllocationSize  uint64
	FileAttributes  uint32
	FileName        string
}

func (i FileDirectoryInformationInfo) Size() int {
	return Align(64+int(utf16le.EncodedStringLen(i.FileName)), 8)
}

func (i FileDirectoryInformationInfo) Encode(pkt []byte) {
	le.PutUint32(pkt[:], i.NextEntryOffset)
	le.PutUint32(pkt[4:], i.FileIndex)
	i.CreationTime.Encode(pkt[8:])
	i.LastAccessTime.Encode(pkt[16:])
	i.LastWriteTime.Encode(pkt[24:])
	i.ChangeTime.Encode(pkt[32:])
	le.PutUint64(pkt[40:], i.EndOfFile)
	le.PutUint64(pkt[48:], i.AllocationSize)
	le.PutUint32(pkt[56:], i.FileAttributes)
	le.PutUint32(pkt[60:], uint32(utf16le.EncodedStringLen(i.FileName)))
	utf16le.EncodeString(pkt[64:], i.FileName)
}

type FileFullDirectoryInformationInfo struct {
	NextEntryOffset uint32 // Byte offset of the next file or directory entry, 0 if this is the last entry
	FileIndex       uint32
	CreationTime    Filetime
	LastAccessTime  Filetime
	LastWriteTime   Filetime
	ChangeTime      Filetime
	EndOfFile       uint64
	AllocationSize  uint64
	FileAttributes  uint32
	EaSize          uint32
	FileName        string
}

func (i FileFullDirectoryInformationInfo) Size() int {
	return Align(68+int(utf16le.EncodedStringLen(i.FileName)), 8)
}

func (i FileFullDirectoryInformationInfo) Encode(pkt []byte) {
	le.PutUint32(pkt[:], i.NextEntryOffset)
	le.PutUint32(pkt[4:], i.FileIndex)
	i.CreationTime.Encode(pkt[8:])
	i.LastAccessTime.Encode(pkt[16:])
	i.LastWriteTime.Encode(pkt[24:])
	i.ChangeTime.Encode(pkt[32:])
	le.PutUint64(pkt[40:], i.EndOfFile)
	le.PutUint64(pkt[48:], i.AllocationSize)
	le.PutUint32(pkt[56:], i.FileAttributes)
	le.PutUint32(pkt[60:], uint32(utf16le.EncodedStringLen(i.FileName)))
	le.PutUint32(pkt[64:], i.EaSize)
	utf16le.EncodeString(pkt[68:], i.FileName)
}

type FileBothDirectoryInformationInfo struct {
	NextEntryOffset uint32 // Byte offset of the next file or directory entry, 0 if this is the last entry
	FileIndex       uint32
	CreationTime    Filetime
	LastAccessTime  Filetime
	LastWriteTime   Filetime
	ChangeTime      Filetime
	EndOfFile       uint64
	AllocationSize  uint64
	FileAttributes  uint32
	//FileNameLength  uint32
	EaSize          uint32
	ShortNameLength uint8
	Pad             uint8
	ShortName       [24]byte // The file's short name in 8.3 format
	FileName        string
}

func (i FileBothDirectoryInformationInfo) Size() int {
	return Align(82+int(utf16le.EncodedStringLen(i.FileName)), 8)
}

func (i FileBothDirectoryInformationInfo) Encode(pkt []byte) {
	le.PutUint32(pkt[:], i.NextEntryOffset)
	le.PutUint32(pkt[4:], i.FileIndex)
	i.CreationTime.Encode(pkt[8:])
	i.LastAccessTime.Encode(pkt[16:])
	i.LastWriteTime.Encode(pkt[24:])
	i.ChangeTime.Encode(pkt[32:])
	le.PutUint64(pkt[40:], i.EndOfFile)
	le.PutUint64(pkt[48:], i.AllocationSize)
	le.PutUint32(pkt[56:], i.FileAttributes)
	le.PutUint32(pkt[60:], uint32(utf16le.EncodedStringLen(i.FileName)))
	le.PutUint32(pkt[64:], i.EaSize)
	utf16le.EncodeString(pkt[82:], i.FileName)
}

type FileIdBothDirectoryInformationInfo struct {
	NextEntryOffset uint32 // Byte offset of the next file or directory entry, 0 if this is the last entry
	FileIndex       uint32
	CreationTime    Filetime
	LastAccessTime  Filetime
	LastWriteTime   Filetime
	ChangeTime      Filetime
	EndOfFile       uint64
	AllocationSize  uint64
	FileAttributes  uint32
	//FileNameLength  uint32
	EaSize          uint32
	ShortNameLength uint8
	Pad             uint8
	ShortName       [24]byte // The file's short name in 8.3 format
	Pad2            uint16
	FileId          uint64
	FileName        string
}

func (i FileIdBothDirectoryInformationInfo) Size() int {
	return Align(104+int(utf16le.EncodedStringLen(i.FileName)), 8)
}

func (i FileIdBothDirectoryInformationInfo) Encode(pkt []byte) {
	le.PutUint32(pkt[:], i.NextEntryOffset)
	le.PutUint32(pkt[4:], i.FileIndex)
	i.CreationTime.Encode(pkt[8:])
	i.LastAccessTime.Encode(pkt[16:])
	i.LastWriteTime.Encode(pkt[24:])
	i.ChangeTime.Encode(pkt[32:])
	le.PutUint64(pkt[40:], i.EndOfFile)
	le.PutUint64(pkt[48:], i.AllocationSize)
	le.PutUint32(pkt[56:], i.FileAttributes)
	le.PutUint32(pkt[60:], uint32(utf16le.EncodedStringLen(i.FileName)))
	le.PutUint32(pkt[64:], i.EaSize)
	le.PutUint64(pkt[96:], i.FileId)
	utf16le.EncodeString(pkt[104:], i.FileName)
}

type FileIdBothDirectoryInformationInfo2 struct {
	NextEntryOffset uint32 // Byte offset of the next file or directory entry, 0 if this is the last entry
	FileIndex       uint32
	CreationTime    Filetime
	LastAccessTime  Filetime
	LastWriteTime   Filetime
	ChangeTime      Filetime
	EndOfFile       uint64
	AllocationSize  uint64
	FileAttributes  uint32
	//FileNameLength  uint32
	MaxAccess            uint32
	ShortNameLength      uint8
	Pad                  uint8
	RsrcForkLen          uint64
	CompressedFinderInfo [16]byte
	UnixMode             uint16
	FileId               uint64
	FileName             string
}

func (i FileIdBothDirectoryInformationInfo2) Size() int {
	return Align(104+int(utf16le.EncodedStringLen(i.FileName)), 8)
}

func (i FileIdBothDirectoryInformationInfo2) Encode(pkt []byte) {
	le.PutUint32(pkt[:], i.NextEntryOffset)
	le.PutUint32(pkt[4:], i.FileIndex)
	i.CreationTime.Encode(pkt[8:])
	i.LastAccessTime.Encode(pkt[16:])
	i.LastWriteTime.Encode(pkt[24:])
	i.ChangeTime.Encode(pkt[32:])
	le.PutUint64(pkt[40:], i.EndOfFile)
	le.PutUint64(pkt[48:], i.AllocationSize)
	le.PutUint32(pkt[56:], i.FileAttributes)
	le.PutUint32(pkt[60:], uint32(utf16le.EncodedStringLen(i.FileName)))
	le.PutUint32(pkt[64:], i.MaxAccess)
	pkt[68] = i.ShortNameLength
	le.PutUint64(pkt[70:], i.RsrcForkLen)
	copy(pkt[78:], i.CompressedFinderInfo[:])
	le.PutUint16(pkt[94:], i.UnixMode)
	le.PutUint64(pkt[96:], i.FileId)
	utf16le.EncodeString(pkt[104:], i.FileName)
}

type FileIdFullDirectoryInformationInfo struct {
	NextEntryOffset uint32 // Byte offset of the next file or directory entry, 0 if this is the last entry
	FileIndex       uint32
	CreationTime    Filetime
	LastAccessTime  Filetime
	LastWriteTime   Filetime
	ChangeTime      Filetime
	EndOfFile       uint64
	AllocationSize  uint64
	FileAttributes  uint32
	//FileNameLength  uint32
	EaSize   uint32
	Pad2     uint32
	FileId   uint64
	FileName string
}

func (i FileIdFullDirectoryInformationInfo) Size() int {
	return Align(80+int(utf16le.EncodedStringLen(i.FileName)), 8)
}

func (i FileIdFullDirectoryInformationInfo) Encode(pkt []byte) {
	le.PutUint32(pkt[:], i.NextEntryOffset)
	le.PutUint32(pkt[4:], i.FileIndex)
	i.CreationTime.Encode(pkt[8:])
	i.LastAccessTime.Encode(pkt[16:])
	i.LastWriteTime.Encode(pkt[24:])
	i.ChangeTime.Encode(pkt[32:])
	le.PutUint64(pkt[40:], i.EndOfFile)
	le.PutUint64(pkt[48:], i.AllocationSize)
	le.PutUint32(pkt[56:], i.FileAttributes)
	le.PutUint32(pkt[60:], uint32(utf16le.EncodedStringLen(i.FileName)))
	le.PutUint32(pkt[64:], i.EaSize)
	le.PutUint64(pkt[72:], i.FileId)
	utf16le.EncodeString(pkt[80:], i.FileName)
}

type FileIdAllExtdBothDirectoryInformationInfo struct {
	NextEntryOffset uint32 // Byte offset of the next file or directory entry, 0 if this is the last entry
	FileIndex       uint32
	CreationTime    Filetime
	LastAccessTime  Filetime
	LastWriteTime   Filetime
	ChangeTime      Filetime
	EndOfFile       uint64
	AllocationSize  uint64
	FileAttributes  uint32
	EaSize          uint32
	ReparsePointTag uint32
	FileId          uint64 // 64-bit unique file identifier
	FileId128       uint64
	FileId128_2     uint64
	ShortNameLength uint8
	Pad             uint8
	ShortName       [24]byte // The file's short name in 8.3 format
	FileName        string
}

// Size returns the size of the encoded structure.
func (i FileIdAllExtdBothDirectoryInformationInfo) Size() int {
	return Align(122+utf16le.EncodedStringLen(i.FileName), 8)
}

// Encode serializes the structure into the given byte slice.
func (i FileIdAllExtdBothDirectoryInformationInfo) Encode(pkt []byte) {
	binary.LittleEndian.PutUint32(pkt[:], i.NextEntryOffset)
	binary.LittleEndian.PutUint32(pkt[4:], i.FileIndex)
	i.CreationTime.Encode(pkt[8:])
	i.LastAccessTime.Encode(pkt[16:])
	i.LastWriteTime.Encode(pkt[24:])
	i.ChangeTime.Encode(pkt[32:])
	binary.LittleEndian.PutUint64(pkt[40:], i.EndOfFile)
	binary.LittleEndian.PutUint64(pkt[48:], i.AllocationSize)
	binary.LittleEndian.PutUint32(pkt[56:], i.FileAttributes)
	binary.LittleEndian.PutUint32(pkt[60:], uint32(utf16le.EncodedStringLen(i.FileName)))
	binary.LittleEndian.PutUint32(pkt[64:], i.EaSize)
	binary.LittleEndian.PutUint32(pkt[68:], i.ReparsePointTag)
	binary.LittleEndian.PutUint64(pkt[72:], i.FileId)
	binary.LittleEndian.PutUint64(pkt[80:], i.FileId128)
	binary.LittleEndian.PutUint64(pkt[88:], i.FileId128_2)
	pkt[96] = i.ShortNameLength
	pkt[97] = i.Pad
	copy(pkt[98:122], i.ShortName[:])

	utf16le.EncodeString(pkt[122:], i.FileName)
}

type FileInformationInfoResponse struct {
	Items []Encoder
}

func (i *FileInformationInfoResponse) Size() int {
	s := 0
	for _, info := range i.Items {
		s += info.Size()
	}
	return s
}

func (i *FileInformationInfoResponse) Encode(pkt []byte) {
	off := 0
	for n, info := range i.Items {
		nextEntryOffset := 0
		if n != len(i.Items)-1 {
			nextEntryOffset = info.Size()
		}
		info.Encode(pkt[off:])
		le.PutUint32(pkt[off:], uint32(nextEntryOffset))
		off += info.Size()
	}
}

type FileEndOfFileInformationInfo struct {
	EndOfFile uint64
}

type FileEndOfFileInformationInfoDecoder []byte

func (f FileEndOfFileInformationInfoDecoder) EndOfFile() uint64 {
	return le.Uint64(f[0:8])
}

type FileDispositionInformationInfo struct {
	DeletePending byte
	//Pad           [3]byte
}

type FileDispositionInformationInfoDecoder []byte

func (f FileDispositionInformationInfoDecoder) DeletePending() byte {
	return f[0]
}

type FileRenameInformationInfo struct {
	ReplaceIfExists byte
	//Reserved        [7]byte
	RootDirectory  uint64
	FileNameLength uint32
	FileName       string
}

type FileRenameInformationInfoDecoder []byte

func (f FileRenameInformationInfoDecoder) ReplaceIfExists() byte {
	return f[0]
}

func (f FileRenameInformationInfoDecoder) RootDirectory() uint64 {
	return le.Uint64(f[8:16])
}

func (f FileRenameInformationInfoDecoder) FileNameLength() uint32 {
	return le.Uint32(f[16:20])
}

func (f FileRenameInformationInfoDecoder) FileName() string {
	return utf16le.DecodeToString(f[20 : 20+f.FileNameLength()])
}

const (
	FILE_ACTION_ADDED                  = 0x00000001
	FILE_ACTION_REMOVED                = 0x00000002
	FILE_ACTION_MODIFIED               = 0x00000003
	FILE_ACTION_RENAMED_OLD_NAME       = 0x00000004
	FILE_ACTION_RENAMED_NEW_NAME       = 0x00000005
	FILE_ACTION_ADDED_STREAM           = 0x00000006
	FILE_ACTION_REMOVED_STREAM         = 0x00000007
	FILE_ACTION_MODIFIED_STREAM        = 0x00000008
	FILE_ACTION_REMOVED_BY_DELETE      = 0x00000009
	FILE_ACTION_ID_NOT_TUNNELLED       = 0x0000000A
	FILE_ACTION_TUNNELLED_ID_COLLISION = 0x0000000B
)

type FileNotifyInformationInfo struct {
	NextEntryOffset uint32
	Action          uint32
	FileName        string
}

func (i *FileNotifyInformationInfo) Size() int {
	return 12 + utf16le.EncodedStringLen(i.FileName)
}

func (i *FileNotifyInformationInfo) Encode(pkt []byte) {
	le.PutUint32(pkt[0:], uint32(i.NextEntryOffset))
	le.PutUint32(pkt[4:], uint32(i.Action))
	le.PutUint32(pkt[8:], uint32(utf16le.EncodedStringLen(i.FileName)))
	utf16le.EncodeString(pkt[12:], i.FileName)
}

type AfpInfo struct {
	Signature  [4]byte // always "AFP_"
	Version    [4]byte // usually 0x00010000 for AFP_AfpInfo
	FileBitmap [2]byte // bitmap for file attributes
	Reserved1  [2]byte
	FinderInfo [32]byte // Finder-specific information
	ProDOSInfo [6]byte  // ProDOS metadata
	Reserved2  [10]byte
}

func (i *AfpInfo) Size() int {
	return 60
}

func (i *AfpInfo) Encode(pkt []byte) {
	copy(pkt[:], i.Signature[:])
	copy(pkt[4:], i.Version[:])
	copy(pkt[8:], i.FileBitmap[:])
	copy(pkt[12:], i.FinderInfo[:])
	copy(pkt[44:], i.ProDOSInfo[:])
}

type FileObjectId1 struct {
	ObjectId      FileId
	BirthVolumeId FileId
	BirthObjectId FileId
	DomainId      FileId
}

func (i *FileObjectId1) Size() int {
	return 64
}

func (i *FileObjectId1) Encode(pkt []byte) {
	i.ObjectId.Encode(pkt[:])
	i.BirthVolumeId.Encode(pkt[16:])
	i.BirthObjectId.Encode(pkt[32:])
	i.DomainId.Encode(pkt[48:])
}

type FileFsObjectIdInfo struct {
	ObjectId     FileId
	ExtendedInfo [48]byte
}

func (i *FileFsObjectIdInfo) Size() int {
	return 64
}

func (i *FileFsObjectIdInfo) Encode(pkt []byte) {
	i.ObjectId.Encode(pkt[:])
}
