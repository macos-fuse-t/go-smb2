package smb2

import "testing"

func TestFileFsSectorSizeInformationInfoEncode(t *testing.T) {
	info := &FileFsSectorSizeInformationInfo{
		LogicalBytesPerSector:                                 512,
		PhysicalBytesPerSectorForAtomicity:                    4096,
		PhysicalBytesPerSectorForPerformance:                  4096,
		FileSystemEffectivePhysicalBytesPerSectorForAtomicity: 4096,
		Flags: SSINFO_FLAGS_ALIGNED_DEVICE |
			SSINFO_FLAGS_PARTITION_ALIGNED_ON_DEVICE |
			SSINFO_FLAGS_NO_SEEK_PENALTY,
		ByteOffsetForSectorAlignment:    0,
		ByteOffsetForPartitionAlignment: 0,
	}

	if got := info.Size(); got != 28 {
		t.Fatalf("Size() = %d, want 28", got)
	}

	pkt := make([]byte, info.Size())
	info.Encode(pkt)

	tests := []struct {
		name string
		off  int
		want uint32
	}{
		{"LogicalBytesPerSector", 0, 512},
		{"PhysicalBytesPerSectorForAtomicity", 4, 4096},
		{"PhysicalBytesPerSectorForPerformance", 8, 4096},
		{"FileSystemEffectivePhysicalBytesPerSectorForAtomicity", 12, 4096},
		{"Flags", 16, 7},
		{"ByteOffsetForSectorAlignment", 20, 0},
		{"ByteOffsetForPartitionAlignment", 24, 0},
	}

	for _, tt := range tests {
		if got := le.Uint32(pkt[tt.off:]); got != tt.want {
			t.Fatalf("%s = %d, want %d", tt.name, got, tt.want)
		}
	}
}
