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

func TestNetworkInterfaceInfoListEncode(t *testing.T) {
	info := NetworkInterfaceInfoList{
		{
			IfIndex:    7,
			Capability: 0,
			LinkSpeed:  1_000_000_000,
			IPv4:       [4]byte{192, 168, 64, 1},
		},
	}

	if got := info.Size(); got != 152 {
		t.Fatalf("Size() = %d, want 152", got)
	}

	pkt := make([]byte, info.Size())
	info.Encode(pkt)

	if got := le.Uint32(pkt[0:]); got != 0 {
		t.Fatalf("Next = %d, want 0", got)
	}
	if got := le.Uint32(pkt[4:]); got != 7 {
		t.Fatalf("IfIndex = %d, want 7", got)
	}
	if got := le.Uint64(pkt[16:]); got != 1_000_000_000 {
		t.Fatalf("LinkSpeed = %d, want 1000000000", got)
	}
	if got := le.Uint16(pkt[24:]); got != 2 {
		t.Fatalf("AddressFamily = %d, want 2", got)
	}
	if got := pkt[28:32]; string(got) != string([]byte{192, 168, 64, 1}) {
		t.Fatalf("IPv4 = %v, want [192 168 64 1]", []byte(got))
	}
}
