package smb2

import "testing"

func TestEncodeHeaderUsesAsyncIdWhenPresent(t *testing.T) {
	hdr := PacketHeader{
		Command:   SMB2_READ,
		Flags:     SMB2_FLAGS_SERVER_TO_REDIR | SMB2_FLAGS_ASYNC_COMMAND,
		MessageId: 42,
		AsyncId:   0x1122334455667788,
		TreeId:    0xaabbccdd,
		SessionId: 0x0102030405060708,
	}
	pkt := make([]byte, 64)

	hdr.encodeHeader(pkt)
	p := PacketCodec(pkt)

	if got := p.AsyncId(); got != hdr.AsyncId {
		t.Fatalf("AsyncId = 0x%x, want 0x%x", got, hdr.AsyncId)
	}
	if got := p.TreeId(); got == hdr.TreeId {
		t.Fatalf("TreeId was encoded into async header: 0x%x", got)
	}
}
