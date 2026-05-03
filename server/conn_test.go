package smb2

import (
	"context"
	"testing"

	. "github.com/macos-fuse-t/go-smb2/internal/smb2"
)

func TestEncodeSessionlessEchoResponseKeepsZeroSession(t *testing.T) {
	c := &conn{
		account: openAccount(16),
		ctx:     context.Background(),
	}
	s := &session{
		conn:      c,
		sessionId: 0x1122334455667788,
	}
	c.session = s
	c.enableSession()

	rsp := &EchoResponse{}
	rsp.MessageId = 42
	rsp.Flags = SMB2_FLAGS_SERVER_TO_REDIR

	pkt, err := c.encodePacket(rsp, nil, c.ctx)
	if err != nil {
		t.Fatal(err)
	}

	p := PacketCodec(pkt)
	if got := p.SessionId(); got != 0 {
		t.Fatalf("SessionId = 0x%x, want 0", got)
	}
	if p.Flags()&SMB2_FLAGS_SIGNED != 0 {
		t.Fatalf("sessionless echo response was signed")
	}
}
