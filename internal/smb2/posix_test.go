package smb2

import "testing"

func TestPosixContextEncodeDecode(t *testing.T) {
	ctx := &PosixContext{}
	buf := make([]byte, ctx.Size())
	ctx.Encode(buf)

	decoded := NegotiateContextDecoder(buf)
	if decoded.IsInvalid() {
		t.Fatalf("encoded context is invalid")
	}
	if decoded.ContextType() != SMB3_POSIX_EXTENSIONS_AVAILABLE {
		t.Fatalf("context type = %#x, want %#x", decoded.ContextType(), SMB3_POSIX_EXTENSIONS_AVAILABLE)
	}
	if !decoded.IsSMB3Posix() {
		t.Fatalf("encoded context was not recognized as SMB3 POSIX")
	}
}
