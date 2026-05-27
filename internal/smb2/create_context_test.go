package smb2

import "testing"

type fixedEncoder int

func (e fixedEncoder) Size() int {
	return int(e)
}

func (e fixedEncoder) Encode(pkt []byte) {
	for i := 0; i < int(e); i++ {
		pkt[i] = byte(i)
	}
}

func TestCreateResponseContextNextIncludesAlignmentPadding(t *testing.T) {
	rsp := &CreateResponse{
		FileId: &FileId{},
		Contexts: []Encoder{
			CreateContext{Name: "0123456789abcdef", Data: fixedEncoder(52)}, // total size 84
			CreateContext{Name: "QFid", Data: fixedEncoder(32)},
		},
	}
	pkt := make([]byte, rsp.Size())
	rsp.Encode(pkt)

	decoded := CreateResponseDecoder(pkt[64:])
	contexts := decoded.CreateContexts()
	first := CreateContextDecoder(contexts)
	if got, want := first.Next(), uint32(88); got != want {
		t.Fatalf("first response context Next = %d, want %d", got, want)
	}
	second := CreateContextDecoder(contexts[first.Next():])
	if got := second.Name(); got != "QFid" {
		t.Fatalf("second response context name = %q, want QFid", got)
	}
}

func TestCreateResponseWithoutContextsHasZeroContextLength(t *testing.T) {
	rsp := &CreateResponse{
		FileId: &FileId{},
	}
	pkt := make([]byte, rsp.Size())
	rsp.Encode(pkt)

	decoded := CreateResponseDecoder(pkt[64:])
	if got := decoded.CreateContextsOffset(); got != 0 {
		t.Fatalf("CreateContextsOffset = %d, want 0", got)
	}
	if got := decoded.CreateContextsLength(); got != 0 {
		t.Fatalf("CreateContextsLength = %d, want 0", got)
	}
	if contexts := decoded.CreateContexts(); contexts != nil {
		t.Fatalf("CreateContexts() = %v, want nil", contexts)
	}
}

func TestCreateRequestContextNextIncludesAlignmentPadding(t *testing.T) {
	req := &CreateRequest{
		Name: "root",
		Contexts: []Encoder{
			CreateContext{Name: "0123456789abcdef", Data: fixedEncoder(52)}, // total size 84
			CreateContext{Name: "QFid", Data: fixedEncoder(32)},
		},
	}
	pkt := make([]byte, req.Size())
	req.Encode(pkt)

	decoded := CreateRequestDecoder(pkt[64:])
	contexts := decoded.CreateContexts()
	first := CreateContextDecoder(contexts)
	if got, want := first.Next(), uint32(88); got != want {
		t.Fatalf("first request context Next = %d, want %d", got, want)
	}
	second := CreateContextDecoder(contexts[first.Next():])
	if got := second.Name(); got != "QFid" {
		t.Fatalf("second request context name = %q, want QFid", got)
	}
}
