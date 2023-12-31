package smb2

import (
	. "github.com/macos-fuse-t/go-smb2/internal/smb2"
)

type compoundContext struct {
	treeId     uint64
	sessionId  uint64
	fileId     *FileId
	lastStatus uint32
	lastMsgId  uint64

	rsp [][]byte
}

func (ctx *compoundContext) addResponse(pkt []byte) {
	ctx.rsp = append(ctx.rsp, pkt)
}

func (ctx *compoundContext) Size() int {
	s := 0
	for _, pkt := range ctx.rsp {
		s += Align(len(pkt), 8)
	}
	return s
}

func (ctx *compoundContext) Encode(buf []byte) {
	off := 0
	for i, p := range ctx.rsp {
		pkt := PacketCodec(p)
		if i > 0 {
			pkt.SetFlags(pkt.Flags() | SMB2_FLAGS_RELATED_OPERATIONS)
		}
		l := Align(len(p), 8)
		if i != len(ctx.rsp)-1 {
			pkt.SetNextCommand(uint32(l))
		}

		copy(buf[off:], pkt)
		off += l
	}
}
