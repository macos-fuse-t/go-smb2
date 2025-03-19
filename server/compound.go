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

func (ctx *compoundContext) isEmpty() bool {
	return len(ctx.rsp) == 0
}

func (ctx *compoundContext) addResponse(pkt []byte) {
	ctx.rsp = append(ctx.rsp, pkt)
}

func (ctx *compoundContext) Size() int {
	s := 0
	for i, pkt := range ctx.rsp {
		if i != len(ctx.rsp)-1 {
			s += Align(len(pkt), 8)
		} else {
			s += len(pkt)
		}
	}
	return s
}

func (ctx *compoundContext) Encode(buf []byte) {
	off := 0
	for _, p := range ctx.rsp {
		pkt := PacketCodec(p)
		l := Align(len(p), 8)
		copy(buf[off:], pkt)
		off += l
	}
}
