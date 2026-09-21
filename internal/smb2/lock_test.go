package smb2

import (
	"encoding/binary"
	"testing"
)

func TestLockRequestDecoder(t *testing.T) {
	b := make([]byte, 72)
	binary.LittleEndian.PutUint16(b[0:2], 48)
	binary.LittleEndian.PutUint16(b[2:4], 2)
	binary.LittleEndian.PutUint32(b[4:8], 0x1234)
	binary.LittleEndian.PutUint64(b[8:16], 11)
	binary.LittleEndian.PutUint64(b[16:24], 22)
	binary.LittleEndian.PutUint64(b[24:32], 100)
	binary.LittleEndian.PutUint64(b[32:40], 20)
	binary.LittleEndian.PutUint32(b[40:44], SMB2_LOCKFLAG_EXCLUSIVE_LOCK|SMB2_LOCKFLAG_FAIL_IMMEDIATELY)
	binary.LittleEndian.PutUint64(b[48:56], 200)
	binary.LittleEndian.PutUint64(b[56:64], 30)
	binary.LittleEndian.PutUint32(b[64:68], SMB2_LOCKFLAG_UNLOCK)

	r := LockRequestDecoder(b)
	if r.IsInvalid() {
		t.Fatal("valid request was rejected")
	}
	if r.LockCount() != 2 || r.LockSequence() != 0x1234 {
		t.Fatalf("header decoded incorrectly: count=%d sequence=%x", r.LockCount(), r.LockSequence())
	}
	locks := r.Locks()
	if locks[0].Offset() != 100 || locks[0].Length() != 20 || locks[1].Flags() != SMB2_LOCKFLAG_UNLOCK {
		t.Fatalf("lock elements decoded incorrectly: %#v", locks)
	}
}

func TestLockRequestDecoderRejectsTruncation(t *testing.T) {
	b := make([]byte, 48)
	binary.LittleEndian.PutUint16(b[0:2], 48)
	binary.LittleEndian.PutUint16(b[2:4], 2)
	if !LockRequestDecoder(b).IsInvalid() {
		t.Fatal("truncated request was accepted")
	}
}
