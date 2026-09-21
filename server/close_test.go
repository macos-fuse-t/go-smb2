package smb2

import (
	"testing"

	. "github.com/macos-fuse-t/go-smb2/internal/smb2"
)

func TestClosePostQueryAttrsAllowedForNonPosixOpen(t *testing.T) {
	open := &Open{}

	if !closePostQueryAttrsAllowed(SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB, open) {
		t.Fatal("close post-query attrs disabled for non-POSIX open")
	}
}

func TestClosePostQueryAttrsSuppressedForPosixOpen(t *testing.T) {
	open := &Open{posixSemantics: true}

	if closePostQueryAttrsAllowed(SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB, open) {
		t.Fatal("close post-query attrs enabled for POSIX open")
	}
}

func TestClosePostQueryAttrsRequireClientFlag(t *testing.T) {
	open := &Open{}

	if closePostQueryAttrsAllowed(0, open) {
		t.Fatal("close post-query attrs enabled without client flag")
	}
}
