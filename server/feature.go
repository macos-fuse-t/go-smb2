package smb2

import (
	. "github.com/macos-fuse-t/go-smb2/internal/smb2"
)

// client

const (
	clientCapabilities = SMB2_GLOBAL_CAP_LARGE_MTU | SMB2_GLOBAL_CAP_ENCRYPTION

	serverCapabilities = SMB2_GLOBAL_CAP_LARGE_MTU | SMB2_GLOBAL_CAP_ENCRYPTION |
		SMB2_GLOBAL_CAP_DFS | SMB2_GLOBAL_CAP_LEASING | SMB2_GLOBAL_CAP_DIRECTORY_LEASING |
		SMB2_GLOBAL_CAP_PERSISTENT_HANDLES
	serverMaxTransactSize = 0x800000
	serverMaxReadSize     = 0x800000
	serverMaxWriteSize    = 0x800000
)

const (
	serverDurableHandleTimeout = 60000 // 1 min
)

var (
	serverHashAlgorithms = []uint16{SHA512}
	serverCiphers        = []uint16{AES128GCM, AES128CCM}
)

var (
	clientHashAlgorithms = []uint16{SHA512}
	clientCiphers        = []uint16{AES128GCM, AES128CCM}
	clientDialects       = []uint16{SMB311, SMB302, SMB300, SMB210, SMB202}

	defaultDerverDialect = uint16(SMB311)
)

const (
	clientMaxCreditBalance = 128
)

const (
	clientMaxSymlinkDepth = 8
)
