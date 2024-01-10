package smb2

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/macos-fuse-t/go-smb2/internal/crypto/ccm"
	"github.com/macos-fuse-t/go-smb2/internal/crypto/cmac"
	. "github.com/macos-fuse-t/go-smb2/internal/erref"
	. "github.com/macos-fuse-t/go-smb2/internal/smb2"
	"github.com/macos-fuse-t/go-smb2/vfs"
	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"
)

const DEFAULT_IOPS = 32

type Server struct {
	maxCreditBalance uint16 // if it's zero, clientMaxCreditBalance is used. (See feature.go for more details)
	negotiator       ServerNegotiator
	authenticator    Authenticator

	serverStartTime time.Time
	serverGuid      Guid

	shares     map[string]vfs.VFSFileSystem
	origShares map[string]vfs.VFSFileSystem

	opens       map[uint64]*Open
	opensByGuid map[Guid]*Open

	allowGuest bool

	maxIOReads  int
	maxIOWrites int

	xattrs bool

	lock sync.Mutex
}

type OpLockState uint8

const (
	LOCKSTATE_NONE OpLockState = iota
	LOCKSTATE_HELD
	LOCKSTATE_BREAKING
)

type Open struct {
	fileId                      uint64
	durableFileId               uint64
	session                     *session
	tree                        *treeConn
	grantedAccess               uint32
	oplockLevel                 uint8
	oplockState                 OpLockState
	oplockTimeout               time.Duration
	isDurable                   bool
	durableOpenTimeout          time.Duration
	durableOpenScavengerTimeout time.Duration
	durableOwner                uint64
	currentEaIndex              uint32
	currentQuotaIndex           uint32
	lockCount                   int
	pathName                    string
	fileName                    string
	resumeKey                   [24]byte
	createOptions               uint32
	createDisposition           uint32
	fileAttributes              uint32
	clientGuid                  Guid
	lease                       *Lease
	isResilient                 bool
	resiliencyTimeout           time.Duration
	resilientOpenTimeout        time.Duration
	lockSequenceArray           [64]byte
	notifyReq                   []byte
	isEa                        bool
	eaKey                       string
	isSymlink                   bool
	createGuid                  Guid
	appInstanceId               Guid
	isPersistent                bool
	channelSequence             uint16
	outstandingRequestCoun      int
	outstandingPreRequestCount  int
}

type Lease struct {
}

// Negotiator contains options for func (*Dialer) Dial.
type ServerNegotiator struct {
	RequireMessageSigning bool   // enforce signing?
	SpecifiedDialect      uint16 // if it's zero, clientDialects is used. (See feature.go for more details)
	Spnego                *spnegoServer
}

type ConnState int

const (
	STATE_NEGOTIATE = ConnState(iota)
	STATE_SESSION_SETUP
	STATE_SESSION_SETUP_CHALLENGE
	STATE_SESSION_ACTIVE
)

var (
	SRVSVC_GUID  = FileId{}
	INVALID_GUID = FileId{
		Persistent: [8]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		Volatile:   [8]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	}
)

type ServerConfig struct {
	AllowGuest  bool
	MaxIOReads  int
	MaxIOWrites int
	Xatrrs      bool
}

func NewServer(cfg *ServerConfig, a Authenticator, shares map[string]vfs.VFSFileSystem) *Server {
	newShares := map[string]vfs.VFSFileSystem{}
	for i, v := range shares {
		newShares[strings.ToUpper(i)] = v
	}

	srv := &Server{
		authenticator: a,
		shares:        newShares,
		origShares:    shares,
		opens:         map[uint64]*Open{},
		allowGuest:    cfg.AllowGuest,
		maxIOReads:    cfg.MaxIOReads,
		maxIOWrites:   cfg.MaxIOWrites,
		xattrs:        cfg.Xatrrs,
	}
	return srv
}

func (d *Server) Serve(addr string) error {

	_, err := rand.Read(d.serverGuid[:])
	if err != nil {
		log.Errorf("failed to generate server guid")
		return &InternalError{err.Error()}
	}
	rand.Read(SRVSVC_GUID.Persistent[:])
	rand.Read(SRVSVC_GUID.Volatile[:])

	// Listen on TCP port 8080 on all available interfaces.
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error setting up listener: %v\n", err)
		os.Exit(1)
	}
	defer listener.Close()

	for {
		// Accept a new connection.
		c, err := listener.Accept()
		if err != nil {
			continue
		}

		ctx := context.Background()

		maxCreditBalance := d.maxCreditBalance
		if maxCreditBalance == 0 {
			maxCreditBalance = clientMaxCreditBalance
		}
		a := openAccount(maxCreditBalance)

		conn := &conn{
			t:                   direct(c),
			outstandingRequests: newOutstandingRequests(),
			account:             a,
			rdone:               make(chan struct{}, 1),
			wdone:               make(chan struct{}, 1),
			write:               make(chan []byte, 10),
			werr:                make(chan error, 1),
			ctx:                 ctx,
			serverCtx:           d,
			serverState:         STATE_NEGOTIATE,
			cipherId:            AES128GCM,
			hashId:              SHA512,
			treeMapByName:       make(map[string]treeOps),
			treeMapById:         make(map[uint32]treeOps),
		}

		go conn.runReciever()
		go conn.runSender()
		// Handle the connection in a new goroutine.
		go func() {

			if err = conn.Run(); err != nil {
				// Run failed
				log.Errorf("err: %v", err)
				c.Close()
			}
		}()
	}
}

func (c *conn) Run() error {
	for {
		pkt, compCtx, err := c.srvRecv()
		if err != nil {
			return err
		}

		p := PacketCodec(pkt)
		if p.Flags()&SMB2_FLAGS_ASYNC_COMMAND != 0 {
			log.Errorf("Async command!!!!")
		}

		switch p.Command() {
		case SMB2_NEGOTIATE, SMB_COM_NEGOTIATE:
			err = c.negotiate(pkt)
		case SMB2_SESSION_SETUP:
			err = c.sessionSetup(pkt)
		case SMB2_LOGOFF:
			err = c.logoff(pkt)
		case SMB2_TREE_CONNECT:
			err = c.treeConnect(pkt)
		case SMB2_TREE_DISCONNECT:
			err = c.treeDisconnect(pkt)
		case SMB2_ECHO:
			err = c.echo(compCtx, pkt)
		default:
			p := PacketCodec(pkt)
			tc, ok := c.treeMapById[p.TreeId()]
			if !ok {
				err = &InvalidRequestError{fmt.Sprintf("tree %d doesn't exist: command %d", p.TreeId(), p.Command())}
				break
			}

			// if prev transaction req failed, don't forward it
			if compCtx != nil && compCtx.lastStatus != 0 {
				rsp := new(ErrorResponse)
				PrepareResponse(&rsp.PacketHeader, pkt, uint32(compCtx.lastStatus))
				c.sendPacket(rsp, tc.getTree(), compCtx)
				continue
			}

			switch p.Command() {
			case SMB2_CREATE:
				err = tc.create(compCtx, pkt)
			case SMB2_CLOSE:
				err = tc.close(compCtx, pkt)
			case SMB2_FLUSH:
				err = tc.flush(compCtx, pkt)
			case SMB2_READ:
				err = tc.read(compCtx, pkt)
			case SMB2_WRITE:
				err = tc.write(compCtx, pkt)
			case SMB2_LOCK:
				err = tc.lock(compCtx, pkt)
			case SMB2_IOCTL:
				err = tc.ioctl(compCtx, pkt)
			case SMB2_CANCEL:
				err = tc.cancel(compCtx, pkt)
			case SMB2_QUERY_DIRECTORY:
				err = tc.queryDirectory(compCtx, pkt)
			case SMB2_CHANGE_NOTIFY:
				err = tc.changeNotify(compCtx, pkt)
			case SMB2_QUERY_INFO:
				err = tc.queryInfo(compCtx, pkt)
			case SMB2_SET_INFO:
				err = tc.setInfo(compCtx, pkt)
			case SMB2_OPLOCK_BREAK:
				err = tc.oplockBreak(compCtx, pkt)
			}
		}
		if err != nil {
			log.Errorf("err: %v", err)
			return err
		}
	}
}

func (c *conn) echo(ctx *compoundContext, pkt []byte) error {
	log.Debugf("Echo")

	p := PacketCodec(pkt)
	rsp := new(EchoResponse)

	rsp.CreditRequestResponse = p.CreditRequest()
	rsp.MessageId = p.MessageId()
	rsp.Flags = 1

	return c.sendPacket(rsp, nil, nil)
}

func (c *conn) negotiate(pkt []byte) error {
	log.Debugf("Negotiate")

	if c.serverState != STATE_NEGOTIATE {
		if c.useSession() {
			c.session = nil
			c.resetSession()
			c.serverState = STATE_NEGOTIATE
		}
	}

	return c.serverCtx.negotiator.negotiate(c, pkt)
}

func (c *conn) sessionSetup(pkt []byte) error {
	log.Debugf("SessionSetup")

	if c.useSession() {
		c.session = nil
		c.resetSession()
		c.serverState = STATE_NEGOTIATE
	}

	switch c.serverState {
	case STATE_NEGOTIATE:
		return c.sessionServerSetup(pkt)
	case STATE_SESSION_SETUP, STATE_SESSION_SETUP_CHALLENGE:
		return c.sessionServerSetupChallenge(pkt)
	default:
		break
	}

	log.Debugf("Wrong connection state %d", c.serverState)
	return &InvalidRequestError{"wrong connction state"}
}

func (c *conn) logoff(pkt []byte) error {
	log.Debugf("Logoff")

	p := PacketCodec(pkt)
	rsp := new(LogoffResponse)

	rsp.CreditRequestResponse = p.CreditRequest()
	rsp.MessageId = p.MessageId()
	rsp.Flags = 1

	return c.sendPacket(rsp, nil, nil)
}

func (c *conn) treeConnect(pkt []byte) error {
	log.Debugf("TreeConnect")

	p := PacketCodec(pkt)

	res, err := accept(SMB2_TREE_CONNECT, pkt)
	if err != nil {
		return err
	}

	r := TreeConnectRequestDecoder(res)
	if r.IsInvalid() {
		return &InvalidResponseError{"broken tree connect format"}
	}

	log.Debugf("TreeConnect: %s", r.Path())

	rsp := new(TreeConnectResponse)
	rsp.CreditRequestResponse = p.CreditRequest()
	rsp.MessageId = p.MessageId()
	rsp.Flags = 1

	if strings.HasSuffix(r.Path(), "\\IPC$") {
		rsp.ShareType = SMB2_SHARE_TYPE_PIPE
		rsp.MaximalAccess = SYNCHRONIZE | WRITE_OWNER | WRITE_DAC | READ_CONTROL | DELETE |
			FILE_READ_ATTRIBUTES | FILE_EXECUTE | FILE_READ_EA | FILE_READ_DATA

		var tc *treeConn
		if t, ok := c.treeMapByName["\\IPC$"]; ok {
			rsp.TreeId = t.getTree().treeId
			tc = t.getTree()
		} else {
			shares := maps.Keys(c.serverCtx.origShares)
			ft := &ipcTree{
				treeConn: treeConn{
					session:    c.session,
					treeId:     randint32(),
					shareFlags: 0,
					path:       "\\IPC$",
				},
				shares: shares,
			}

			tc = &ft.treeConn
			c.treeMapByName["\\IPC$"] = ft
			c.treeMapById[tc.treeId] = ft
			log.Debugf("new ipc tree %d", tc.treeId)
		}

		err = c.sendPacket(rsp, tc, nil)
	} else {
		parts := strings.Split(r.Path(), "\\")
		if len(parts) < 1 {
			return &InvalidRequestError{"bad share: " + r.Path()}
		}
		path := parts[len(parts)-1]

		fs, ok := c.serverCtx.shares[strings.ToUpper(path)]
		if !ok {
			if fs, ok = c.serverCtx.shares[strings.ToUpper(path)+"$"]; !ok {
				log.Debugf("shares: %v", maps.Keys(c.serverCtx.shares))
				return &InvalidRequestError{"bad share: " + path}
			}
		}

		rsp.ShareType = SMB2_SHARE_TYPE_DISK
		rsp.MaximalAccess = SYNCHRONIZE | WRITE_OWNER | WRITE_DAC | READ_CONTROL | DELETE |
			FILE_READ_ATTRIBUTES | FILE_EXECUTE | FILE_READ_EA | FILE_READ_DATA

		var tc *treeConn
		if t, ok := c.treeMapByName[path]; ok {
			rsp.TreeId = t.getTree().treeId
			tc = t.getTree()
		} else {
			maxIOWrites, maxIoReads := DEFAULT_IOPS, DEFAULT_IOPS
			if c.serverCtx.maxIOReads > 0 {
				maxIoReads = c.serverCtx.maxIOReads
			}
			if c.serverCtx.maxIOWrites > 0 {
				maxIOWrites = c.serverCtx.maxIOWrites
			}
			ft := &fileTree{
				treeConn: treeConn{
					session:    c.session,
					treeId:     randint32(),
					shareFlags: 0,
					path:       path,
				},
				fs:         fs,
				openFiles:  make(map[uint64]bool),
				ioReadSem:  make(chan struct{}, maxIoReads),
				ioWriteSem: make(chan struct{}, maxIOWrites),
			}

			tc = &ft.treeConn
			c.treeMapByName[path] = ft
			c.treeMapById[tc.treeId] = ft
			log.Debugf("new file tree %d", ft.treeId)
		}

		err = c.sendPacket(rsp, tc, nil)
	}

	return err
}

func (c *conn) treeDisconnect(pkt []byte) error {
	log.Debugf("TreeDisconnect")

	p := PacketCodec(pkt)

	tc, ok := c.treeMapById[p.TreeId()]
	if !ok {
		log.Warnf(fmt.Sprintf("tree doesn't exist: %d", p.TreeId()))
	}

	if tc != nil {
		delete(c.treeMapByName, tc.getTree().path)
		delete(c.treeMapById, tc.getTree().treeId)
	}

	rsp := new(TreeDisconnectResponse)
	rsp.CreditRequestResponse = p.CreditRequest()
	rsp.MessageId = p.MessageId()
	rsp.Flags = 1

	return c.sendPacket(rsp, tc.getTree(), nil)
}

func (n *ServerNegotiator) negotiate(conn *conn, pkt []byte) error {
	p := PacketCodec(pkt)
	if p.IsSmb1() {
		n.SpecifiedDialect = SMB2
		rsp, _ := n.makeResponse(conn)
		return conn.sendPacket(rsp, nil, nil)
	}

	res, err := accept(SMB2_NEGOTIATE, pkt)
	if err != nil {
		return err
	}

	r := NegotiateRequestDecoder(res)
	if r.IsInvalid() {
		return &InvalidResponseError{"broken negotiate response format"}
	}

	n.SpecifiedDialect = uint16(SMB2)
	for _, d := range r.Dialects() {
		if d > n.SpecifiedDialect && d <= SMB311 {
			n.SpecifiedDialect = d
		}
	}

	if n.SpecifiedDialect == SMB2 {
		n.SpecifiedDialect = SMB210
	}

	if n.SpecifiedDialect == UnknownSMB {
		return &InvalidResponseError{"unexpected dialect returned"}
	}

	conn.requireSigning = n.RequireMessageSigning || r.SecurityMode()&SMB2_NEGOTIATE_SIGNING_REQUIRED != 0
	conn.capabilities = serverCapabilities & r.Capabilities()
	conn.dialect = n.SpecifiedDialect
	conn.maxTransactSize = serverMaxTransactSize
	conn.maxReadSize = serverMaxReadSize
	conn.maxWriteSize = serverMaxWriteSize
	conn.sequenceWindow = 1

	// conn.gssNegotiateToken = r.SecurityBuffer()
	// conn.clientGuid = n.ClientGuid
	// copy(conn.serverGuid[:], r.ServerGuid())

	n.Spnego = newSpnegoServer([]Authenticator{conn.serverCtx.authenticator})
	outputToken, _ := n.Spnego.initSecContext()

	if conn.dialect != SMB311 {
		rsp, _ := n.makeResponse(conn)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(0))
		rsp.SecurityBuffer = outputToken
		return conn.sendPacket(rsp, nil, nil)
	}

	// handle context for SMB311
	list := r.NegotiateContextList()
	for count := r.NegotiateContextCount(); count > 0; count-- {
		ctx := NegotiateContextDecoder(list)
		if ctx.IsInvalid() {
			return &InvalidResponseError{"broken negotiate context format"}
		}

		switch ctx.ContextType() {
		case SMB2_PREAUTH_INTEGRITY_CAPABILITIES:
			d := HashContextDataDecoder(ctx.Data())
			if d.IsInvalid() {
				return &InvalidResponseError{"broken hash context data format"}
			}

			algs := d.HashAlgorithms()

			if len(algs) != 1 {
				return &InvalidResponseError{"multiple hash algorithms"}
			}

			conn.preauthIntegrityHashId = algs[0]
			conn.calcPreauthHash(pkt)
		case SMB2_ENCRYPTION_CAPABILITIES:
			d := CipherContextDataDecoder(ctx.Data())
			if d.IsInvalid() {
				return &InvalidResponseError{"broken cipher context data format"}
			}

			ciphs := d.Ciphers()
			for _, ciph := range ciphs {
				if ciph == AES128CCM || ciph == AES128GCM {
					conn.cipherId = ciph
					break
				}
			}

			switch conn.cipherId {
			case AES128CCM:
			case AES128GCM:
			default:
				return &InvalidResponseError{"unknown cipher algorithm"}
			}
		default:
			// skip unsupported context
		}

		off := ctx.Next()

		if len(list) < off {
			list = nil
		} else {
			list = list[off:]
		}
	}

	rsp, _ := n.makeResponse(conn)
	PrepareResponse(&rsp.PacketHeader, pkt, uint32(0))
	rsp.SecurityBuffer = outputToken
	return conn.sendPacket(rsp, nil, nil)
}

func (n *ServerNegotiator) makeResponse(conn *conn) (*NegotiateResponse, error) {
	rsp := new(NegotiateResponse)

	if n.RequireMessageSigning {
		rsp.SecurityMode = SMB2_NEGOTIATE_SIGNING_REQUIRED
	} else {
		rsp.SecurityMode = SMB2_NEGOTIATE_SIGNING_ENABLED
	}
	rsp.Flags = 1

	rsp.Capabilities = serverCapabilities
	rsp.MaxTransactSize = serverMaxTransactSize
	rsp.MaxReadSize = serverMaxReadSize
	rsp.MaxWriteSize = serverMaxWriteSize
	rsp.SystemTime = NsecToFiletime(time.Now().UnixNano())
	rsp.ServerStartTime = &Filetime{}
	rsp.ServerGuid = conn.serverCtx.serverGuid

	if n.SpecifiedDialect != UnknownSMB {
		rsp.DialectRevision = n.SpecifiedDialect

		switch n.SpecifiedDialect {
		case SMB2:
		case SMB202:
		case SMB210:
		case SMB300:
		case SMB302:
		case SMB311:
			hc := &HashContext{
				HashAlgorithms: []uint16{conn.hashId},
				HashSalt:       make([]byte, 32),
			}
			if _, err := rand.Read(hc.HashSalt); err != nil {
				return nil, &InternalError{err.Error()}
			}

			cc := &CipherContext{
				Ciphers: []uint16{conn.cipherId},
			}

			crc := &CompressionContext{
				Compressions: []uint16{0},
				Flags:        0,
			}

			rsp.Contexts = append(rsp.Contexts, hc, cc, crc)
		default:
			return nil, &InternalError{"unsupported dialect specified"}
		}
	} else {
		rsp.DialectRevision = defaultDerverDialect

		hc := &HashContext{
			HashAlgorithms: clientHashAlgorithms,
			HashSalt:       make([]byte, 32),
		}
		if _, err := rand.Read(hc.HashSalt); err != nil {
			return nil, &InternalError{err.Error()}
		}

		cc := &CipherContext{
			Ciphers: clientCiphers,
		}

		rsp.Contexts = append(rsp.Contexts, hc, cc)
	}

	return rsp, nil
}

func randint32() uint32 {
	var b [4]byte
	rand.Read(b[:])
	return uint32(binary.LittleEndian.Uint32(b[:]))
}

func randint64() uint64 {
	var b [8]byte
	rand.Read(b[:])
	return uint64(binary.LittleEndian.Uint64(b[:]))
}

func (c *conn) calcPreauthHash(pkt []byte) {
	switch c.dialect {
	case SMB311:
		switch c.preauthIntegrityHashId {
		case SHA512:
			h := sha512.New()
			h.Write(c.preauthIntegrityHashValue[:])
			h.Write(pkt)
			h.Sum(c.preauthIntegrityHashValue[:0])
		}
	}
}

func (c *conn) sessionServerSetup(pkt []byte) error {
	log.Debugf("sessionServerSetup")

	p := PacketCodec(pkt)

	res, err := accept(SMB2_SESSION_SETUP, pkt)
	if err != nil {
		log.Debugf("sessionServerSetup: %v", err)
		return err
	}

	c.calcPreauthHash(pkt)

	r := SessionSetupRequestDecoder(res)
	if r.IsInvalid() {
		log.Debugf("sessionServerSetup invalid")
		return &InvalidRequestError{"broken session setup request format"}
	}

	/*if c.requireSigning && r.SecurityMode() != SMB2_NEGOTIATE_SIGNING_REQUIRED {
		return &InvalidRequestError{"request security mode doesn't match connection requirement"}
	}*/

	outputToken, err := c.serverCtx.negotiator.Spnego.challenge(r.SecurityBuffer())
	if err != nil {
		log.Debugf("sessionServerSetup challenge: %v", err)
		return &InvalidRequestError{err.Error()}
	}

	rsp := &SessionSetupResponse{
		SessionFlags:   0,
		SecurityBuffer: outputToken,
	}

	sessionId := randint64()

	rsp.Flags = 1
	rsp.CreditRequestResponse = p.CreditRequest()
	rsp.CreditCharge = 0 //c.CreditCharge()
	rsp.MessageId = p.MessageId()
	rsp.Status = uint32(STATUS_MORE_PROCESSING_REQUIRED)
	rsp.SessionId = sessionId

	c.serverState = STATE_SESSION_SETUP_CHALLENGE

	return c.sendPacket(rsp, nil, nil)
}

func (c *conn) sessionServerSetupChallenge(pkt []byte) error {
	log.Debugf("sessionServerSetupChallenge")

	p := PacketCodec(pkt)

	res, err := accept(SMB2_SESSION_SETUP, pkt)
	if err != nil {
		return err
	}

	r := SessionSetupRequestDecoder(res)
	if r.IsInvalid() {
		return &InvalidResponseError{"broken session setup request format"}
	}

	c.calcPreauthHash(pkt)

	outputToken, user, err := c.serverCtx.negotiator.Spnego.authenticate(r.SecurityBuffer())
	if err != nil {
		return &InvalidRequestError{err.Error()}
	}

	log.Debugf("auth user: %s", user)
	flags := uint16(0)
	if c.serverCtx.allowGuest {
		flags = SMB2_SESSION_FLAG_IS_GUEST
	}

	sessionId := p.SessionId()
	s := &session{
		conn:           c,
		treeConnTables: make(map[uint32]*treeConn),
		sessionFlags:   flags,
		sessionId:      sessionId,
	}

	rsp := &SessionSetupResponse{
		SessionFlags:   s.sessionFlags,
		SecurityBuffer: outputToken,
	}

	rsp.Flags = 1
	rsp.CreditRequestResponse = p.CreditRequest()
	rsp.CreditCharge = 0 //c.CreditCharge()
	rsp.MessageId = p.MessageId()
	rsp.SessionId = sessionId
	rsp.SecurityBuffer = outputToken

	if s.sessionFlags&(SMB2_SESSION_FLAG_IS_GUEST|SMB2_SESSION_FLAG_IS_NULL) == 0 {
		sessionKey := c.serverCtx.negotiator.Spnego.sessionKey()
		switch c.dialect {
		case SMB202, SMB210:
			s.signer = hmac.New(sha256.New, sessionKey)
			s.verifier = hmac.New(sha256.New, sessionKey)
		case SMB300, SMB302:
			signingKey := kdf(sessionKey, []byte("SMB2AESCMAC\x00"), []byte("SmbSign\x00"))
			ciph, err := aes.NewCipher(signingKey)
			if err != nil {
				return &InternalError{err.Error()}
			}
			s.signer = cmac.New(ciph)
			s.verifier = cmac.New(ciph)

			// s.applicationKey = kdf(sessionKey, []byte("SMB2APP\x00"), []byte("SmbRpc\x00"))

			encryptionKey := kdf(sessionKey, []byte("SMB2AESCCM\x00"), []byte("ServerIn \x00"))
			decryptionKey := kdf(sessionKey, []byte("SMB2AESCCM\x00"), []byte("ServerOut\x00"))

			ciph, err = aes.NewCipher(encryptionKey)
			if err != nil {
				return &InternalError{err.Error()}
			}
			s.encrypter, err = ccm.NewCCMWithNonceAndTagSizes(ciph, 11, 16)
			if err != nil {
				return &InternalError{err.Error()}
			}

			ciph, err = aes.NewCipher(decryptionKey)
			if err != nil {
				return &InternalError{err.Error()}
			}
			s.decrypter, err = ccm.NewCCMWithNonceAndTagSizes(ciph, 11, 16)
			if err != nil {
				return &InternalError{err.Error()}
			}
		case SMB311:
			s.preauthIntegrityHashValue = c.preauthIntegrityHashValue
			signingKey := kdf(sessionKey, []byte("SMBSigningKey\x00"), s.preauthIntegrityHashValue[:])
			ciph, err := aes.NewCipher(signingKey)
			if err != nil {
				return &InternalError{err.Error()}
			}
			s.signer = cmac.New(ciph)
			s.verifier = cmac.New(ciph)

			encryptionKey := kdf(sessionKey, []byte("SMBC2CCipherKey\x00"), s.preauthIntegrityHashValue[:])
			decryptionKey := kdf(sessionKey, []byte("SMBS2SCipherKey\x00"), s.preauthIntegrityHashValue[:])

			switch c.cipherId {
			case AES128CCM:
				ciph, err := aes.NewCipher(encryptionKey)
				if err != nil {
					return &InternalError{err.Error()}
				}
				s.encrypter, err = ccm.NewCCMWithNonceAndTagSizes(ciph, 11, 16)
				if err != nil {
					return &InternalError{err.Error()}
				}

				ciph, err = aes.NewCipher(decryptionKey)
				if err != nil {
					return &InternalError{err.Error()}
				}
				s.decrypter, err = ccm.NewCCMWithNonceAndTagSizes(ciph, 11, 16)
				if err != nil {
					return &InternalError{err.Error()}
				}
			case AES128GCM:
				ciph, err := aes.NewCipher(encryptionKey)
				if err != nil {
					return &InternalError{err.Error()}
				}
				s.encrypter, err = cipher.NewGCMWithNonceSize(ciph, 12)
				if err != nil {
					return &InternalError{err.Error()}
				}

				ciph, err = aes.NewCipher(decryptionKey)
				if err != nil {
					return &InternalError{err.Error()}
				}
				s.decrypter, err = cipher.NewGCMWithNonceSize(ciph, 12)
				if err != nil {
					return &InternalError{err.Error()}
				}
			}
		}
	}

	// We set session before sending packet just for setting hdr.SessionId.
	// But, we should not permit access from receiver until the session information is completed.
	c.session = s

	c.serverState = STATE_SESSION_ACTIVE
	if err = c.sendPacket(rsp, nil, nil); err == nil {
		// now, allow access from receiver
		c.enableSession()
	}

	return err
}

func (d *Server) addOpen(open *Open) {
	d.lock.Lock()
	defer d.lock.Unlock()

	d.opens[open.fileId] = open
	if open.isDurable {
		d.opensByGuid[open.createGuid] = open
	}
}

func (d *Server) getOpen(fileId uint64) *Open {
	d.lock.Lock()
	defer d.lock.Unlock()

	return d.opens[fileId]
}

func (d *Server) deleteOpen(fileId uint64) {
	d.lock.Lock()
	defer d.lock.Unlock()
	if open, ok := d.opens[fileId]; ok {
		delete(d.opens, fileId)
		if open.isDurable {
			delete(d.opensByGuid, open.createGuid)
		}
	}
}
