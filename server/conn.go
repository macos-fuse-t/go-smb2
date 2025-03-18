package smb2

import (
	"context"
	"fmt"
	"os"
	"sync"
	"sync/atomic"

	. "github.com/macos-fuse-t/go-smb2/internal/erref"
	. "github.com/macos-fuse-t/go-smb2/internal/smb2"
	log "github.com/sirupsen/logrus"
)

type requestResponse struct {
	msgId         uint64
	creditRequest uint16
	pkt           []byte // request packet
	compCtx       *compoundContext
	ctx           context.Context
	recv          chan []byte
	err           error
}

type outstandingRequests struct {
	m        sync.Mutex
	s        chan uint64
	requests map[uint64]*requestResponse
}

func newOutstandingRequests() *outstandingRequests {
	return &outstandingRequests{
		requests: make(map[uint64]*requestResponse, 0),
		s:        make(chan uint64),
	}
}

func (r *outstandingRequests) set(msgId uint64, rr *requestResponse) {
	r.m.Lock()

	r.requests[msgId] = rr
	r.m.Unlock()

	r.s <- msgId
}

func (r *outstandingRequests) pop(ctx context.Context) ([]byte, *compoundContext, error) {
	var msgId uint64

again:
	select {
	case <-ctx.Done():
		return nil, nil, &ContextError{Err: ctx.Err()}
	case msgId = <-r.s:
		break
	}

	r.m.Lock()
	defer r.m.Unlock()

	rr := r.requests[msgId]
	delete(r.requests, msgId)
	if rr == nil {
		// Cancel message
		goto again
	}
	return rr.pkt, rr.compCtx, nil
}

func (r *outstandingRequests) shutdown(err error) {
	r.m.Lock()
	defer r.m.Unlock()

	for _, rr := range r.requests {
		rr.err = err
		close(rr.recv)
	}
}

type conn struct {
	t transport

	session                   *session
	outstandingRequests       *outstandingRequests
	sequenceWindow            uint64
	dialect                   uint16
	maxTransactSize           uint32
	maxReadSize               uint32
	maxWriteSize              uint32
	requireSigning            bool
	capabilities              uint32
	preauthIntegrityHashId    uint16
	preauthIntegrityHashValue [64]byte
	cipherId                  uint16
	hashId                    uint16

	account *account

	rdone chan struct{}
	wdone chan struct{}
	write chan []byte
	werr  chan error

	m sync.Mutex

	err error

	// gssNegotiateToken []byte
	// serverGuid        [16]byte
	// clientGuid        [16]byte

	_useSession int32 // receiver use session?

	ctx         context.Context
	cancel      context.CancelFunc
	serverCtx   *Server
	serverState ConnState

	treeMapByName map[string]treeOps
	treeMapById   map[uint32]treeOps
}

func (conn *conn) shutdown() {
	conn.cancel()
	conn.wdone <- struct{}{}
	conn.rdone <- struct{}{}
	conn.t.Close()
}

func (conn *conn) useSession() bool {
	return atomic.LoadInt32(&conn._useSession) != 0
}

func (conn *conn) enableSession() {
	atomic.StoreInt32(&conn._useSession, 1)
}

func (conn *conn) resetSession() {
	atomic.StoreInt32(&conn._useSession, 0)
}

func (conn *conn) encodePacket(req Packet, tc *treeConn, ctx context.Context) ([]byte, error) {
	var err error
	hdr := req.Header()

	if _, ok := req.(*CancelRequest); !ok {
		creditCharge := hdr.CreditCharge

		conn.sequenceWindow += uint64(creditCharge)
		if hdr.CreditRequestResponse == 0 {
			hdr.CreditRequestResponse = creditCharge
		}

		hdr.CreditRequestResponse += conn.account.opening()
	}

	s := conn.session

	if s != nil && s.conn.useSession() {
		hdr.SessionId = s.sessionId

		if tc != nil {
			hdr.TreeId = tc.treeId
		}
	}

	pkt := make([]byte, req.Size())

	req.Encode(pkt)

	if s != nil {
		if _, ok := req.(*SessionSetupRequest); !ok {
			if s.sessionFlags&SMB2_SESSION_FLAG_ENCRYPT_DATA != 0 || (tc != nil && tc.shareFlags&SMB2_SHAREFLAG_ENCRYPT_DATA != 0) {
				pkt, err = s.encrypt(pkt)
				if err != nil {
					return nil, &InternalError{err.Error()}
				}
			} else {
				if s.sessionFlags&(SMB2_SESSION_FLAG_IS_GUEST|SMB2_SESSION_FLAG_IS_NULL) == 0 {
					pkt = s.sign(pkt)
				}
			}
		}
	}
	return pkt, nil
}

func (conn *conn) srvRecv() ([]byte, *compoundContext, error) {
	return conn.outstandingRequests.pop(conn.ctx)
}

func (conn *conn) runSender() {
	for {
		select {
		case <-conn.wdone:
			return
		case pkt := <-conn.write:
			_, err := conn.t.Write(pkt)

			conn.werr <- err
		}
	}
}

func (conn *conn) runReciever() {
	var err error

	for {
		n, e := conn.t.ReadSize()
		if e != nil {
			err = &TransportError{e}

			goto exit
		}

		pkt := make([]byte, n)

		_, e = conn.t.Read(pkt)
		if e != nil {
			err = &TransportError{e}

			goto exit
		}

		hasSession := conn.useSession()

		var isEncrypted bool

		if hasSession {
			pkt, e, isEncrypted = conn.tryDecrypt(pkt)
			if e != nil {
				log.Warning("skip:", e)

				continue
			}

			p := PacketCodec(pkt)
			if s := conn.session; s != nil {
				if p.Command() != SMB2_NEGOTIATE && p.Command() != SMB2_SESSION_SETUP &&
					s.sessionId != p.SessionId() {
					log.Warning("skip:", &InvalidResponseError{"unknown session id"})

					log.Errorf("Session!!!: msg %d, %d %d", p.Command(), s.sessionId, p.SessionId())
					continue
				}

				if tc, ok := s.treeConnTables[p.TreeId()]; ok {
					if tc.treeId != p.TreeId() {
						log.Warningln("skip:", &InvalidResponseError{"unknown tree id"})

						continue
					}
				}
			}
		}

		var next []byte
		var compCtx *compoundContext = nil

		for {
			p := PacketCodec(pkt)
			if p.IsInvalid() {
				err = &InvalidRequestError{}
				goto exit
			}

			if p.IsCompoundFirst() {
				compCtx = &compoundContext{
					treeId:    uint64(p.TreeId()),
					sessionId: p.SessionId(),
				}
			}

			if p.IsCompoundLast() {
				compCtx.lastMsgId = p.MessageId()
			}

			if off := p.NextCommand(); off != 0 {
				pkt, next = pkt[:off], pkt[off:]
			} else {
				next = nil
			}

			if hasSession {
				e = conn.tryVerify(pkt, isEncrypted)
				if e != nil {
					log.Errorf("verify error: %v", err)
				}
			}

			e = conn.tryHandle(pkt, compCtx, e)
			if e != nil {
				log.Warningln("skip:", e)
			}

			if next == nil {
				break
			}

			pkt = next
		}
	}

exit:
	select {
	case <-conn.rdone:
		err = nil
	default:
		log.Errorln("error:", err)
	}

	conn.m.Lock()
	defer conn.m.Unlock()

	conn.outstandingRequests.shutdown(err)

	conn.err = err

	close(conn.wdone)
	log.Debugf("receiver finished")
}

func accept(cmd uint16, pkt []byte) (res []byte, err error) {
	p := PacketCodec(pkt)
	if command := p.Command(); cmd != command {
		return nil, &InvalidResponseError{fmt.Sprintf("expected command: %v, got %v", cmd, command)}
	}

	// request, don't check status
	if (p.Flags() & SMB2_FLAGS_SERVER_TO_REDIR) == 0 {
		return p.Data(), nil
	}

	status := NtStatus(p.Status())

	switch status {
	case STATUS_SUCCESS:
		return p.Data(), nil
	case STATUS_OBJECT_NAME_COLLISION:
		return nil, os.ErrExist
	case STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND:
		return nil, os.ErrNotExist
	case STATUS_ACCESS_DENIED, STATUS_CANNOT_DELETE:
		return nil, os.ErrPermission
	}

	switch cmd {
	case SMB2_SESSION_SETUP:
		if status == STATUS_MORE_PROCESSING_REQUIRED {
			return p.Data(), nil
		}
	case SMB2_QUERY_INFO:
		if status == STATUS_BUFFER_OVERFLOW {
			return nil, &ResponseError{Code: uint32(status)}
		}
	case SMB2_IOCTL:
		if status == STATUS_BUFFER_OVERFLOW {
			if !IoctlResponseDecoder(p.Data()).IsInvalid() {
				return p.Data(), &ResponseError{Code: uint32(status)}
			}
		}
	case SMB2_READ:
		if status == STATUS_BUFFER_OVERFLOW {
			return nil, &ResponseError{Code: uint32(status)}
		}
	case SMB2_CHANGE_NOTIFY:
		if status == STATUS_NOTIFY_ENUM_DIR {
			return nil, &ResponseError{Code: uint32(status)}
		}
	}

	return nil, acceptError(uint32(status), p.Data())
}

func acceptError(status uint32, res []byte) error {
	r := ErrorResponseDecoder(res)
	if r.IsInvalid() {
		return &InvalidResponseError{"broken error response format"}
	}

	eData := r.ErrorData()

	if count := r.ErrorContextCount(); count != 0 {
		data := make([][]byte, count)
		for i := range data {
			ctx := ErrorContextResponseDecoder(eData)
			if ctx.IsInvalid() {
				return &InvalidResponseError{"broken error context response format"}
			}

			data[i] = ctx.ErrorContextData()

			next := ctx.Next()

			if len(eData) < next {
				return &InvalidResponseError{"broken error context response format"}
			}

			eData = eData[next:]
		}
		return &ResponseError{Code: status, data: data}
	}
	return &ResponseError{Code: status, data: [][]byte{eData}}
}

func (conn *conn) tryDecrypt(pkt []byte) ([]byte, error, bool) {
	p := PacketCodec(pkt)
	if p.IsInvalid() {
		t := TransformCodec(pkt)
		if t.IsInvalid() {
			return nil, &InvalidResponseError{"broken packet header format"}, false
		}

		if t.Flags() != Encrypted {
			return nil, &InvalidResponseError{"encrypted flag is not on"}, false
		}

		if conn.session == nil || conn.session.sessionId != t.SessionId() {
			return nil, &InvalidResponseError{"unknown session id returned"}, false
		}

		pkt, err := conn.session.decrypt(pkt)
		if err != nil {
			return nil, &InvalidResponseError{err.Error()}, false
		}

		return pkt, nil, true
	}

	return pkt, nil, false
}

func (conn *conn) tryVerify(pkt []byte, isEncrypted bool) error {
	p := PacketCodec(pkt)

	msgId := p.MessageId()

	if msgId != 0xFFFFFFFFFFFFFFFF {
		if p.Flags()&SMB2_FLAGS_SIGNED != 0 {
			if conn.session == nil || conn.session.sessionId != p.SessionId() {
				return &InvalidResponseError{"unknown session id returned"}
			} else {
				if !conn.session.verify(pkt) {
					return &InvalidResponseError{"unverified packet returned"}
				}
			}
		} else {
			if conn.requireSigning && !isEncrypted {
				if conn.session != nil {
					if conn.session.sessionFlags&(SMB2_SESSION_FLAG_IS_GUEST|SMB2_SESSION_FLAG_IS_NULL) == 0 {
						if conn.session.sessionId == p.SessionId() {
							return &InvalidResponseError{"signing required"}
						}
					}
				}
			}
		}
	}

	return nil
}

func (conn *conn) tryHandle(pkt []byte, compCtx *compoundContext, e error) error {
	p := PacketCodec(pkt)

	msgId := p.MessageId()

	rr := &requestResponse{
		msgId:         msgId,
		creditRequest: p.CreditRequest(),
		pkt:           pkt,
		ctx:           conn.ctx,
		recv:          make(chan []byte, 1),
		compCtx:       compCtx,
	}

	conn.outstandingRequests.set(msgId, rr)
	return nil
}

func (conn *conn) sendPacket(req Packet, tc *treeConn, compCtx *compoundContext) error {
	conn.m.Lock()

	if compCtx != nil {
		if !compCtx.isEmpty() {
			req.Header().Flags |= SMB2_FLAGS_RELATED_OPERATIONS
		}

		if req.Header().MessageId != compCtx.lastMsgId {
			l := Align(req.Size(), 8)
			req.Header().NextCommand = uint32(l)
		}
	}

	pkt, err := conn.encodePacket(req, tc, conn.ctx)
	if err != nil {
		conn.m.Unlock()
		return err
	}

	if compCtx != nil {
		compCtx.lastStatus = req.Header().Status

		compCtx.addResponse(pkt)
		if req.Header().MessageId != compCtx.lastMsgId {
			conn.m.Unlock()
			return nil
		}
		pkt = make([]byte, compCtx.Size())
		compCtx.Encode(pkt)
	}

	switch conn.serverState {
	case STATE_NEGOTIATE, STATE_SESSION_SETUP, STATE_SESSION_SETUP_CHALLENGE:
		conn.calcPreauthHash(pkt)
	}
	conn.m.Unlock()

	ctx := conn.ctx
	select {
	case conn.write <- pkt:
		select {
		case err = <-conn.werr:
			if err != nil {
				return &TransportError{err}
			}
		case <-ctx.Done():
			return &ContextError{Err: ctx.Err()}
		}
	case <-ctx.Done():
		return &ContextError{Err: ctx.Err()}
	}

	return nil
}
