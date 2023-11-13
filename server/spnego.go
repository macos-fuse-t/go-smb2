package smb2

import (
	"encoding/asn1"
	"fmt"
	"strings"

	"github.com/macos-fuse-t/go-smb2/internal/spnego"
)

type spnegoServer struct {
	mechs        []Authenticator
	mechTypes    []asn1.ObjectIdentifier
	selectedMech Authenticator
}

func newSpnegoServer(mechs []Authenticator) *spnegoServer {
	mechTypes := make([]asn1.ObjectIdentifier, len(mechs))
	for i, mech := range mechs {
		mechTypes[i] = mech.oid()
	}
	return &spnegoServer{
		mechs:     mechs,
		mechTypes: mechTypes,
	}
}

func (c *spnegoServer) oid() asn1.ObjectIdentifier {
	return spnego.SpnegoOid
}

func (c *spnegoServer) initSecContext() (negTokenInitBytes []byte, err error) {
	negTokenInitBytes, err = spnego.EncodeNegTokenInit(c.mechTypes, nil)
	if err != nil {
		return nil, err
	}
	return negTokenInitBytes, nil
}

func (c *spnegoServer) challenge(negTokenReqBytes []byte) (negTokenChallengBytes []byte, err error) {
	if strings.HasPrefix(string(negTokenReqBytes), "NTLMSSP") {
		for i, mechType := range c.mechTypes {
			if mechType.Equal(spnego.NlmpOid) {
				c.selectedMech = c.mechs[i]
				break
			}
		}
		if c.selectedMech == nil {
			return nil, fmt.Errorf("failed to find ntlmspp authenticator")
		}
		return c.selectedMech.challenge(negTokenReqBytes)
	}

	negTokenResp, err := spnego.DecodeNegTokenInit(negTokenReqBytes)
	if err != nil {
		return nil, err
	}

	for i, mechType := range c.mechTypes {
		for _, mech := range negTokenResp.MechTypes {
			if mechType.Equal(mech) {
				c.selectedMech = c.mechs[i]
				break
			}
		}
	}
	if c.selectedMech == nil {
		return nil, fmt.Errorf("incompatible mech type in tokenInit")
	}

	responseToken, err := c.selectedMech.challenge(negTokenResp.MechToken)
	if err != nil {
		return nil, err
	}

	negTokenChallengBytes, err = spnego.EncodeNegTokenResp(1, c.selectedMech.oid(), responseToken, nil)
	if err != nil {
		return nil, err
	}

	return negTokenChallengBytes, nil
}

func (c *spnegoServer) authenticate(negTokenRespBytes []byte) (negTokenAuthBytes []byte, user string, err error) {
	if strings.HasPrefix(string(negTokenRespBytes), "NTLMSSP") {
		if user, err = c.selectedMech.authenticate(negTokenRespBytes); err != nil {
			return nil, "", err
		}
		return nil, user, err
	}

	negTokenResp, err := spnego.DecodeNegTokenResp(negTokenRespBytes)
	if err != nil {
		return nil, "", err
	}

	for i, mechType := range c.mechTypes {
		if mechType.Equal(negTokenResp.SupportedMech) {
			c.selectedMech = c.mechs[i]
			break
		}
	}

	if user, err = c.selectedMech.authenticate(negTokenResp.ResponseToken); err != nil {
		t, _ := spnego.EncodeNegTokenRejected()
		return t, "", err
	}

	t, err := spnego.EncodeNegTokenAccepted()
	return t, user, err
}

func (c *spnegoServer) sum(bs []byte) []byte {
	return c.selectedMech.sum(bs)
}

func (c *spnegoServer) sessionKey() []byte {
	return c.selectedMech.sessionKey()
}
