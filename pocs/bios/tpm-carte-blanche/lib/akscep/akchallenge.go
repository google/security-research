package akscep

import (
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"fmt"

	"github.com/google/go-tpm/tpmutil"
)

type GetChallengeReply struct {
	EKChallenge struct {
		OID      asn1.ObjectIdentifier
		Contents struct {
			Challenge []byte
		} `asn1:"set"`
	}
	ServerContext asn1.RawValue
}

type AttestationKeyChallenge struct {
	CredentialBlob    []byte
	Secret            []byte
	ServerContextBlob asn1.RawValue
}

type AttestationKeyChallengeHdr struct {
	Magic         uint32
	Version       uint32
	Platform      uint32
	HeaderSize    uint32
	ChallengeSize uint32
	Reserved      uint32
}

func ParseAttestationKeyChallenge(data []byte) (*AttestationKeyChallenge, error) {
	var reply GetChallengeReply
	if rest, err := asn1.UnmarshalWithParams(data, &reply, "set"); err != nil {
		return nil, fmt.Errorf("parsing inner challenge: %w", err)
	} else if len(rest) > 0 {
		return nil, fmt.Errorf("unexpected data at the end of GetChallenge reply: %v", rest)
	}
	rdr := bytes.NewReader(reply.EKChallenge.Contents.Challenge)
	var hdr AttestationKeyChallengeHdr
	if err := binary.Read(rdr, binary.LittleEndian, &hdr); err != nil {
		return nil, err
	}
	challenge := make([]byte, hdr.ChallengeSize)
	if hdr.ChallengeSize > 0 {
		if n, err := rdr.Read(challenge); err != nil {
			return nil, err
		} else if n != len(challenge) {
			return nil, fmt.Errorf("unexpected end of statement reading %d bytes into challenge", n)
		}
	}
	var credBlob, secret tpmutil.U16Bytes
	_, err := tpmutil.Unpack(challenge, &credBlob, &secret)
	if err != nil {
		return nil, err
	}
	return &AttestationKeyChallenge{
		CredentialBlob:    credBlob,
		Secret:            secret,
		ServerContextBlob: reply.ServerContext,
	}, nil
}
