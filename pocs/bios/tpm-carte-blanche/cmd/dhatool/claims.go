package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

type dhaClaimsHeader struct {
	One           uint32
	Four          uint32
	QuoteSize     uint32
	SignatureSize uint32
	PCRsSize      uint32
	TCGLogSize    uint32
}

type DhaClaims struct {
	Quote     []byte
	Signature []byte
	PCRs      []byte
	TCGLog    []byte
}

type valClaimsHeader struct {
	One           uint32
	Four          uint32
	QuoteSize     uint32
	SignatureSize uint32
	Zero          uint32
}

type ValClaims struct {
	Quote     []byte
	Signature []byte
}

func read(rdr io.Reader, output []byte) error {
	if sz, err := rdr.Read(output); err != nil {
		return err
	} else if sz != len(output) {
		return fmt.Errorf("unexpected end of stream: want %d more bytes", len(output)-sz)
	}
	return nil
}

func write(wri io.Writer, input []byte) error {
	if sz, err := wri.Write(input); err != nil {
		return err
	} else if sz != len(input) {
		return fmt.Errorf("unexpected: wanted to write %d more bytes", len(input)-sz)
	}
	return nil
}

func UnmarshalClaims(claims []byte) (*DhaClaims, error) {
	rdr := bytes.NewReader(claims)
	var hdr dhaClaimsHeader
	if err := binary.Read(rdr, binary.LittleEndian, &hdr); err != nil {
		return nil, err
	}
	result := DhaClaims{
		Quote:     make([]byte, hdr.QuoteSize),
		Signature: make([]byte, hdr.SignatureSize),
		PCRs:      make([]byte, hdr.PCRsSize),
		TCGLog:    make([]byte, hdr.TCGLogSize),
	}
	if err := read(rdr, result.Quote); err != nil {
		return nil, err
	}
	if err := read(rdr, result.Signature); err != nil {
		return nil, err
	}
	if err := read(rdr, result.PCRs); err != nil {
		return nil, err
	}
	if err := read(rdr, result.TCGLog); err != nil {
		return nil, err
	}

	return &result, nil
}

func (claims *DhaClaims) Marshal() ([]byte, error) {
	hdr := dhaClaimsHeader{
		One:           1,
		Four:          4,
		QuoteSize:     uint32(len(claims.Quote)),
		SignatureSize: uint32(len(claims.Signature)),
		PCRsSize:      uint32(len(claims.PCRs)),
		TCGLogSize:    uint32(len(claims.TCGLog)),
	}
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, hdr); err != nil {
		return nil, err
	}
	if err := write(&buf, claims.Quote); err != nil {
		return nil, err
	}
	if err := write(&buf, claims.Signature); err != nil {
		return nil, err
	}
	if err := write(&buf, claims.PCRs); err != nil {
		return nil, err
	}
	if err := write(&buf, claims.TCGLog); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func UnmarshalValClaims(claims []byte) (*ValClaims, error) {
	rdr := bytes.NewReader(claims)
	var hdr valClaimsHeader
	if err := binary.Read(rdr, binary.LittleEndian, &hdr); err != nil {
		return nil, err
	}
	result := ValClaims{
		Quote:     make([]byte, hdr.QuoteSize),
		Signature: make([]byte, hdr.SignatureSize),
	}
	if err := read(rdr, result.Quote); err != nil {
		return nil, err
	}
	if err := read(rdr, result.Signature); err != nil {
		return nil, err
	}

	return &result, nil
}

func (claims *ValClaims) Marshal() ([]byte, error) {
	hdr := valClaimsHeader{
		One:           1,
		Four:          4,
		QuoteSize:     uint32(len(claims.Quote)),
		SignatureSize: uint32(len(claims.Signature)),
		Zero:          0,
	}
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, hdr); err != nil {
		return nil, err
	}
	if err := write(&buf, claims.Quote); err != nil {
		return nil, err
	}
	if err := write(&buf, claims.Signature); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// TODO: contribute a completed version of this function into go-tpm
func encodeSignature(sig *tpm2.Signature) ([]byte, error) {
	if sig.RSA == nil {
		return nil, fmt.Errorf("non-RSA signatures not supported")
	}
	return tpmutil.Pack(sig.Alg, sig.RSA)
}

func getPCRs(tpm io.ReadWriter, bank tpm2.Algorithm) ([]byte, error) {
	var result []byte
	// we aren't going for any speed records here, just read the PCRs one
	// at a time instead of N at the time (and letting the TPM decide N)
	for i := 0; i < 24; i++ {
		pcr, err := tpm2.ReadPCR(tpm, i, bank)
		if err != nil {
			return nil, err
		}
		result = append(result, pcr...)
	}
	return result, nil
}

func MakeClaims(tcgLog, aikTemplate, nonce []byte, bank tpm2.Algorithm) (*DhaClaims, error) {
	tpm, err := tpm2.OpenTPM("/dev/tpmrm0")
	if err != nil {
		return nil, err
	}
	defer tpm.Close()
	tmp, err := tpm2.DecodePublic(aikTemplate)
	if err != nil {
		return nil, err
	}
	h, _, err := tpm2.CreatePrimary(tpm, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", tmp)
	if err != nil {
		return nil, err
	}
	defer tpm2.FlushContext(tpm, h)

	sel := tpm2.PCRSelection{
		Hash: bank,
		PCRs: []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
			13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23},
	}
	attest, sig, err := tpm2.Quote(tpm, h, "", "", nonce, sel, tpm2.AlgNull)
	if err != nil {
		return nil, err
	}
	sigBytes, err := encodeSignature(sig)
	if err != nil {
		return nil, err
	}
	pcrs, err := getPCRs(tpm, bank)
	if err != nil {
		return nil, err
	}

	claims := DhaClaims{
		Quote:     attest,
		Signature: sigBytes,
		PCRs:      pcrs,
		TCGLog:    tcgLog,
	}
	return &claims, nil
}

func MakeValClaims(aikTemplate, nonce []byte, bank tpm2.Algorithm) (*ValClaims, error) {
	claims, err := MakeClaims(nil, aikTemplate, nonce, bank)
	if err != nil {
		return nil, err
	}
	return &ValClaims{
		Quote:     claims.Quote,
		Signature: claims.Signature,
	}, nil
}
