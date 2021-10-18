package akscep

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io/ioutil"

	"github.com/chrisfenner/pkcs7"
)

type GetChallengeReq struct {
	Envelope *pkcs7.PKCS7
	Contents *pkcs7.PKCS7
}

func (req GetChallengeReq) DecryptCSR(cert, scepCert *x509.Certificate, key crypto.PrivateKey) (*AttestationKeyCSR, error) {
	data, err := req.Contents.Decrypt(cert, key)
	if err != nil {
		return nil, fmt.Errorf("could not decrypt CSR: %w", err)
	}
	return ParseAttestationKeyCSR(data, scepCert)
}

type GetChallengeRsp struct {
	Envelope *pkcs7.PKCS7
	Contents *pkcs7.PKCS7
}

func (rsp GetChallengeRsp) DecryptChallenge(cert *x509.Certificate, key crypto.PrivateKey) (*AttestationKeyChallenge, error) {
	data, err := rsp.Contents.Decrypt(cert, key)
	if err != nil {
		return nil, fmt.Errorf("could not decrypt CSR: %w", err)
	}
	return ParseAttestationKeyChallenge(data)
}

type GetCertReq struct {
	Envelope *pkcs7.PKCS7
	Contents *pkcs7.PKCS7
}

type GetCertRsp struct {
	Envelope *pkcs7.PKCS7
	Contents *pkcs7.PKCS7
}

type GetChallengeReqBuilder struct {
	Claims        []byte
	ExtraEKCerts  []*x509.Certificate
	SignerCert    *x509.Certificate
	SignerKey     crypto.PrivateKey
	RecipientCert *x509.Certificate
}

func (b GetChallengeReqBuilder) Build() ([]byte, error) {
	Contents, err := encryptData(b.Claims, b.RecipientCert)
	if err != nil {
		return nil, err
	}
	env, err := pkcs7.NewSignedData(Contents)
	if err != nil {
		return nil, err
	}
	cfg := pkcs7.SignerInfoConfig{
		ExtraSignedAttributes: []pkcs7.Attribute{
			{
				Type:  asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 2},
				Value: asn1.RawValue{FullBytes: []byte{0x13, 0x02, 0x31, 0x39}},
			},
			{
				Type:  asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 5},
				Value: asn1.RawValue{FullBytes: []byte{0x04, 0x10, 0x9b, 0x99, 0x68, 0x48, 0xbc, 0x4d, 0x96, 0xca, 0x3f, 0x84, 0xd8, 0xe9, 0xf6, 0x62, 0x5f, 0xc4}},
			},
			{
				Type:  asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 7},
				Value: asn1.RawValue{FullBytes: []byte{0x13, 0x28, 0x39, 0x39, 0x61, 0x36, 0x34, 0x66, 0x31, 0x34, 0x64, 0x36, 0x38, 0x63, 0x32, 0x63, 0x61, 0x62, 0x62, 0x39, 0x35, 0x35, 0x35, 0x34, 0x32, 0x37, 0x39, 0x66, 0x33, 0x32, 0x65, 0x63, 0x37, 0x37, 0x61, 0x32, 0x30, 0x39, 0x31, 0x38, 0x66, 0x61}},
			},
		},
	}
	env.SetEncryptionAlgorithm(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1} /* rsaEncryption */)
	env.SetDigestAlgorithm(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1} /* sha256 */)
	if err := env.AddSigner(b.SignerCert, b.SignerKey, cfg); err != nil {
		return nil, err
	}
	for _, cert := range b.ExtraEKCerts {
		env.AddCertificate(cert)
	}
	return env.Finish()
}

type GetCertReqBuilder struct {
	Challenge          *AttestationKeyChallenge
	DecryptedChallenge []byte
	SignerCert         *x509.Certificate
	SignerKey          crypto.PrivateKey
	RecipientCert      *x509.Certificate
}

type GetCertInner struct {
	EKChallenge struct {
		OID        asn1.ObjectIdentifier
		InnerPKCS7 struct {
			EncryptedChallenge asn1.RawValue
		} `asn1:"set"`
	}
	ServerContext asn1.RawValue
}

func (b GetCertReqBuilder) Build() ([]byte, error) {
	reply := GetCertInner{
		ServerContext: b.Challenge.ServerContextBlob,
	}
	// Yes, we give back the challenge within two layers of RSA encryption, inside TLS
	encChallenge, err := encryptData(b.DecryptedChallenge, b.RecipientCert)
	if err != nil {
		return nil, err
	}
	reply.EKChallenge.OID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 21, 35}
	reply.EKChallenge.InnerPKCS7.EncryptedChallenge.FullBytes = encChallenge
	claims, err := asn1.MarshalWithParams(reply, "set")
	if err != nil {
		return nil, err
	}
	ioutil.WriteFile("innerChallengePresentation", claims, 0644)
	contents, err := encryptData(claims, b.RecipientCert)
	if err != nil {
		return nil, err
	}
	env, err := pkcs7.NewSignedData(contents)
	if err != nil {
		return nil, err
	}
	cfg := pkcs7.SignerInfoConfig{
		ExtraSignedAttributes: []pkcs7.Attribute{
			{
				Type:  asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 2},
				Value: asn1.RawValue{FullBytes: []byte{0x13, 0x02, 0x34, 0x31}},
			},
			{
				Type:  asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 5},
				Value: asn1.RawValue{FullBytes: []byte{0x04, 0x10, 0x9b, 0x99, 0x68, 0x48, 0xbc, 0x4d, 0x96, 0xca, 0x3f, 0x84, 0xd8, 0xe9, 0xf6, 0x62, 0x5f, 0xc4}},
			},
			{
				Type:  asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 7},
				Value: asn1.RawValue{FullBytes: []byte{0x13, 0x28, 0x39, 0x39, 0x61, 0x36, 0x34, 0x66, 0x31, 0x34, 0x64, 0x36, 0x38, 0x63, 0x32, 0x63, 0x61, 0x62, 0x62, 0x39, 0x35, 0x35, 0x35, 0x34, 0x32, 0x37, 0x39, 0x66, 0x33, 0x32, 0x65, 0x63, 0x37, 0x37, 0x61, 0x32, 0x30, 0x39, 0x31, 0x38, 0x66, 0x61}},
			},
		},
	}
	env.SetEncryptionAlgorithm(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1} /* rsaEncryption */)
	env.SetDigestAlgorithm(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1} /* sha256 */)
	if err := env.AddSigner(b.SignerCert, b.SignerKey, cfg); err != nil {
		return nil, err
	}
	result, err := env.Finish()
	if err != nil {
		return nil, err
	}
	ioutil.WriteFile("challengeReq", result, 0644)
	return result, nil
}

func ParseGetChallengeReq(data []byte) (*GetChallengeReq, error) {
	env, err := pkcs7.Parse(data)
	if err != nil {
		return nil, err
	}
	if err := validateEnvelope(env); err != nil {
		return nil, err
	}
	if err := env.Verify(); err != nil {
		return nil, err
	}
	if err := ValidateClientCert(env.Certificates[0]); err != nil {
		return nil, err
	}
	conts, err := pkcs7.Parse(env.Content)
	if err != nil {
		return nil, err
	}
	if err := validateClientContents(conts); err != nil {
		return nil, err
	}

	return &GetChallengeReq{
		Envelope: env,
		Contents: conts,
	}, nil
}

func (req *GetChallengeReq) SCEPCert() *x509.Certificate {
	return req.Envelope.Certificates[0]
}

type GetChallengeRspBuilder struct {
	Challenge     []byte
	SenderNonce   []byte
	TransactionID string
	SignerCert    *x509.Certificate
	SignerKey     crypto.PrivateKey
	RecipientCert *x509.Certificate
}

func (b GetChallengeRspBuilder) Build() ([]byte, error) {
	Contents, err := encryptData(b.Challenge, b.RecipientCert)
	if err != nil {
		return nil, err
	}
	env, err := pkcs7.NewSignedData(Contents)
	if err != nil {
		return nil, err
	}

	var attrs []pkcs7.Attribute

	attrs = append(attrs, pkcs7.Attribute{
		Type:  asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 2},
		Value: "3",
	})

	attrs = append(attrs, pkcs7.Attribute{
		Type:  asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 3},
		Value: "11",
	})

	attrs = append(attrs, pkcs7.Attribute{
		Type:  asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 5},
		Value: b.SenderNonce,
	})

	attrs = append(attrs, pkcs7.Attribute{
		Type:  asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 6},
		Value: b.SenderNonce,
	})

	attrs = append(attrs, pkcs7.Attribute{
		Type:  asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 7},
		Value: b.TransactionID,
	})

	cfg := pkcs7.SignerInfoConfig{
		ExtraSignedAttributes: attrs,
	}
	env.SetEncryptionAlgorithm(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11} /* sha256WithRSAEncryption */)
	if err := env.AddSigner(b.SignerCert, b.SignerKey, cfg); err != nil {
		return nil, err
	}
	return env.Finish()
}

func ParseGetChallengeRsp(data []byte) (*GetChallengeRsp, error) {
	env, err := pkcs7.Parse(data)
	if err != nil {
		return nil, err
	}
	if err := validateEnvelope(env); err != nil {
		return nil, err
	}
	if err := env.Verify(); err != nil {
		return nil, err
	}
	if err := ValidateRASigningCert(env.Certificates[0]); err != nil {
		return nil, err
	}
	conts, err := pkcs7.Parse(env.Content)
	if err != nil {
		return nil, err
	}
	if err := validateServerContents(conts); err != nil {
		return nil, err
	}
	return &GetChallengeRsp{
		Envelope: env,
		Contents: conts,
	}, nil
}

func ParseGetCertReq(data []byte) (*GetCertReq, error) {
	env, err := pkcs7.Parse(data)
	if err != nil {
		return nil, err
	}
	if err := validateEnvelope(env); err != nil {
		return nil, err
	}
	if err := env.Verify(); err != nil {
		return nil, err
	}
	if err := ValidateClientCert(env.Certificates[0]); err != nil {
		return nil, err
	}
	conts, err := pkcs7.Parse(env.Content)
	if err != nil {
		return nil, err
	}
	if err := validateClientContents(conts); err != nil {
		return nil, err
	}
	return &GetCertReq{
		Envelope: env,
		Contents: conts,
	}, nil
}

type GetCertRspBuilder struct {
	Cert          []byte
	SignerCert    *x509.Certificate
	SignerKey     crypto.PrivateKey
	RecipientCert *x509.Certificate
}

func (b GetCertRspBuilder) Build() ([]byte, error) {
	Contents, err := encryptData(b.Cert, b.RecipientCert)
	if err != nil {
		return nil, err
	}
	env, err := pkcs7.NewSignedData(Contents)
	if err != nil {
		return nil, err
	}
	cfg := pkcs7.SignerInfoConfig{}
	env.SetEncryptionAlgorithm(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11} /* sha256WithRSAEncryption */)
	if err := env.AddSigner(b.SignerCert, b.SignerKey, cfg); err != nil {
		return nil, err
	}
	return env.Finish()
}

func ParseGetCertRsp(data []byte) (*GetCertRsp, error) {
	env, err := pkcs7.Parse(data)
	if err != nil {
		return nil, err
	}
	if err := validateEnvelope(env); err != nil {
		return nil, err
	}
	if err := env.Verify(); err != nil {
		return nil, err
	}
	if err := ValidateRASigningCert(env.Certificates[0]); err != nil {
		return nil, err
	}
	conts, err := pkcs7.Parse(env.Content)
	if err != nil {
		return nil, err
	}
	if err := validateServerContents(conts); err != nil {
		return nil, err
	}
	return &GetCertRsp{
		Envelope: env,
		Contents: conts,
	}, nil
}

func (rsp GetCertRsp) DecryptCert(cert *x509.Certificate, key crypto.PrivateKey) ([]byte, error) {
	data, err := rsp.Contents.Decrypt(cert, key)
	if err != nil {
		return nil, fmt.Errorf("could not decrypt cert: %w", err)
	}
	return data, nil
}

func validateEnvelope(msg *pkcs7.PKCS7) error {
	if len(msg.Content) == 0 {
		return fmt.Errorf("no content")
	}
	if len(msg.CRLs) != 0 {
		return fmt.Errorf("unexpected CRL")
	}
	if len(msg.Certificates) == 0 {
		return fmt.Errorf("no certs")
	}
	if err := validateCertificate(msg.Certificates[0]); err != nil {
		return fmt.Errorf("first cert: %w", err)
	}
	if len(msg.Signers) != 1 {
		return fmt.Errorf("unexpected amount of signers (%d)", len(msg.Signers))
	}
	return nil
}

func validateClientContents(data *pkcs7.PKCS7) error {
	if err := validateContents(data); err != nil {
		return err
	}

	return nil
}

func validateServerContents(data *pkcs7.PKCS7) error {
	if err := validateContents(data); err != nil {
		return err
	}

	return nil
}

func validateContents(data *pkcs7.PKCS7) error {
	return nil
}

func encryptData(data []byte, recipient *x509.Certificate) ([]byte, error) {
	pkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmAES128CBC
	return pkcs7.Encrypt(data, []*x509.Certificate{recipient})
}
