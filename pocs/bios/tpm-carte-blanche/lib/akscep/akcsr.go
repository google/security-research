package akscep

import (
	"bytes"
	"crypto"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"unicode/utf16"

	"github.com/chrisfenner/pkcs7"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

var (
	osVersion            = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 13, 2, 3}
	scepSignerHash       = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 21, 42}
	clientInfo           = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 21, 20}
	kspName              = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 21, 25}
	cspInfo              = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 13, 2, 2}
	requestedExtensions  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}
	attestationStatement = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 21, 24}
	ekInfo               = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 21, 23}
	subjectAltName       = asn1.ObjectIdentifier{2, 5, 29, 17}
	keyAffinity          = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 21, 41}
	subjectKeyID         = asn1.ObjectIdentifier{2, 5, 29, 14}
	tpmManufacturer      = asn1.ObjectIdentifier{2, 23, 133, 2, 1}
	tpmModel             = asn1.ObjectIdentifier{2, 23, 133, 2, 2}
	tpmVersion           = asn1.ObjectIdentifier{2, 23, 133, 2, 3}
	idSHA256             = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
)

type setValue struct {
	Value asn1.RawValue
}

type taggedSetValue struct {
	OID   asn1.ObjectIdentifier
	Value setValue `asn1:"set"`
}

// Modified, customized x509 package structure specific to Windows AK CSRs
// This structure is extremely brittle, as it is for emulating the specific
// attributes in the specific order that Windows creates them, to avoid
// compatibility issues.
type akCSR struct {
	Raw        asn1.RawContent
	Version    int
	Subject    asn1.RawValue
	PublicKey  asn1.RawValue
	Attributes struct {
		OSVersion struct {
			OID   asn1.ObjectIdentifier
			Value struct {
				Version string `asn1:"ia5"`
			} `asn1:"set"`
		}
		SCEPSignerHash struct {
			OID   asn1.ObjectIdentifier
			Value struct {
				Hash []byte
			} `asn1:"set"`
		}
		ClientInfo struct {
			OID   asn1.ObjectIdentifier
			Value struct {
				ClientInfo struct {
					ClientID    int
					MachineName string `asn1:"utf8"`
					UserName    string `asn1:"utf8"`
					ProcessName string `asn1:"utf8"`
				}
			} `asn1:"set"`
		}
		KSPName struct {
			OID   asn1.ObjectIdentifier
			Value struct {
				Name asn1.RawValue // asn1 package doesn't marshal BMP
			} `asn1:"set"`
		}
		CSPInfo struct {
			OID   asn1.ObjectIdentifier
			Value struct {
				CSPInfo struct {
					Version   int
					Name      asn1.RawValue // asn1 package doesn't marshal BMP
					Signature asn1.BitString
				}
			} `asn1:"set"`
		}
		Extensions struct {
			OID   asn1.ObjectIdentifier
			Value struct {
				Extensions struct {
					SubjectAlternativeName pkix.Extension
					KeyAffinity            pkix.Extension
					SubjectKeyID           pkix.Extension
				}
			} `asn1:"set"`
		}
		AttestationStatement struct {
			OID   asn1.ObjectIdentifier
			Value struct {
				AttestationStatement []byte
			} `asn1:"set"`
		}
		EKInfo struct {
			OID   asn1.ObjectIdentifier
			Value struct {
				// A PKCS7, to be parsed with pkcs7
				EKInfo asn1.RawValue
			} `asn1:"set"`
		}
	} `asn1:"tag:0"`
}

// Modified, customized x509 package structure specific to Windows AK CSRs
type certificateRequest struct {
	Raw                asn1.RawContent
	AKCSR              akCSR
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

type TPMInfo struct {
	Manufacturer []byte
	Model        string
	Version      []byte
}

// This ASN.1-encoded structure is wrapped in an OCTET STRING in both the EK cert and AK request.
// I'm not sure how to tell asn1 about this wrapping, or I'd inline this in akCSR.
// The real question is, does this data have enough layers of nesting?
type tpmSan struct {
	Attributes struct {
		Value struct {
			Manufacturer struct {
				Value struct {
					OID    asn1.ObjectIdentifier
					String string `asn1:"utf8"`
				}
			} `asn1:"set"`
			Model struct {
				Value struct {
					OID    asn1.ObjectIdentifier
					String string `asn1:"utf8"`
				}
			} `asn1:"set"`
			Version struct {
				Value struct {
					OID    asn1.ObjectIdentifier
					String string `asn1:"utf8"`
				}
			} `asn1:"set"`
		}
	} `asn1:"tag:4"`
}

func parseTPMInfo(data []byte) (*TPMInfo, error) {
	var san tpmSan
	if rest, err := asn1.Unmarshal(data, &san); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, fmt.Errorf("extra data in SAN: %v", rest)
	}
	if !san.Attributes.Value.Manufacturer.Value.OID.Equal(tpmManufacturer) {
		return nil, fmt.Errorf("wrong OID: want %v got %v", tpmManufacturer, san.Attributes.Value.Manufacturer.Value.OID)
	}
	if !san.Attributes.Value.Model.Value.OID.Equal(tpmModel) {
		return nil, fmt.Errorf("wrong OID: want %v got %v", tpmModel, san.Attributes.Value.Model.Value.OID)
	}
	if !san.Attributes.Value.Version.Value.OID.Equal(tpmVersion) {
		return nil, fmt.Errorf("wrong OID: want %v got %v", tpmVersion, san.Attributes.Value.Version.Value.OID)
	}
	mfrRaw := san.Attributes.Value.Manufacturer.Value.String
	model := san.Attributes.Value.Model.Value.String
	versionRaw := san.Attributes.Value.Version.Value.String
	if !strings.HasPrefix(mfrRaw, "id:") {
		return nil, fmt.Errorf("TPM manufacturer ID does not begin with 'id:': %s", mfrRaw)
	}
	if !strings.HasPrefix(versionRaw, "id:") {
		return nil, fmt.Errorf("TPM version does not begin with 'id:': %s", versionRaw)
	}
	mfr, err := hex.DecodeString(mfrRaw[3:])
	if err != nil {
		return nil, fmt.Errorf("manufacturer ID was not a hex string: %s", mfrRaw[3:])
	}
	version, err := hex.DecodeString(versionRaw[3:])
	if err != nil {
		return nil, fmt.Errorf("version was not a hex string: %s", versionRaw[3:])
	}
	return &TPMInfo{
		Manufacturer: mfr,
		Model:        model,
		Version:      version,
	}, nil
}

func ekTPMInfo(ek *x509.Certificate) (*TPMInfo, error) {
	for _, ext := range ek.Extensions {
		if ext.Id.Equal(subjectAltName) {
			return parseTPMInfo(ext.Value)
		}
	}
	return nil, fmt.Errorf("could not find subject alternate name on EK cert")
}

func generateTPMInfo(info *TPMInfo) ([]byte, error) {
	hexMfr := "id:" + hex.EncodeToString(info.Manufacturer)
	hexVersion := "id:" + hex.EncodeToString(info.Version)
	var san tpmSan
	san.Attributes.Value.Manufacturer.Value.OID = tpmManufacturer
	san.Attributes.Value.Manufacturer.Value.String = hexMfr
	san.Attributes.Value.Model.Value.OID = tpmModel
	san.Attributes.Value.Model.Value.String = info.Model
	san.Attributes.Value.Version.Value.OID = tpmVersion
	san.Attributes.Value.Version.Value.String = hexVersion
	return asn1.Marshal(san)
}

type AttestationKeyCSR struct {
	SubjectPublicKey crypto.PublicKey
	SubjectKeyID     []byte
	OSVersion        string
	SCEPSignerHash   []byte
	MachineName      string
	UserName         string
	AttestationStatement
	EncryptedEKCerts []byte
	TPMInfo
}

func encodeBMPString(str string) []byte {
	utf := utf16.Encode([]rune(str))
	result := make([]byte, 0, len(utf)*2)
	for _, c := range utf {
		result = append(result, byte(c>>8), byte(c))
	}
	return result
}

func ParseAttestationKeyCSR(data []byte, scepCert *x509.Certificate) (*AttestationKeyCSR, error) {
	var req certificateRequest
	rest, err := asn1.Unmarshal(data, &req)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("extra trailing data: %v", rest)
	}
	pub, err := x509.ParsePKIXPublicKey(req.AKCSR.PublicKey.FullBytes)
	if err != nil {
		return nil, err
	}
	if err := validateAKCSR(&req.AKCSR, scepCert); err != nil {
		return nil, err
	}
	tpmInfo, err := parseTPMInfo(req.AKCSR.Attributes.Extensions.Value.Extensions.SubjectAlternativeName.Value)
	if err != nil {
		return nil, err
	}
	stmt, err := parseAttestationStatement(req.AKCSR.Attributes.AttestationStatement.Value.AttestationStatement)
	if err != nil {
		return nil, err
	}
	return &AttestationKeyCSR{
		SubjectPublicKey:     pub,
		SubjectKeyID:         req.AKCSR.Attributes.Extensions.Value.Extensions.SubjectKeyID.Value,
		OSVersion:            req.AKCSR.Attributes.OSVersion.Value.Version,
		SCEPSignerHash:       req.AKCSR.Attributes.SCEPSignerHash.Value.Hash,
		MachineName:          req.AKCSR.Attributes.ClientInfo.Value.ClientInfo.MachineName,
		UserName:             req.AKCSR.Attributes.ClientInfo.Value.ClientInfo.UserName,
		AttestationStatement: *stmt,
		EncryptedEKCerts:     req.AKCSR.Attributes.EKInfo.Value.EKInfo.FullBytes,
		TPMInfo:              *tpmInfo,
	}, nil
}

func GenerateAttestationKeyCSR(in *AttestationKeyCSR) ([]byte, error) {
	pub, err := x509.MarshalPKIXPublicKey(in.SubjectPublicKey)
	if err != nil {
		return nil, err
	}
	san, err := generateTPMInfo(&in.TPMInfo)
	if err != nil {
		return nil, err
	}
	stmt, err := GenerateAttestationStatement(&in.AttestationStatement)
	if err != nil {
		return nil, err
	}
	var csr akCSR
	csr.Subject.FullBytes = []byte{0x30, 0x00} // empty SEQUENCE as opposed to EOC
	csr.PublicKey.FullBytes = pub
	attrs := &csr.Attributes
	attrs.OSVersion.OID = osVersion
	attrs.OSVersion.Value.Version = in.OSVersion
	attrs.SCEPSignerHash.OID = scepSignerHash
	attrs.SCEPSignerHash.Value.Hash = in.SCEPSignerHash
	attrs.ClientInfo.OID = clientInfo
	attrs.ClientInfo.Value.ClientInfo.ClientID = 5
	attrs.ClientInfo.Value.ClientInfo.MachineName = in.MachineName
	attrs.ClientInfo.Value.ClientInfo.UserName = in.UserName
	attrs.ClientInfo.Value.ClientInfo.ProcessName = "taskhostw.exe"
	attrs.KSPName.OID = kspName
	attrs.KSPName.Value.Name.Tag = 30
	attrs.KSPName.Value.Name.Bytes = encodeBMPString("Microsoft Platform Crypto Provider")
	attrs.CSPInfo.OID = cspInfo
	attrs.CSPInfo.Value.CSPInfo.Name.Tag = 30
	attrs.CSPInfo.Value.CSPInfo.Name.Bytes = encodeBMPString("Microsoft Platform Crypto Provider")
	attrs.Extensions.OID = requestedExtensions
	attrs.Extensions.Value.Extensions.SubjectAlternativeName.Id = subjectAltName
	attrs.Extensions.Value.Extensions.SubjectAlternativeName.Value = san
	attrs.Extensions.Value.Extensions.KeyAffinity.Id = keyAffinity
	attrs.Extensions.Value.Extensions.KeyAffinity.Value = []byte{0x05, 0x00} // NULL not absent
	attrs.Extensions.Value.Extensions.SubjectKeyID.Id = subjectKeyID
	attrs.Extensions.Value.Extensions.SubjectKeyID.Value = append([]byte{0x04, 0x14}, in.SubjectKeyID...)
	attrs.AttestationStatement.OID = attestationStatement
	attrs.AttestationStatement.Value.AttestationStatement = stmt
	attrs.EKInfo.OID = ekInfo
	attrs.EKInfo.Value.EKInfo.FullBytes = in.EncryptedEKCerts
	csrBytes, err := asn1.Marshal(csr)
	if err != nil {
		return nil, fmt.Errorf("can't serialize CSR: %w", err)
	}
	hash := sha256.Sum256(csrBytes)

	var req certificateRequest
	req.AKCSR = csr
	req.SignatureAlgorithm.Algorithm = idSHA256
	req.SignatureAlgorithm.Parameters.FullBytes = []byte{0x05, 0x00} // NULL as opposed to absent
	req.SignatureValue.Bytes = hash[:]

	result, err := asn1.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("can't serialize certificate request: %w", err)
	}
	return result, nil
}

type ekInfoEnvelope struct {
	EKPub  asn1.RawValue
	EKCert asn1.RawValue
}

func ParseEKInfo(data []byte) (*x509.Certificate, error) {
	var env ekInfoEnvelope
	if rest, err := asn1.Unmarshal(data, &env); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, fmt.Errorf("extra data at end of EK certs packet")
	}
	return x509.ParseCertificate(env.EKCert.FullBytes)
}

func GenerateEKInfo(ek *x509.Certificate) ([]byte, error) {
	pub, err := x509.MarshalPKIXPublicKey(ek.PublicKey)
	if err != nil {
		return nil, err
	}
	var ekInfo ekInfoEnvelope
	ekInfo.EKPub.FullBytes = pub
	ekInfo.EKCert.FullBytes = ek.Raw
	return asn1.Marshal(ekInfo)
}

func AdditionalEKCerts(ek *x509.Certificate) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	currentCert := ek
	for {
		urls := currentCert.IssuingCertificateURL
		if len(urls) == 0 {
			break
		}
		url := urls[0]
		// TODO: try all the URLs if there are more than one?
		fmt.Printf("Fetching %s...", url)
		rsp, err := http.Get(url)
		fmt.Printf("done\n")
		if err != nil {
			return nil, err
		}
		defer rsp.Body.Close()
		data, err := ioutil.ReadAll(rsp.Body)
		if err != nil {
			return nil, err
		}
		currentCert, err = x509.ParseCertificate(data)
		if err != nil {
			return nil, err
		}
		// Prepend to mimic Windows
		certs = append([]*x509.Certificate{currentCert}, certs...)
	}
	return certs, nil
}

func EncryptEKInfo(ek, ra *x509.Certificate) ([]byte, error) {
	info, err := GenerateEKInfo(ek)
	if err != nil {
		return nil, err
	}
	pkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmAES128CBC
	return pkcs7.Encrypt(info, []*x509.Certificate{ra})
}

type AttestationStatementHdr struct {
	Magic              uint32
	Version            uint32
	Platform           uint32
	HeaderSize         uint32
	IDBindingSize      uint32
	KeyAttestationSize uint32
	AIKOpaqueSize      uint32
}

type AttestationStatement struct {
	Header AttestationStatementHdr
	IDBinding
	KeyAttestation []byte
	AIKOpaque      []byte
}

type IDBinding struct {
	Public tpm2.Public
	CreationAttestation
}

type CreationAttestation struct {
	CreationData tpm2.CreationData
	Attest       tpm2.AttestationData
	// This could be a tpm2.Signature, if an Encode() function were available for that type.
	// TODO: add that, and upstream it.
	SignatureAlg tpm2.Algorithm
	Signature    tpm2.SignatureRSA
}

func parseIDBinding(data []byte) (*IDBinding, error) {
	var public2B, creation2B, attest2B tpmutil.U16Bytes
	var result IDBinding
	n, err := tpmutil.Unpack(data, &public2B, &creation2B, &attest2B)
	if err != nil {
		return nil, err
	}

	pub, err := tpm2.DecodePublic(public2B)
	if err != nil {
		return nil, err
	}
	cd, err := tpm2.DecodeCreationData(creation2B)
	if err != nil {
		return nil, err
	}
	attest, err := tpm2.DecodeAttestationData(attest2B)
	if err != nil {
		return nil, err
	}
	sig, err := tpm2.DecodeSignature(bytes.NewBuffer(data[n:]))
	if err != nil {
		return nil, err
	}
	result.Public = pub
	result.CreationAttestation.CreationData = *cd
	result.CreationAttestation.Attest = *attest
	result.CreationAttestation.SignatureAlg = sig.Alg
	result.CreationAttestation.Signature = *sig.RSA

	return &result, nil
}

func generateIDBinding(id *IDBinding) ([]byte, error) {
	public, err := id.Public.Encode()
	if err != nil {
		return nil, err
	}
	creation, err := id.CreationAttestation.CreationData.EncodeCreationData()
	if err != nil {
		return nil, err
	}
	attest, err := id.CreationAttestation.Attest.Encode()
	if err != nil {
		return nil, err
	}
	return tpmutil.Pack(
		tpmutil.U16Bytes(public), tpmutil.U16Bytes(creation), tpmutil.U16Bytes(attest),
		id.CreationAttestation.SignatureAlg, id.CreationAttestation.Signature)
}

func parseAttestationStatement(data []byte) (*AttestationStatement, error) {
	rdr := bytes.NewReader(data)
	var hdr AttestationStatementHdr
	if err := binary.Read(rdr, binary.LittleEndian, &hdr); err != nil {
		return nil, err
	}
	stmt := AttestationStatement{
		Header:         hdr,
		KeyAttestation: make([]byte, hdr.KeyAttestationSize),
		AIKOpaque:      make([]byte, hdr.AIKOpaqueSize),
	}
	idBinding := make([]byte, hdr.IDBindingSize)
	if hdr.IDBindingSize > 0 {
		if n, err := rdr.Read(idBinding); err != nil {
			return nil, err
		} else if n != len(idBinding) {
			return nil, fmt.Errorf("unexpected end of statement reading %d bytes into IDBinding", n)
		}
	}
	id, err := parseIDBinding(idBinding)
	if err != nil {
		return nil, err
	}
	stmt.IDBinding = *id
	if hdr.KeyAttestationSize > 0 {
		if n, err := rdr.Read(stmt.KeyAttestation); err != nil {
			return nil, err
		} else if n != len(stmt.KeyAttestation) {
			return nil, fmt.Errorf("unexpected end of statement reading %d bytes into KeyAttestation", n)
		}
	}
	if hdr.AIKOpaqueSize > 0 {
		if n, err := rdr.Read(stmt.AIKOpaque); err != nil {
			return nil, err
		} else if n != len(stmt.AIKOpaque) {
			return nil, fmt.Errorf("unexpected end of statement reading %d bytes into AIKOpaque", n)
		}
	}
	return &stmt, nil
}

func GenerateAttestationStatement(stmt *AttestationStatement) ([]byte, error) {
	id, err := generateIDBinding(&stmt.IDBinding)
	if err != nil {
		return nil, err
	}
	// Make sure all the header lengths make sense
	stmt.Header.IDBindingSize = uint32(len(id))
	stmt.Header.KeyAttestationSize = uint32(len(stmt.KeyAttestation))
	stmt.Header.AIKOpaqueSize = uint32(len(stmt.AIKOpaque))

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, &stmt.Header); err != nil {
		return nil, err
	}
	buf.Write(id)
	if err := binary.Write(&buf, binary.LittleEndian, &stmt.KeyAttestation); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.LittleEndian, &stmt.AIKOpaque); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func parseEKInfo(data []byte) (*pkcs7.PKCS7, error) {
	return pkcs7.Parse(data)
}

func expectExtension(got, want asn1.ObjectIdentifier) error {
	if !got.Equal(want) {
		return fmt.Errorf("Expected extension %v, got %v", want, got)
	}
	return nil
}

// Found by trial and error to be the SHA1 hash of the full SCEP cert.
func thumbprint(cert *x509.Certificate) []byte {
	result := sha1.Sum(cert.Raw)
	return result[:]
}

func validateAKCSR(csr *akCSR, scepCert *x509.Certificate) error {
	if csr.Version != 0 {
		return fmt.Errorf("Version not 0: %d", csr.Version)
	}
	// Get the special SCEP attributes
	attrs := csr.Attributes
	if err := expectExtension(attrs.Extensions.OID, requestedExtensions); err != nil {
		return err
	}
	if err := expectExtension(attrs.Extensions.Value.Extensions.SubjectAlternativeName.Id, subjectAltName); err != nil {
		return err
	}
	if err := expectExtension(attrs.Extensions.Value.Extensions.KeyAffinity.Id, keyAffinity); err != nil {
		return err
	}
	if err := expectExtension(attrs.Extensions.Value.Extensions.SubjectKeyID.Id, subjectKeyID); err != nil {
		return err
	}
	if err := expectExtension(attrs.OSVersion.OID, osVersion); err != nil {
		return err
	}
	if err := expectExtension(attrs.SCEPSignerHash.OID, scepSignerHash); err != nil {
		return err
	}
	if scepCert != nil && !bytes.Equal(attrs.SCEPSignerHash.Value.Hash, thumbprint(scepCert)) {
		return fmt.Errorf("SCEP hash incorrect: cert thumbprint is %x, request is for %x",
			thumbprint(scepCert), attrs.SCEPSignerHash.Value.Hash)
	}
	if err := expectExtension(attrs.ClientInfo.OID, clientInfo); err != nil {
		return err
	}
	if err := expectExtension(attrs.KSPName.OID, kspName); err != nil {
		return err
	}
	if err := expectExtension(attrs.CSPInfo.OID, cspInfo); err != nil {
		return err
	}
	if err := expectExtension(attrs.AttestationStatement.OID, attestationStatement); err != nil {
		return err
	}
	_, err := parseAttestationStatement(attrs.AttestationStatement.Value.AttestationStatement)
	if err != nil {
		return err
	}
	if err := expectExtension(attrs.EKInfo.OID, ekInfo); err != nil {
		return err
	}
	_, err = parseEKInfo(attrs.EKInfo.Value.EKInfo.FullBytes)
	if err != nil {
		return err
	}
	return nil
}
