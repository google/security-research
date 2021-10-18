package akscep

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"reflect"
	"strings"
	"time"
)

func serial() *big.Int {
	serial := make([]byte, 16)
	rand.Reader.Read(serial)
	return big.NewInt(0).SetBytes(serial)
}

func MakeClientCert(subject crypto.PublicKey, issuer crypto.PrivateKey) (*x509.Certificate, []byte, error) {
	// Manually assemble and order the extensions to be consistent with what a real Windows client does.
	authorityKeyId := make([]byte, 20)
	rand.Reader.Read(authorityKeyId)
	authorityKeyId = append([]byte{0x30, 0x16, 0x80, 0x14}, authorityKeyId...)
	subjectKeyId := make([]byte, 20)
	rand.Reader.Read(subjectKeyId)
	subjectKeyId = append([]byte{0x04, 0x14}, subjectKeyId...)
	exts := []pkix.Extension{
		{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 35 /* Authority Key Identifier */},
			Value: authorityKeyId,
		},
		{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 14 /* Subject Key Identifier */},
			Value: subjectKeyId,
		},
	}
	template := x509.Certificate{
		SerialNumber: serial(),
		Subject: pkix.Name{
			CommonName: "SCEP Protocol Certificate",
		},
		NotBefore:       time.Now(),
		NotAfter:        time.Now().Add(time.Hour * 24 * 367),
		ExtraExtensions: exts,
	}
	certData, err := x509.CreateCertificate(rand.Reader, &template, &template, subject, issuer)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(certData)
	if err != nil {
		return nil, nil, err
	}
	return cert, certData, nil
}

func ValidateClientCert(cert *x509.Certificate) error {
	if err := validateCertificate(cert); err != nil {
		return err
	}
	if cert.Issuer.CommonName != "SCEP Protocol Certificate" {
		return fmt.Errorf("Issuer not SCEP Protocol Certificate")
	}
	if cert.Subject.CommonName != "SCEP Protocol Certificate" {
		return fmt.Errorf("Subject not SCEP Protocol Certificate")
	}
	if len(cert.Extensions) != 2 {
		return fmt.Errorf("not 2 extensions: %v", cert.Extensions)
	}
	if !cert.Extensions[0].Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 35} /* authority key ID */) {
		return fmt.Errorf("extension 0 not 2.5.29.35 Authority Key Identifier: %v", cert.Extensions[0].Id)
	}
	if cert.Extensions[0].Critical {
		return fmt.Errorf("extension 0 marked critical")
	}
	if !cert.Extensions[1].Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 14} /* subject key ID */) {
		return fmt.Errorf("extension 1 not 2.5.29.14 Subject Key Identifier: %v", cert.Extensions[1].Id)
	}
	if cert.Extensions[1].Critical {
		return fmt.Errorf("extension 1 marked critical")
	}
	if cert.KeyUsage != 0 {
		return fmt.Errorf("KeyUsage not 0: %v", cert.KeyUsage)
	}
	if cert.MaxPathLen != 0 {
		return fmt.Errorf("MaxPathLen not 0: %v", cert.MaxPathLen)
	}
	if cert.IsCA {
		return fmt.Errorf("IsCA")
	}
	if len(cert.AuthorityKeyId) != 20 {
		return fmt.Errorf("AuthorityKeyId not 20 bytes: %v", len(cert.AuthorityKeyId))
	}
	if cert.MaxPathLenZero {
		return fmt.Errorf("MaxPathLenZero")
	}
	if len(cert.CRLDistributionPoints) != 0 {
		return fmt.Errorf("unexpected CRLDistributionPoints: %v", cert.CRLDistributionPoints)
	}
	if len(cert.PolicyIdentifiers) != 0 {
		return fmt.Errorf("unexpected PolicyIdentifiers: %v", cert.PolicyIdentifiers)
	}

	return nil
}

func MakeRootCert(subject crypto.PublicKey, issuer crypto.PrivateKey) (*x509.Certificate, []byte, error) {
	// Manually assemble and order the extensions to be consistent with what a real Windows client does.
	authorityKeyId := make([]byte, 20)
	rand.Reader.Read(authorityKeyId)
	authorityKeyId = append([]byte{0x30, 0x16, 0x80, 0x14}, authorityKeyId...)
	subjectKeyId := make([]byte, 20)
	rand.Reader.Read(subjectKeyId)
	subjectKeyId = append([]byte{0x04, 0x14}, subjectKeyId...)
	exts := []pkix.Extension{
		{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 15 /* Key Usage */},
			Critical: false,
			Value:    []byte{0x03, 0x02, 0x01, 0x86},
		},
		{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 19 /* Basic Constraints */},
			Critical: true,
			Value:    []byte{0x30, 0x03, 0x01, 0x01, 0xff},
		},
		{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 14 /* Subject Key Identifier */},
			Value: subjectKeyId,
		},
		{
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 21, 1 /* authority info access */},
			Value: []byte{0x02, 0x01, 0x00},
		},
	}
	template := x509.Certificate{
		SerialNumber: serial(),
		Subject: pkix.Name{
			Country:      []string{"US"},
			Province:     []string{"Washington"},
			Locality:     []string{"Redmond"},
			Organization: []string{"Microsoft Corporation"},
			CommonName:   "Microsoft TPM Root Certificate Authority 2014",
		},
		NotBefore:       time.Now(),
		NotAfter:        time.Now().Add(time.Hour * 24 * 367 * 20),
		ExtraExtensions: exts,
	}
	certData, err := x509.CreateCertificate(rand.Reader, &template, &template, subject, issuer)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(certData)
	if err != nil {
		return nil, nil, err
	}
	return cert, certData, nil
}

func ValidateRootCert(cert *x509.Certificate) error {
	if err := validateCertificate(cert); err != nil {
		return err
	}
	if cert.Subject.CommonName != "Microsoft TPM Root Certificate Authority 2014" {
		return fmt.Errorf("Subject not Microsoft TPM Root Certificate Authority 2014")
	}
	if len(cert.Extensions) != 4 {
		return fmt.Errorf("not 4 extensions: %v", cert.Extensions)
	}
	if !cert.Extensions[0].Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 15} /* key usage */) {
		return fmt.Errorf("extension 0 not 2.5.29.15 Key Usage: %v", cert.Extensions[0].Id)
	}
	if cert.Extensions[0].Critical {
		return fmt.Errorf("extension 0 marked critical")
	}
	if !cert.Extensions[1].Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 19} /* basic constraints */) {
		return fmt.Errorf("extension 1 not 2.5.29.19 Basic Constraints: %v", cert.Extensions[1].Id)
	}
	if !cert.Extensions[1].Critical {
		return fmt.Errorf("extension 1 not marked critical")
	}
	if !bytes.Equal(cert.Extensions[1].Value, []byte{48, 3, 1, 1, 255}) {
		return fmt.Errorf("extension 1 content was not [48, 3, 1, 1, 255]: %v", cert.Extensions[1].Value)
	}
	if !cert.Extensions[2].Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 14} /* subject key ID */) {
		return fmt.Errorf("extension 2 not 2.5.29.14 Subject Key Identifier: %v", cert.Extensions[2].Id)
	}
	if cert.Extensions[2].Critical {
		return fmt.Errorf("extension 2 marked critical")
	}
	if !cert.Extensions[3].Id.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 21, 1} /* authority info access */) {
		return fmt.Errorf("extension 3 not 1.3.6.1.4.1.311.21.1 MS Certificate Services CA Version: %v", cert.Extensions[3].Id)
	}
	if cert.Extensions[3].Critical {
		return fmt.Errorf("extension 3 marked critical")
	}
	if !bytes.Equal(cert.Extensions[3].Value, []byte{2, 1, 0}) {
		return fmt.Errorf("extension 3 content was not [2, 1, 0]: %v", cert.Extensions[3].Value)
	}
	if cert.KeyUsage != 97 {
		return fmt.Errorf("KeyUsage not 97: %v", cert.KeyUsage)
	}
	if cert.MaxPathLen != -1 {
		return fmt.Errorf("MaxPathLen not -1: %v", cert.MaxPathLen)
	}
	if !cert.IsCA {
		return fmt.Errorf("not IsCA")
	}
	if cert.MaxPathLenZero {
		return fmt.Errorf("MaxPathLenZero")
	}
	if len(cert.CRLDistributionPoints) != 0 {
		return fmt.Errorf("unexpected CRLDistributionPoints: %v", cert.CRLDistributionPoints)
	}
	if len(cert.PolicyIdentifiers) != 0 {
		return fmt.Errorf("unexpected PolicyIdentifiers: %v", cert.PolicyIdentifiers)
	}

	return nil
}

func MakeCACert(subject crypto.PublicKey, issuer crypto.PrivateKey, issuerCert *x509.Certificate) (*x509.Certificate, []byte, error) {
	// Manually assemble and order the extensions to be consistent with what a real Windows client does.
	authorityKeyId := issuerCert.SubjectKeyId
	authorityKeyId = append([]byte{0x30, 0x16, 0x80, 0x14}, authorityKeyId...)
	subjectKeyId := make([]byte, 20)
	rand.Reader.Read(subjectKeyId)
	subjectKeyId = append([]byte{0x04, 0x14}, subjectKeyId...)
	aia := "\x30\x6f\x30\x6d\x06\x08\x2b\x06\x01\x05\x05\x07\x30\x02\x86\x61http://www.microsoft.com/pkiops/certs/Microsoft%20TPM%20Root%20Certificate%20Authority%202014.crt"
	exts := []pkix.Extension{
		{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 15 /* Key Usage */},
			Critical: true,
			Value:    []byte{0x03, 0x02, 0x02, 0x84},
		},
		{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 37 /* Extended Key Usage */},
			Value: []byte{0x30, 0x12, 0x06, 0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x15, 0x24, 0x06, 0x05, 0x67, 0x81, 0x05, 0x08, 0x03},
		},
		{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 32 /* Certificate Policies */},
			Value: []byte{48, 13, 48, 11, 6, 9, 43, 6, 1, 4, 1, 130, 55, 21, 31},
		},
		{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 19 /* Basic Constraints */},
			Critical: true,
			Value:    []byte{48, 6, 1, 1, 255, 2, 1, 0},
		},
		{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 14 /* Subject Key Identifier */},
			Value: subjectKeyId,
		},
		{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 35 /* Authority Key Identifier */},
			Value: authorityKeyId,
		},
		{
			Id: asn1.ObjectIdentifier{2, 5, 29, 31 /* CRL Distribution Points */},
			Value: []byte{
				0x30, 0x67, 0x30, 0x65, 0xa0, 0x63, 0xa0, 0x61, 0x86, 0x5f, 0x68, 0x74, 0x74,
				0x70, 0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77, 0x2e, 0x6d, 0x69, 0x63, 0x72, 0x6f,
				0x73, 0x6f, 0x66, 0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x70, 0x6b, 0x69, 0x6f,
				0x70, 0x73, 0x2f, 0x63, 0x72, 0x6c, 0x2f, 0x4d, 0x69, 0x63, 0x72, 0x6f, 0x73,
				0x6f, 0x66, 0x74, 0x25, 0x32, 0x30, 0x54, 0x50, 0x4d, 0x25, 0x32, 0x30, 0x52,
				0x6f, 0x6f, 0x74, 0x25, 0x32, 0x30, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69,
				0x63, 0x61, 0x74, 0x65, 0x25, 0x32, 0x30, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72,
				0x69, 0x74, 0x79, 0x25, 0x32, 0x30, 0x32, 0x30, 0x31, 0x34, 0x2e, 0x63, 0x72,
				0x6c,
			},
		},
		{
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1 /* Authority Info Access */},
			Value: []byte(aia),
		},
	}
	template := x509.Certificate{
		SerialNumber: serial(),
		Subject: pkix.Name{
			CommonName: "WUS-IFX-KEYID-C2EF641C329CB0A9F2EAE04BFB10C99B89C34614",
		},
		NotBefore:       time.Now(),
		NotAfter:        time.Now().Add(time.Hour * 24 * 367 * 40),
		ExtraExtensions: exts,
	}
	certData, err := x509.CreateCertificate(rand.Reader, &template, issuerCert, subject, issuer)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(certData)
	if err != nil {
		return nil, nil, err
	}
	return cert, certData, nil
}

func ValidateCACert(cert *x509.Certificate) error {
	if err := validateCertificate(cert); err != nil {
		return err
	}
	if len(cert.Extensions) != 8 {
		return fmt.Errorf("not 8 extensions: %v", cert.Extensions)
	}
	if !cert.Extensions[0].Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 15} /* key usage */) {
		return fmt.Errorf("extension 0 not 2.5.29.15 Key Usage: %v", cert.Extensions[0].Id)
	}
	if !cert.Extensions[0].Critical {
		return fmt.Errorf("extension 0 not marked critical")
	}
	if !cert.Extensions[1].Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 37} /* key usage */) {
		return fmt.Errorf("extension 1 not 2.5.29.37 Extended Key Usage: %v", cert.Extensions[1].Id)
	}
	if cert.Extensions[1].Critical {
		return fmt.Errorf("extension 1 marked critical")
	}
	if !cert.Extensions[2].Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 32} /* certificate policies */) {
		return fmt.Errorf("extension 2 not 2.5.29.32 Certificate Policies: %v", cert.Extensions[2].Id)
	}
	if cert.Extensions[2].Critical {
		return fmt.Errorf("extension 2 marked critical")
	}
	if !bytes.Equal(cert.Extensions[2].Value, []byte{48, 13, 48, 11, 6, 9, 43, 6, 1, 4, 1, 130, 55, 21, 31}) {
		return fmt.Errorf("extension 2 wrong value: %v", cert.Extensions[2].Value)
	}
	if !cert.Extensions[3].Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 19} /* basic constraints */) {
		return fmt.Errorf("extension 3 not 2.5.29.19 Basic Constraints: %v", cert.Extensions[3].Id)
	}
	if !cert.Extensions[3].Critical {
		return fmt.Errorf("extension 3 not marked critical")
	}
	if !bytes.Equal(cert.Extensions[3].Value, []byte{48, 6, 1, 1, 255, 2, 1, 0}) {
		return fmt.Errorf("extension 3 wrong value: %v", cert.Extensions[3].Value)
	}
	if !cert.Extensions[4].Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 14} /* subject key ID */) {
		return fmt.Errorf("extension 4 not 2.5.29.14 Subject Key Identifier: %v", cert.Extensions[4].Id)
	}
	if cert.Extensions[4].Critical {
		return fmt.Errorf("extension 4 marked critical")
	}
	if !cert.Extensions[5].Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 35} /* authority key ID */) {
		return fmt.Errorf("extension 5 not 2.5.29.35 Authority Key Identifier: %v", cert.Extensions[5].Id)
	}
	if cert.Extensions[5].Critical {
		return fmt.Errorf("extension 5 marked critical")
	}
	if !cert.Extensions[6].Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 31} /* authority key ID */) {
		return fmt.Errorf("extension 6 not 2.5.29.31 CRL Distribution Points: %v", cert.Extensions[6].Id)
	}
	if cert.Extensions[6].Critical {
		return fmt.Errorf("extension 6 marked critical")
	}
	if !cert.Extensions[7].Id.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1} /* authority info access */) {
		return fmt.Errorf("extension 7 not 1.3.6.1.5.5.7.1.1 Authority Info Access: %v", cert.Extensions[7].Id)
	}
	if cert.Extensions[7].Critical {
		return fmt.Errorf("extension 7 marked critical")
	}
	if cert.KeyUsage != 33 {
		return fmt.Errorf("KeyUsage not 33: %v", cert.KeyUsage)
	}
	if cert.MaxPathLen != 0 {
		return fmt.Errorf("MaxPathLen not 0: %v", cert.MaxPathLen)
	}
	if !cert.IsCA {
		return fmt.Errorf("not IsCA")
	}
	if len(cert.AuthorityKeyId) != 20 {
		return fmt.Errorf("AuthorityKeyId not 20 bytes: %v", len(cert.AuthorityKeyId))
	}
	if !cert.MaxPathLenZero {
		return fmt.Errorf("not MaxPathLenZero")
	}
	if len(cert.CRLDistributionPoints) != 1 {
		return fmt.Errorf("not 1 CRLDistributionPoints: %v", cert.CRLDistributionPoints)
	}
	if len(cert.PolicyIdentifiers) != 1 {
		return fmt.Errorf("not 1 PolicyIdentifiers: %v", cert.PolicyIdentifiers)
	}

	return nil
}

func MakeRASigningCert(subject crypto.PublicKey, issuer crypto.PrivateKey, issuerCert *x509.Certificate) (*x509.Certificate, []byte, error) {
	// Manually assemble and order the extensions to be consistent with what a real Windows AIK service does.
	authorityKeyId := issuerCert.SubjectKeyId
	authorityKeyId = append([]byte{0x30, 0x16, 0x80, 0x14}, authorityKeyId...)
	subjectKeyId := make([]byte, 20)
	rand.Reader.Read(subjectKeyId)
	subjectKeyId = append([]byte{0x04, 0x14}, subjectKeyId...)
	// Just use the AIA from the real IFX AIK instance. This is invalid for other ODMs,
	// or other IFX TPMs, but should be just fine for the purpose of reverse-engineering.
	aia := "\x30\x81\xa2\x30\x81\x9f\x06\x08\x2b\x06\x01\x05\x05\x07\x30\x02\x86\x81\x92http://azcsprodwusaikpublish.blob.core.windows.net/wus-ifx-keyid-c2ef641c329cb0a9f2eae04bfb10c99b89c34614/421fda8e-31d5-430d-b384-b8653633c05a.cer"
	exts := []pkix.Extension{
		{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 15 /* Key Usage */},
			Critical: true,
			Value:    []byte{0x03, 0x02, 0x07, 0x80},
		},
		{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 19 /* Basic Constraints */},
			Critical: true,
			Value:    []byte{0x30, 0x00},
		},
		{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 35 /* Authority Key Identifier */},
			Value: authorityKeyId,
		},
		{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 14 /* Subject Key Identifier */},
			Value: subjectKeyId,
		},
		{
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1 /* Authority Info Access */},
			Value: []byte(aia),
		},
	}
	template := x509.Certificate{
		SerialNumber: serial(),
		Subject: pkix.Name{
			CommonName: "RA Signing Certificate",
		},
		NotBefore:       time.Now(),
		NotAfter:        time.Now().Add(time.Hour * 24 * 367),
		ExtraExtensions: exts,
	}
	certData, err := x509.CreateCertificate(rand.Reader, &template, issuerCert, subject, issuer)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(certData)
	if err != nil {
		return nil, nil, err
	}
	return cert, certData, nil
}

func ValidateRASigningCert(cert *x509.Certificate) error {
	if err := validateCertificate(cert); err != nil {
		return err
	}
	if cert.Subject.CommonName != "RA Signing Certificate" {
		return fmt.Errorf("Subject not RA Signing Certificate")
	}
	if len(cert.Extensions) != 5 {
		return fmt.Errorf("not 5 extensions: %v", cert.Extensions)
	}
	if !cert.Extensions[0].Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 15} /* key usage */) {
		return fmt.Errorf("extension 0 not 2.5.29.15 Key Usage: %v", cert.Extensions[0].Id)
	}
	if !cert.Extensions[0].Critical {
		return fmt.Errorf("extension 0 not marked critical")
	}
	if !cert.Extensions[1].Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 19} /* basic constraints */) {
		return fmt.Errorf("extension 1 not 2.5.29.19 Basic Constraints: %v", cert.Extensions[1].Id)
	}
	if !cert.Extensions[1].Critical {
		return fmt.Errorf("extension 1 not marked critical")
	}
	var basicConstraints []int
	if rest, err := asn1.Unmarshal(cert.Extensions[1].Value, &basicConstraints); err != nil {
		return fmt.Errorf("parsing extension 1: %w", err)
	} else if len(rest) != 0 {
		return fmt.Errorf("leftover bytes parsing extension 1: %v", rest)
	} else if len(basicConstraints) != 0 {
		return fmt.Errorf("extension 1 content was not an empty sequence")
	}
	if !cert.Extensions[2].Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 35} /* authority key ID */) {
		return fmt.Errorf("extension 2 not 2.5.29.35 Authority Key Identifier: %v", cert.Extensions[2].Id)
	}
	if cert.Extensions[2].Critical {
		return fmt.Errorf("extension 2 marked critical")
	}
	if !cert.Extensions[3].Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 14} /* subject key ID */) {
		return fmt.Errorf("extension 3 not 2.5.29.14 Subject Key Identifier: %v", cert.Extensions[3].Id)
	}
	if cert.Extensions[3].Critical {
		return fmt.Errorf("extension 3 marked critical")
	}
	if !cert.Extensions[4].Id.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1} /* authority info access */) {
		return fmt.Errorf("extension 4 not 1.3.6.1.5.5.7.1.1 Authority Info Access: %v", cert.Extensions[4].Id)
	}
	if cert.Extensions[4].Critical {
		return fmt.Errorf("extension 4 marked critical")
	}
	var aia struct {
		Inner struct {
			OID     asn1.ObjectIdentifier
			Address []byte `asn1:"tag:6"`
		}
	}
	if rest, err := asn1.Unmarshal(cert.Extensions[4].Value, &aia); err != nil {
		return fmt.Errorf("parsing extension 4: %w", err)
	} else if len(rest) != 0 {
		return fmt.Errorf("leftover bytes parsing extension 4: %v", rest)
	} else if !aia.Inner.OID.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 2} /* */) {
		return fmt.Errorf("extension 4 AIA OID was not 1.3.6.1.5.5.7.48.2 CA Issuers")
	} else if !strings.HasPrefix(string(aia.Inner.Address), "http://azcsprodwusaikpublish.blob.core.windows.net") {
		return fmt.Errorf("extension 4 AIA address had unexpected prefix: %v", string(aia.Inner.Address))
	}
	if cert.KeyUsage != 1 {
		return fmt.Errorf("KeyUsage not 1: %v", cert.KeyUsage)
	}
	if cert.MaxPathLen != -1 {
		return fmt.Errorf("MaxPathLen not -1: %v", cert.MaxPathLen)
	}
	if cert.IsCA {
		return fmt.Errorf("IsCA")
	}
	if len(cert.AuthorityKeyId) != 20 {
		return fmt.Errorf("AuthorityKeyId not 20 bytes: %v", len(cert.AuthorityKeyId))
	}
	if cert.MaxPathLenZero {
		return fmt.Errorf("MaxPathLenZero")
	}
	if len(cert.CRLDistributionPoints) != 0 {
		return fmt.Errorf("unexpected CRLDistributionPoints: %v", cert.CRLDistributionPoints)
	}
	if len(cert.PolicyIdentifiers) != 0 {
		return fmt.Errorf("unexpected PolicyIdentifiers: %v", cert.PolicyIdentifiers)
	}

	return nil
}

func MakeRAEncryptionCert(subject crypto.PublicKey, issuer crypto.PrivateKey, issuerCert *x509.Certificate) (*x509.Certificate, []byte, error) {
	// Manually assemble and order the extensions to be consistent with what a real Windows client does.
	authorityKeyId := issuerCert.SubjectKeyId
	authorityKeyId = append([]byte{0x30, 0x16, 0x80, 0x14}, authorityKeyId...)
	subjectKeyId := make([]byte, 20)
	rand.Reader.Read(subjectKeyId)
	subjectKeyId = append([]byte{0x04, 0x14}, subjectKeyId...)
	aia := "\x30\x81\xa2\x30\x81\x9f\x06\x08\x2b\x06\x01\x05\x05\x07\x30\x02\x86\x81\x92http://azcsprodwusaikpublish.blob.core.windows.net/wus-ifx-keyid-c2ef641c329cb0a9f2eae04bfb10c99b89c34614/421fda8e-31d5-430d-b384-b8653633c05a.cer"
	exts := []pkix.Extension{
		{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 15 /* Key Usage */},
			Critical: true,
			Value:    []byte{0x03, 0x02, 0x05, 0x20},
		},
		{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 19 /* Basic Constraints */},
			Critical: true,
			Value:    []byte{0x30, 0x00},
		},
		{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 37 /* Extended Key Usage */},
			Value: []byte{0x30, 0x0b, 0x06, 0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x15, 0x24},
		},
		{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 35 /* Authority Key Identifier */},
			Value: authorityKeyId,
		},
		{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 14 /* Subject Key Identifier */},
			Value: subjectKeyId,
		},
		{
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1 /* Authority Info Access */},
			Value: []byte(aia),
		},
	}
	template := x509.Certificate{
		SerialNumber: serial(),
		Subject: pkix.Name{
			CommonName: "RA Encryption Certificate",
		},
		NotBefore:       time.Now(),
		NotAfter:        time.Now().Add(time.Hour * 24 * 367),
		ExtraExtensions: exts,
	}
	certData, err := x509.CreateCertificate(rand.Reader, &template, issuerCert, subject, issuer)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(certData)
	if err != nil {
		return nil, nil, err
	}
	return cert, certData, nil
}

func ValidateRAEncryptionCert(cert *x509.Certificate) error {
	if err := validateCertificate(cert); err != nil {
		return err
	}
	if cert.Subject.CommonName != "RA Encryption Certificate" {
		return fmt.Errorf("Subject not RA Encryption Certificate")
	}
	if len(cert.Extensions) != 6 {
		return fmt.Errorf("not 6 extensions: %v", cert.Extensions)
	}
	if !cert.Extensions[0].Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 15} /* key usage */) {
		return fmt.Errorf("extension 0 not 2.5.29.15 Key Usage: %v", cert.Extensions[0].Id)
	}
	if !cert.Extensions[0].Critical {
		return fmt.Errorf("extension 0 not marked critical")
	}
	if !cert.Extensions[1].Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 19} /* basic constraints */) {
		return fmt.Errorf("extension 1 not 2.5.29.19 Basic Constraints: %v", cert.Extensions[1].Id)
	}
	if !cert.Extensions[1].Critical {
		return fmt.Errorf("extension 1 not marked critical")
	}
	var basicConstraints []int
	if rest, err := asn1.Unmarshal(cert.Extensions[1].Value, &basicConstraints); err != nil {
		return fmt.Errorf("parsing extension 1: %w", err)
	} else if len(rest) != 0 {
		return fmt.Errorf("leftover bytes parsing extension 1: %v", rest)
	} else if len(basicConstraints) != 0 {
		return fmt.Errorf("extension 1 content was not an empty sequence")
	}
	if !cert.Extensions[2].Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 37} /* key usage */) {
		return fmt.Errorf("extension 2 not 2.5.29.37 Extended Key Usage: %v", cert.Extensions[2].Id)
	}
	if cert.Extensions[2].Critical {
		return fmt.Errorf("extension 2 marked critical")
	}
	if !cert.Extensions[3].Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 35} /* authority key ID */) {
		return fmt.Errorf("extension 3 not 2.5.29.35 Authority Key Identifier: %v", cert.Extensions[3].Id)
	}
	if cert.Extensions[3].Critical {
		return fmt.Errorf("extension 3 marked critical")
	}
	if !cert.Extensions[4].Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 14} /* subject key ID */) {
		return fmt.Errorf("extension 4 not 2.5.29.14 Subject Key Identifier: %v", cert.Extensions[4].Id)
	}
	if cert.Extensions[4].Critical {
		return fmt.Errorf("extension 4 marked critical")
	}
	if !cert.Extensions[5].Id.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1} /* authority info access */) {
		return fmt.Errorf("extension 5 not 1.3.6.1.5.5.7.1.1 Authority Info Access: %v", cert.Extensions[5].Id)
	}
	if cert.Extensions[5].Critical {
		return fmt.Errorf("extension 5 marked critical")
	}
	if cert.KeyUsage != 4 {
		return fmt.Errorf("KeyUsage not 4: %v", cert.KeyUsage)
	}
	if cert.MaxPathLen != -1 {
		return fmt.Errorf("MaxPathLen not -1: %v", cert.MaxPathLen)
	}
	if cert.IsCA {
		return fmt.Errorf("IsCA")
	}
	if len(cert.AuthorityKeyId) != 20 {
		return fmt.Errorf("AuthorityKeyId not 20 bytes: %v", len(cert.AuthorityKeyId))
	}
	if cert.MaxPathLenZero {
		return fmt.Errorf("MaxPathLenZero")
	}
	if len(cert.CRLDistributionPoints) != 0 {
		return fmt.Errorf("unexpected CRLDistributionPoints: %v", cert.CRLDistributionPoints)
	}
	if len(cert.PolicyIdentifiers) != 0 {
		return fmt.Errorf("unexpected PolicyIdentifiers: %v", cert.PolicyIdentifiers)
	}

	return nil
}

func MakeSSLCert(subject crypto.PublicKey, issuer crypto.PrivateKey) (*x509.Certificate, []byte, error) {
	subjectKeyId := make([]byte, 20)
	rand.Reader.Read(subjectKeyId)
	template := x509.Certificate{
		SerialNumber: serial(),
		Subject: pkix.Name{
			CommonName:   "graph.windows.net",
			Country:      []string{"US"},
			Province:     []string{"Washington"},
			Locality:     []string{"Redmond"},
			Organization: []string{"Microsoft Corporation"},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour * 24 * 367),
		SubjectKeyId: subjectKeyId,
		DNSNames:     []string{"*.microsoftaik.azure.net"},
	}
	certData, err := x509.CreateCertificate(rand.Reader, &template, &template, subject, issuer)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(certData)
	if err != nil {
		return nil, nil, err
	}
	return cert, certData, nil
}

func validateCertificate(cert *x509.Certificate) error {
	if len(cert.Signature) == 0 {
		return fmt.Errorf("no signature")
	}
	if cert.SignatureAlgorithm != x509.SHA256WithRSA {
		return fmt.Errorf("not SHA256WithRSA: %v", cert.SignatureAlgorithm)
	}
	if _, ok := cert.PublicKey.(*rsa.PublicKey); !ok {
		return fmt.Errorf("not *rsa.PublicKey: %v", reflect.TypeOf(cert.PublicKey))
	}
	if cert.PublicKeyAlgorithm != x509.RSA {
		return fmt.Errorf("not RSA: %v", cert.PublicKeyAlgorithm)
	}
	if cert.Version != 3 {
		return fmt.Errorf("not version 3: %v", cert.Version)
	}
	if cert.SerialNumber == nil {
		return fmt.Errorf("nil SerialNumber")
	}
	if cert.MaxPathLen != -1 && cert.MaxPathLen != 0 {
		return fmt.Errorf("MaxPathLen not -1 or 0: %v", cert.MaxPathLen)
	}
	if len(cert.SubjectKeyId) != 20 {
		return fmt.Errorf("SubjectKeyId not 20 bytes: %v", len(cert.SubjectKeyId))
	}
	if len(cert.OCSPServer) != 0 {
		return fmt.Errorf("unexpected OCSPServer: %v", cert.OCSPServer)
	}
	if len(cert.DNSNames) != 0 {
		return fmt.Errorf("unexpected DNSNames: %v", cert.DNSNames)
	}
	if len(cert.EmailAddresses) != 0 {
		return fmt.Errorf("unexpected EmailAddresses: %v", cert.EmailAddresses)
	}
	if len(cert.IPAddresses) != 0 {
		return fmt.Errorf("unexpected IPAddresses: %v", cert.IPAddresses)
	}
	if len(cert.URIs) != 0 {
		return fmt.Errorf("unexpected URIs: %v", cert.URIs)
	}
	if cert.PermittedDNSDomainsCritical {
		return fmt.Errorf("PermittedDNSDomainsCritical")
	}
	if len(cert.PermittedDNSDomains) != 0 {
		return fmt.Errorf("unexpected PermittedDNSDomains: %v", cert.PermittedDNSDomains)
	}
	if len(cert.ExcludedDNSDomains) != 0 {
		return fmt.Errorf("unexpected ExcludedDNSDomains: %v", cert.ExcludedDNSDomains)
	}
	if len(cert.PermittedIPRanges) != 0 {
		return fmt.Errorf("unexpected PermittedIPRanges: %v", cert.PermittedIPRanges)
	}
	if len(cert.ExcludedIPRanges) != 0 {
		return fmt.Errorf("unexpected ExcludedIPRanges: %v", cert.ExcludedIPRanges)
	}
	if len(cert.PermittedEmailAddresses) != 0 {
		return fmt.Errorf("unexpected PermittedEmailAddresses: %v", cert.PermittedEmailAddresses)
	}
	if len(cert.ExcludedEmailAddresses) != 0 {
		return fmt.Errorf("unexpected ExcludedEmailAddresses: %v", cert.ExcludedEmailAddresses)
	}
	if len(cert.PermittedURIDomains) != 0 {
		return fmt.Errorf("unexpected PermittedURIDomains: %v", cert.PermittedURIDomains)
	}
	if len(cert.ExcludedURIDomains) != 0 {
		return fmt.Errorf("unexpected ExcludedURIDomains: %v", cert.ExcludedURIDomains)
	}

	return nil
}
