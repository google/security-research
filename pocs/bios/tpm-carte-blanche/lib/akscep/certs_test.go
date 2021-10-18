package akscep_test

import (
	"crypto/x509"
	"io/ioutil"
	"testing"

	"github.com/google/security-research/pocs/bios/tpm-carte-blanche/lib/akscep"
)

func TestValidateClientCert(t *testing.T) {
	data, err := ioutil.ReadFile("sampledata/scep")
	if err != nil {
		t.Fatalf("can't read test data: %v", err)
	}
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		t.Errorf("can't parse test cert: %v", err)
	}
	if err = akscep.ValidateClientCert(cert); err != nil {
		t.Errorf("want nil got %v", err)
	}
}

func TestMakeClientCert(t *testing.T) {
	if err := akscep.ValidateClientCert(certs.client); err != nil {
		t.Errorf("want nil got %v", err)
	}
}

func TestValidateRootCert(t *testing.T) {
	data, err := ioutil.ReadFile("sampledata/root")
	if err != nil {
		t.Fatalf("can't read test data: %v", err)
	}
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		t.Errorf("can't parse test cert: %v", err)
	}
	if err = akscep.ValidateRootCert(cert); err != nil {
		t.Errorf("want nil got %v", err)
	}
}

func TestMakeRootCert(t *testing.T) {
	if err := akscep.ValidateRootCert(certs.root); err != nil {
		t.Errorf("want nil got %v", err)
	}
}

func TestValidateCACert(t *testing.T) {
	data, err := ioutil.ReadFile("sampledata/ca")
	if err != nil {
		t.Fatalf("can't read test data: %v", err)
	}
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		t.Errorf("can't parse test cert: %v", err)
	}
	if err = akscep.ValidateCACert(cert); err != nil {
		t.Errorf("want nil got %v", err)
	}
}

func TestMakeCACert(t *testing.T) {
	if err := akscep.ValidateCACert(certs.ca); err != nil {
		t.Errorf("want nil got %v", err)
	}
}

func TestValidateRASigningCert(t *testing.T) {
	data, err := ioutil.ReadFile("sampledata/rasigning")
	if err != nil {
		t.Fatalf("can't read test data: %v", err)
	}
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		t.Errorf("can't parse test cert: %v", err)
	}
	if err = akscep.ValidateRASigningCert(cert); err != nil {
		t.Errorf("want nil got %v", err)
	}
}

func TestMakeRASigningCert(t *testing.T) {
	if err := akscep.ValidateRASigningCert(certs.raSigning); err != nil {
		t.Errorf("want nil got %v", err)
	}
}

func TestValidateRAEncryptionCert(t *testing.T) {
	data, err := ioutil.ReadFile("sampledata/raencrypt")
	if err != nil {
		t.Fatalf("can't read test data: %v", err)
	}
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		t.Errorf("can't parse test cert: %v", err)
	}
	if err = akscep.ValidateRAEncryptionCert(cert); err != nil {
		t.Errorf("want nil got %v", err)
	}
}

func TestMakeRAEncryptionCert(t *testing.T) {
	if err := akscep.ValidateRAEncryptionCert(certs.raEncryption); err != nil {
		t.Errorf("want nil got %v", err)
	}
}
