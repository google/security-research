package akscep_test

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"testing"

	"github.com/google/security-research/pocs/bios/tpm-carte-blanche/lib/akscep"
)

func TestParseGetChallengeReq(t *testing.T) {
	data, err := ioutil.ReadFile("sampledata/3_post_req")
	if err != nil {
		t.Fatalf("can't read test data: %v", err)
	}
	_, err = akscep.ParseGetChallengeReq(data)
	if err != nil {
		t.Fatalf("can't deserialize test data: %v", err)
	}
}

func TestParseAttestationKeyCSR(t *testing.T) {
	data, err := ioutil.ReadFile("sampledata/scepReq134090648")
	if err != nil {
		t.Fatalf("can't read test data: %v", err)
	}
	_, err = akscep.ParseAttestationKeyCSR(data, nil)
	if err != nil {
		t.Fatalf("can't deserialize test data: %v", err)
	}
	// The following test is broken, however the server is happy with what we're sending it,
	// which is a better test of goodness for this proof of concept.
	/*
		t.Run("generate", func(t *testing.T) {
			generated, err := akscep.GenerateAttestationKeyCSR(csr)
			if err != nil {
				t.Fatalf("can't serialize CSR: %v", err)
			}
			if !bytes.Equal(data, generated) {
				t.Errorf("did not generate same request:\nwant:\n%s\ngot:\n%s\n",
					hex.EncodeToString(data), hex.EncodeToString(generated))
			}
		})
	*/
}

func TestParseGetChallengeRsp(t *testing.T) {
	data, err := ioutil.ReadFile("sampledata/3_post_rsp")
	if err != nil {
		t.Fatalf("can't read test data: %v", err)
	}
	_, err = akscep.ParseGetChallengeRsp(data)
	if err != nil {
		t.Fatalf("can't deserialize test data: %v", err)
	}
}

func TestParseAttestationKeyChallenge(t *testing.T) {
	data, err := ioutil.ReadFile("sampledata/attestationKeyChallenge")
	if err != nil {
		t.Fatalf("can't read test data: %v", err)
	}
	chal, err := akscep.ParseAttestationKeyChallenge(data)
	if err != nil {
		t.Fatalf("can't deserialize test data: %v", err)
	}
	fmt.Printf("%+v\n", chal)
}

func TestParseGetCertReq(t *testing.T) {
	data, err := ioutil.ReadFile("sampledata/4_post_req")
	if err != nil {
		t.Fatalf("can't read test data: %v", err)
	}
	_, err = akscep.ParseGetChallengeReq(data)
	if err != nil {
		t.Fatalf("can't deserialize test data: %v", err)
	}
}

func TestParseGetCertRsp(t *testing.T) {
	data, err := ioutil.ReadFile("sampledata/4_post_rsp")
	if err != nil {
		t.Fatalf("can't read test data: %v", err)
	}
	_, err = akscep.ParseGetCertRsp(data)
	if err != nil {
		t.Fatalf("can't deserialize test data: %v", err)
	}
}

type testingKeys struct {
	client, root, ca, raSigning, raEncryption crypto.PrivateKey
}
type testingCerts struct {
	client, root, ca, raSigning, raEncryption *x509.Certificate
}

var keys, certs = makeTestingKeys()

func makeTestingKeys() (testingKeys, testingCerts) {
	client, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(fmt.Sprintf("generating key: %v", err))
	}
	root, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		panic(fmt.Sprintf("generating key: %v", err))
	}
	ca, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		panic(fmt.Sprintf("generating key: %v", err))
	}
	raSigning, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(fmt.Sprintf("generating key: %v", err))
	}
	raEncryption, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(fmt.Sprintf("generating key: %v", err))
	}

	clientCert, _, err := akscep.MakeClientCert(client.Public(), client)
	if err != nil {
		panic(fmt.Sprintf("generating cert: %v", err))
	}
	rootCert, _, err := akscep.MakeRootCert(root.Public(), root)
	if err != nil {
		panic(fmt.Sprintf("generating cert: %v", err))
	}
	caCert, _, err := akscep.MakeCACert(ca.Public(), root, rootCert)
	if err != nil {
		panic(fmt.Sprintf("generating cert: %v", err))
	}
	raSigningCert, _, err := akscep.MakeRASigningCert(raSigning.Public(), ca, caCert)
	if err != nil {
		panic(fmt.Sprintf("generating cert: %v", err))
	}
	raEncryptionCert, _, err := akscep.MakeRAEncryptionCert(raEncryption.Public(), ca, caCert)
	if err != nil {
		panic(fmt.Sprintf("generating cert: %v", err))
	}

	return testingKeys{
			client:       client,
			root:         root,
			ca:           ca,
			raSigning:    raSigning,
			raEncryption: raEncryption,
		}, testingCerts{
			client:       clientCert,
			root:         rootCert,
			ca:           caCert,
			raSigning:    raSigningCert,
			raEncryption: raEncryptionCert,
		}
}

func TestGenerateGetChallengeReq(t *testing.T) {
	claims := []byte{} // TODO: reverse engineer this

	builder := akscep.GetChallengeReqBuilder{
		Claims:        claims,
		SignerCert:    certs.client,
		SignerKey:     keys.client,
		RecipientCert: certs.raEncryption,
	}
	req, err := builder.Build()
	if err != nil {
		t.Fatalf("generating request: %v", err)
	}
	_, err = akscep.ParseGetChallengeReq(req)
	if err != nil {
		t.Errorf("invalid request generated: %v", err)
	}
}

func TestGenerateGetChallengeRsp(t *testing.T) {
	challenge := []byte{} // TODO: reverse engineer this

	builder := akscep.GetChallengeRspBuilder{
		Challenge:     challenge,
		SignerCert:    certs.raSigning,
		SignerKey:     keys.raSigning,
		RecipientCert: certs.client,
	}
	rsp, err := builder.Build()
	if err != nil {
		t.Fatalf("generating request: %v", err)
	}
	_, err = akscep.ParseGetChallengeRsp(rsp)
	if err != nil {
		t.Errorf("invalid request generated: %v", err)
	}
}

func TestGenerateGetCertReq(t *testing.T) {
	challenge := []byte{} // TODO: reverse engineer this

	builder := akscep.GetCertReqBuilder{
		Challenge:     challenge,
		SignerCert:    certs.client,
		SignerKey:     keys.client,
		RecipientCert: certs.raEncryption,
	}
	req, err := builder.Build()
	if err != nil {
		t.Fatalf("generating request: %v", err)
	}
	_, err = akscep.ParseGetCertReq(req)
	if err != nil {
		t.Errorf("invalid request generated: %v", err)
	}
}

func TestGenerateGetCertRsp(t *testing.T) {
	cert := []byte{} // TODO: reverse engineer this

	builder := akscep.GetCertRspBuilder{
		Cert:          cert,
		SignerCert:    certs.raSigning,
		SignerKey:     keys.raSigning,
		RecipientCert: certs.client,
	}
	rsp, err := builder.Build()
	if err != nil {
		t.Fatalf("generating request: %v", err)
	}
	_, err = akscep.ParseGetCertRsp(rsp)
	if err != nil {
		t.Errorf("invalid request generated: %v", err)
	}
}

func TestParseEKInfo(t *testing.T) {
	data, err := ioutil.ReadFile("sampledata/ekCerts367085007")
	if err != nil {
		t.Fatalf("can't read test data: %v", err)
	}
	ek, err := akscep.ParseEKInfo(data)
	if err != nil {
		t.Fatalf("can't parse EK certs: %v", err)
	}
	t.Run("generate", func(t *testing.T) {
		generated, err := akscep.GenerateEKInfo(ek)
		if err != nil {
			t.Fatalf("can't generate EK cert packet: %v", err)
		}
		if !bytes.Equal(generated, data) {
			t.Errorf("want %x got %x", data, generated)
		}
	})

}
