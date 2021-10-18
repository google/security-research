package akscep

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	insecurerand "math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/chrisfenner/pkcs7"
	forkx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

type ClientContext struct {
	tpm         io.ReadWriteCloser
	httpClient  http.Client
	requestID   string
	machineName string
	scepKey     *rsa.PrivateKey
	scepCert    *x509.Certificate
	serviceURL  string
	raCert      *x509.Certificate
	ak          *AK
	akBundle    akBundle
	ek          *attest.EK
}

func (cli *ClientContext) Close() {
	tpm2.FlushContext(cli.tpm, cli.akBundle.handle)
	cli.tpm.Close()
}

func unfork(cert *forkx509.Certificate) *x509.Certificate {
	unforked, err := x509.ParseCertificate(cert.Raw)
	if err != nil {
		panic(err)
	}
	return unforked
}

func NewClientContext() (*ClientContext, error) {
	machineName := randomMachineName()

	// Fetch the EK
	ek, err := getEK()
	if err != nil {
		return nil, err
	}

	httpClient := http.Client{
		Timeout: 10 * time.Second,
	}

	b := make([]byte, 16)
	rand.Reader.Read(b)
	requestID := fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
	// TODO get the manufacturer id properly
	serviceURL := serviceAddress("ifx", ek.Certificate.AuthorityKeyId)

	cli := ClientContext{
		httpClient:  httpClient,
		requestID:   requestID,
		machineName: machineName,
		serviceURL:  serviceURL,
		ek:          ek,
	}

	// Fetch the RA certificate from the service, we encrypt requests to it
	// TODO: clean up the fact that we rely on the fact that getRA works on a
	// partly constructed client
	ra, err := (&cli).getRA(unfork(ek.Certificate))
	if err != nil {
		return nil, err
	}
	cli.raCert = ra

	// Generate a new AK
	ak, err := newAK()
	if err != nil {
		return nil, err
	}
	cli.ak = ak

	tpm, err := tpm2.OpenTPM("/dev/tpmrm0")
	if err != nil {
		return nil, err
	}
	// TODO: don't leak this if there is an error in the next few lines
	cli.tpm = tpm

	bundle, err := ak.Generate(tpm)
	if err != nil {
		return nil, err
	}
	// TODO: don't leak this if there is an error in the next few lines
	cli.akBundle = *bundle

	// Generate the SCEP key for decrypting responses from the server
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	cli.scepKey = key

	cert, _, err := MakeClientCert(key.Public(), key)
	if err != nil {
		return nil, err
	}
	cli.scepCert = cert

	return &cli, nil
}

func randomMachineName() string {
	var buf strings.Builder
	buf.WriteString("DESKTOP-")
	r := insecurerand.New(insecurerand.NewSource(time.Now().UnixNano()))
	for i := 0; i < 7; i++ {
		c := r.Intn(len(machNameCharSet))
		buf.WriteByte(machNameCharSet[c])
	}
	return buf.String()
}

func serviceAddress(tpmManufacturerID string, ekid []byte) string {
	return fmt.Sprintf("https://%s-keyid-%x.microsoftaik.azure.net/templates/Aik/scep", tpmManufacturerID, ekid)
}

func (cli *ClientContext) addSCEPHeaders(h http.Header) {
	h.Add("Cache-Control", "no-cache")
	h.Add("Connection", "Keep-Alive")
	h.Add("Pragma", "no-cache")
	h.Add("Content-Type", "application/x-pki-message")
	// TODO: populate this with the same version number we put into the claims
	h.Add("User-Agent", `Mozilla/4.0 (compatible; Win32; NDES client 10.0.19041.746/vb_release_svc_prod1)`)
	// TODO: Populate this with real data from the TPM, assuming the service checks
	h.Add("PlatformType", `TPM-Version:2.0 -Level:0-Revision:0.99-VendorID:'IFX '-Firmware:327680.278786`)
	h.Add("x-ms-client-request-id", cli.requestID)
}

func (cli *ClientContext) getRA(ekCert *x509.Certificate) (*x509.Certificate, error) {
	url := cli.serviceURL + "?operation=GetCACertChain&message=default"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	cli.addSCEPHeaders(req.Header)
	fmt.Printf("Connecting to AK Service...")
	rsp, err := cli.httpClient.Do(req)
	fmt.Printf("done\n")
	if err != nil {
		return nil, err
	}
	defer rsp.Body.Close()
	data, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		return nil, err
	}
	serviceCerts, err := pkcs7.Parse(data)
	if err != nil {
		return nil, err
	}
	for _, serviceCert := range serviceCerts.Certificates {
		if serviceCert.Subject.CommonName == "RA Encryption Certificate" {
			return serviceCert, nil
		}
	}
	return nil, fmt.Errorf("Service did not provide an RA encryption cert")
}

func (cli *ClientContext) getChallenge(chal *GetChallengeReqBuilder) ([]byte, error) {
	chalReq, err := chal.Build()
	if err != nil {
		return nil, err
	}
	url := cli.serviceURL + "?operation=PKIOperation"
	req, err := http.NewRequest("POST", url, bytes.NewReader(chalReq))
	if err != nil {
		return nil, err
	}
	cli.addSCEPHeaders(req.Header)
	rsp, err := cli.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer rsp.Body.Close()
	data, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func (cli *ClientContext) getCert(b *GetCertReqBuilder) ([]byte, error) {
	certReq, err := b.Build()
	if err != nil {
		return nil, err
	}
	url := cli.serviceURL + "?operation=PKIOperation"
	req, err := http.NewRequest("POST", url, bytes.NewReader(certReq))
	if err != nil {
		return nil, err
	}
	cli.addSCEPHeaders(req.Header)
	rsp, err := cli.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer rsp.Body.Close()
	data, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func getEK() (*attest.EK, error) {
	tpm, err := attest.OpenTPM(nil)
	if err != nil {
		return nil, err
	}
	defer tpm.Close()
	eks, err := tpm.EKs()
	if err != nil {
		return nil, err
	}
	if len(eks) == 0 {
		return nil, fmt.Errorf("this TPM has no EK")
	}
	return &eks[0], nil
}

type AK struct {
	subjectKeyId []byte
}

var machNameCharSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func newAK() (*AK, error) {
	id := make([]byte, 20)
	rand.Reader.Read(id)
	return &AK{
		subjectKeyId: id,
	}, nil
}

func decodeHexOrPanic(in string) []byte {
	data, err := hex.DecodeString(in)
	if err != nil {
		panic(err)
	}
	return data
}

type akBundle struct {
	handle                                           tpmutil.Handle
	public, creationName, creationData, creationHash []byte
	creationTicket                                   tpm2.Ticket
	template                                         []byte
}

func (ak *AK) Generate(tpm io.ReadWriter) (*akBundle, error) {
	template := tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagNoDA | tpm2.FlagRestricted | tpm2.FlagSign,
		AuthPolicy: decodeHexOrPanic("9dffcbf36c383ae699fb9868dc6dcb89" +
			"d7153884be2803922c124158bfad22ae"),
		RSAParameters: &tpm2.RSAParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgRSASSA,
				Hash: tpm2.AlgSHA1,
			},
			KeyBits: 2048,
			// Customize the input template with the random Subject Key ID
			// This allows each AIK to be unique even though they are Primary
			ModulusRaw: tpmutil.U16Bytes(ak.subjectKeyId),
		},
	}
	encodedTemplate, err := template.Encode()
	if err != nil {
		return nil, err
	}

	fmt.Printf("Generating AK %x...", ak.subjectKeyId)
	h, pub, cd, ch, tk, cn, err := tpm2.CreatePrimaryEx(tpm, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", template)
	fmt.Printf("done\n")
	if err != nil {
		return nil, err
	}

	return &akBundle{
		handle:         h,
		public:         pub,
		creationData:   cd,
		creationHash:   ch,
		creationTicket: tk,
		creationName:   cn,
		template:       encodedTemplate,
	}, nil
}

func (cli *ClientContext) AttestationStatement() (*AttestationStatement, crypto.PublicKey, error) {
	fmt.Printf("Certifying AK...")
	attest, sig, err := tpm2.CertifyCreation(cli.tpm, "", cli.akBundle.handle, cli.akBundle.handle, []byte{}, cli.akBundle.creationHash, tpm2.SigScheme{Alg: tpm2.AlgNull}, cli.akBundle.creationTicket)
	fmt.Printf("done\n")
	if err != nil {
		return nil, nil, err
	}

	public, err := tpm2.DecodePublic(cli.akBundle.public)
	if err != nil {
		return nil, nil, err
	}
	creationData, err := tpm2.DecodeCreationData(cli.akBundle.creationData)
	if err != nil {
		return nil, nil, err
	}
	att, err := tpm2.DecodeAttestationData(attest)
	if err != nil {
		return nil, nil, err
	}
	tpmPub, err := tpm2.DecodePublic(cli.akBundle.public)
	if err != nil {
		return nil, nil, err
	}
	tpmSig, err := tpm2.DecodeSignature(bytes.NewBuffer(sig))
	if err != nil {
		return nil, nil, err
	}
	pub, err := tpmPub.Key()
	if err != nil {
		return nil, nil, err
	}

	stmt := AttestationStatement{
		Header: AttestationStatementHdr{
			Magic:      0x5453414b,
			Version:    1,
			Platform:   2,
			HeaderSize: 28,
		},
		IDBinding: IDBinding{
			Public: public,
			CreationAttestation: CreationAttestation{
				CreationData: *creationData,
				Attest:       *att,
				SignatureAlg: tpmSig.Alg,
				Signature:    *tpmSig.RSA,
			},
		},
	}

	return &stmt, pub, nil
}

// Default EK template defined in:
// https://trustedcomputinggroup.org/wp-content/uploads/Credential_Profile_EK_V2.0_R14_published.pdf
// From https://github.com/google/go-attestation/blob/0a3c6e82bfbdef476a1b6b9e6ac2a0fdcc79e821/attest/tpm.go#L74
var defaultEKTemplate = tpm2.Public{
	Type:    tpm2.AlgRSA,
	NameAlg: tpm2.AlgSHA256,
	Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
		tpm2.FlagAdminWithPolicy | tpm2.FlagRestricted | tpm2.FlagDecrypt,
	AuthPolicy: []byte{
		0x83, 0x71, 0x97, 0x67, 0x44, 0x84,
		0xB3, 0xF8, 0x1A, 0x90, 0xCC, 0x8D,
		0x46, 0xA5, 0xD7, 0x24, 0xFD, 0x52,
		0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64,
		0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14,
		0x69, 0xAA,
	},
	RSAParameters: &tpm2.RSAParams{
		Symmetric: &tpm2.SymScheme{
			Alg:     tpm2.AlgAES,
			KeyBits: 128,
			Mode:    tpm2.AlgCFB,
		},
		KeyBits:    2048,
		ModulusRaw: make([]byte, 256),
	},
}

func (cli *ClientContext) DecryptChallenge(challenge *AttestationKeyChallenge) ([]byte, error) {
	ek, _, err := tpm2.CreatePrimary(cli.tpm, tpm2.HandleEndorsement, tpm2.PCRSelection{}, "", "", defaultEKTemplate)
	if err != nil {
		return nil, fmt.Errorf("EK CreatePrimary failed: %v", err)
	}
	defer tpm2.FlushContext(cli.tpm, ek)

	sessHandle, _, err := tpm2.StartAuthSession(
		cli.tpm,
		tpm2.HandleNull,  /*tpmKey*/
		tpm2.HandleNull,  /*bindKey*/
		make([]byte, 16), /*nonceCaller*/
		nil,              /*secret*/
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		return nil, fmt.Errorf("creating session: %v", err)
	}
	defer tpm2.FlushContext(cli.tpm, sessHandle)

	if _, err := tpm2.PolicySecret(cli.tpm, tpm2.HandleEndorsement, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}, sessHandle, nil, nil, nil, 0); err != nil {
		return nil, fmt.Errorf("tpm2.PolicySecret() failed: %v", err)
	}

	result, err := tpm2.ActivateCredentialUsingAuth(cli.tpm, []tpm2.AuthCommand{
		{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession},
		{Session: sessHandle, Attributes: tpm2.AttrContinueSession},
	}, cli.akBundle.handle, ek, challenge.CredentialBlob, challenge.Secret)
	return result, err
}

func (cli *ClientContext) unwrapGetChallengeResponse(rsp []byte) (*AttestationKeyChallenge, error) {
	// Unwrap the outer PKCS7 signed blob
	env, err := ParseGetChallengeRsp(rsp)
	if err != nil {
		return nil, err
	}

	// Decrypt the inner PKCS7 encrypted blob and parse the inner structure there
	return env.DecryptChallenge(cli.scepCert, cli.scepKey)
}

func (cli *ClientContext) unwrapGetCertResponse(rsp []byte) ([]byte, error) {
	// Unwrap the outer PKCS7 signed blob
	env, err := ParseGetCertRsp(rsp)
	if err != nil {
		return nil, err
	}

	// Decrypt the inner PKCS7 encrypted PKCS7 signed certificate
	decrypted, err := env.DecryptCert(cli.scepCert, cli.scepKey)
	if err != nil {
		return nil, err
	}

	// Unwrap the redundantly signed PKCS7 to return a nice x509
	signed, err := pkcs7.Parse(decrypted)
	if err != nil {
		return nil, err
	}
	if len(signed.Certificates) < 1 {
		return nil, fmt.Errorf("didn't get any certs back")
	}

	return signed.Certificates[0].Raw, nil
}

func (cli *ClientContext) GetAKCert() (template, cert []byte, err error) {
	tpmInfo, err := ekTPMInfo(unfork(cli.ek.Certificate))
	if err != nil {
		return nil, nil, err
	}
	extraEKCerts, err := AdditionalEKCerts(unfork(cli.ek.Certificate))
	if err != nil {
		return nil, nil, fmt.Errorf("fetching EK intermediates: %w", err)
	}
	ekInfo, err := EncryptEKInfo(unfork(cli.ek.Certificate), cli.raCert)
	if err != nil {
		return nil, nil, err
	}
	attestation, public, err := cli.AttestationStatement()
	if err != nil {
		return nil, nil, err
	}

	csr := AttestationKeyCSR{
		SubjectPublicKey:     public,
		SubjectKeyID:         cli.ak.subjectKeyId,
		OSVersion:            "10.0.19043.2",
		SCEPSignerHash:       thumbprint(cli.scepCert),
		MachineName:          cli.machineName,
		UserName:             `WORKGROUP\` + cli.machineName + "$",
		AttestationStatement: *attestation,
		EncryptedEKCerts:     ekInfo,
		TPMInfo:              *tpmInfo,
	}

	claims, err := GenerateAttestationKeyCSR(&csr)
	if err != nil {
		return nil, nil, err
	}

	challengeBuilder := GetChallengeReqBuilder{
		Claims:        claims,
		ExtraEKCerts:  extraEKCerts,
		SignerCert:    cli.scepCert,
		SignerKey:     cli.scepKey,
		RecipientCert: cli.raCert,
	}

	fmt.Printf("Requesting EK challenge...")
	getChallengeRsp, err := cli.getChallenge(&challengeBuilder)
	fmt.Printf("done\n")
	if err != nil {
		return nil, nil, err
	}

	fmt.Printf("Unwrapping EK challenge outer PKCS7 layers...")
	challenge, err := cli.unwrapGetChallengeResponse(getChallengeRsp)
	fmt.Printf("done\n")
	if err != nil {
		return nil, nil, err
	}

	fmt.Printf("Decrypting EK challenge...")
	decrypted, err := cli.DecryptChallenge(challenge)
	fmt.Printf("done\n")
	if err != nil {
		return nil, nil, err
	}

	fmt.Printf("Decrypted challenge: %x\n", decrypted)

	certBuilder := GetCertReqBuilder{
		Challenge:          challenge,
		DecryptedChallenge: decrypted,
		SignerCert:         cli.scepCert,
		SignerKey:          cli.scepKey,
		RecipientCert:      cli.raCert,
	}

	fmt.Printf("Presenting decrypted EK challenge to server...")
	encCert, err := cli.getCert(&certBuilder)
	fmt.Printf("done\n")
	if err != nil {
		return nil, nil, err
	}

	fmt.Printf("Decrypting AK cert...")
	certificate, err := cli.unwrapGetCertResponse(encCert)
	fmt.Printf("done\n")
	if err != nil {
		return nil, nil, err
	}
	return cli.akBundle.template, certificate, err
}
