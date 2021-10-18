package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/TylerBrock/colorjson"
	xj "github.com/basgys/goxml2json"
	"github.com/google/go-tpm/tpm2"
)

var (
	logFile  = flag.String("log", "", "the TCG log file to use")
	certFile = flag.String("cert", "", "the health certificate file to use")
	bank     = flag.String("bank", "", "the PCR bank to use (SHA1 or SHA256)")
	aikFile  = flag.String("aik", "", "the .aik file to use")
	nonce    = flag.String("nonce", "", "the nonce to use (hex)")
)

func printUsage() {
	fmt.Printf(`dhatool usage:
  extend a log:
    dhatool --log=<log file> --bank=<sha1 or sha256> replay 
  fetch a health certificate:
    dhatool --log=<log file> --bank=<sha1 or sha256> --aik=<aik file> getcert 
  validate a health certificate:
    dhatool --cert=<cert file> --bank=<sha1 or sha256> --aik=<aik file> --nonce=<hex nonce> validate
`)
}

func main() {
	flag.Parse()
	os.Exit(mainWithReturn())
}

func mainWithReturn() int {
	if len(flag.Args()) != 1 {
		fmt.Fprintf(os.Stderr, "please specify a command\n")
		printUsage()
		return -1
	}
	switch strings.ToLower(flag.Args()[0]) {
	case "replay":
		if err := replayLog(*logFile, *bank); err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			printUsage()
			return -1
		}
	case "getcert":
		if err := getHealthCert(*logFile, *bank, *aikFile); err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			printUsage()
			return -1
		}
	case "validate":
		if err := validate(*certFile, *bank, *aikFile, *nonce); err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			printUsage()
			return -1
		}
	default:
		printUsage()
		return -1
	}

	return -1
}

func hashAlgFromString(name string) (tpm2.Algorithm, error) {
	switch strings.ToLower(name) {
	case "sha1":
		return tpm2.AlgSHA1, nil
	case "sha256":
		return tpm2.AlgSHA256, nil
	default:
		return tpm2.AlgNull, fmt.Errorf("'%v' is not a valid PCR bank")
	}
}

func replayLog(logFile, bank string) error {
	log, err := ioutil.ReadFile(logFile)
	if err != nil {
		return err
	}
	alg, err := hashAlgFromString(bank)
	if err != nil {
		return err
	}
	fmt.Printf("extending log events...")
	err = ReplayLog(log, alg)
	fmt.Printf("done!\n")
	return err
}

type certifiedAK struct {
	Template    []byte
	Certificate []byte
}

func getHealthCert(logFile, bank, aikFile string) error {
	alg, err := hashAlgFromString(bank)
	if err != nil {
		return err
	}
	if aikFile == "" {
		return fmt.Errorf("please specify an AIK file")
	}
	if logFile == "" {
		return fmt.Errorf("please specify a TCG log file")
	}

	aikContents, err := ioutil.ReadFile(aikFile)
	if err != nil {
		return err
	}
	log, err := ioutil.ReadFile(logFile)
	if err != nil {
		return err
	}

	var aik certifiedAK
	if err := json.Unmarshal(aikContents, &aik); err != nil {
		return err
	}

	fmt.Printf("generating claims (may take up to 60 seconds)...")
	claims, err := MakeClaims(log, aik.Template, nil, alg)
	fmt.Printf("done!\n")
	if err != nil {
		return err
	}
	claimsBytes, err := claims.Marshal()
	if err != nil {
		return err
	}
	req := Request{
		Claims: claimsBytes,
		AIK:    aik.Certificate,
	}
	reqBytes, err := req.Marshal()
	if err != nil {
		return err
	}
	reqRdr := bytes.NewReader(reqBytes)

	fmt.Printf("requesting cert...")
	client := &http.Client{}
	httpReq, err := http.NewRequest("POST", "https://has.spserv.microsoft.com/devicehealthattestation/gethealthcertificate/v1", reqRdr)
	if err != nil {
		return fmt.Errorf("could not initialize DHA client: %w\n", err)
	}
	httpReq.Header.Add("content-type", "application/xml")
	httpReq.Header.Add("accept", "* /*")
	httpReq.Header.Add("user-agent", "Windows Health Cert Retrieval 1.0")
	httpReq.Header.Add("dhascorrelationid", "cab697aa-3975-4972-a4b4-6e01f047d224")
	resp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("error POSTing to DHA: %w\n", err)
	}
	var respBuf bytes.Buffer
	resp.Write(&respBuf)
	fmt.Printf("done!\n")

	certFile := "./healthcert"
	cert, err := extractCertFromResponse(respBuf.Bytes())
	if err != nil {
		return fmt.Errorf("error from DHA: %w\n", err)
	}
	if err = ioutil.WriteFile(certFile, cert, 0644); err != nil {
		return err
	}

	fmt.Printf("Wrote %d bytes of health certificate to %s.\n", len(cert), certFile)

	return nil
}

func validate(certFile, bank, aikFile, nonce string) error {
	alg, err := hashAlgFromString(bank)
	if err != nil {
		return err
	}
	if aikFile == "" {
		return fmt.Errorf("please specify an AIK file")
	}

	aikContents, err := ioutil.ReadFile(aikFile)
	if err != nil {
		return err
	}
	cert, err := ioutil.ReadFile(certFile)
	if err != nil {
		return err
	}

	nonceDecoded, err := hex.DecodeString(nonce)
	if err != nil {
		return err
	}

	var aik certifiedAK
	if err := json.Unmarshal(aikContents, &aik); err != nil {
		return err
	}

	fmt.Printf("generating claims (may take up to 60 seconds)...")
	claims, err := MakeValClaims(aik.Template, nonceDecoded, alg)
	fmt.Printf("done!\n")
	if err != nil {
		return err
	}
	claimsBytes, err := claims.Marshal()
	if err != nil {
		return err
	}

	req := Validation{
		Cert:   cert,
		Nonce:  nonceDecoded,
		Claims: claimsBytes,
	}
	reqBytes, err := req.Marshal()
	if err != nil {
		return err
	}

	reqRdr := bytes.NewReader(reqBytes)

	fmt.Printf("requesting validation...")
	client := &http.Client{}
	httpReq, err := http.NewRequest("POST", "https://has.spserv.microsoft.com/devicehealthattestation/validatehealthcertificate/v1", reqRdr)
	if err != nil {
		return fmt.Errorf("could not initialize DHA client: %w\n", err)
	}
	httpReq.Header.Add("content-type", "application/xml")
	httpReq.Header.Add("accept", "*/*")
	httpReq.Header.Add("user-agent", "Windows Health Cert Retrieval 1.0")
	httpReq.Header.Add("dhascorrelationid", "c8b697aa-3975-4972-a4b4-6e01f047d224")
	resp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("error POSTing to DHA: %w\n", err)
	}
	var respBuf bytes.Buffer
	resp.Write(&respBuf)
	fmt.Printf("done!\n")

	prettyPrintStatus(respBuf.Bytes())
	return nil
}

func extractCertFromResponse(rsp []byte) ([]byte, error) {
	// HACK: TODO: proper xml unmarshalling here...
	rspString := string(rsp)
	fmt.Printf("Response\n%v\n", rspString)
	start := "<HealthCertificateBlob>"
	startIdx := strings.Index(rspString, start)
	startIdx += len(start)
	end := "</HealthCertificateBlob>"
	endIdx := strings.Index(rspString, end)
	// If we can't find the health blob, just assume there was an error.
	if startIdx == -1 || endIdx == -1 {
		return nil, fmt.Errorf("error from service: %v", rspString)
	}
	decoded, err := base64.StdEncoding.DecodeString(rspString[startIdx:endIdx])
	if err != nil {
		return nil, err
	}
	if len(decoded) < 3 {
		return nil, fmt.Errorf("error from service: %v", rspString)
	}
	return decoded, nil
}

func prettyPrintStatus(rsp []byte) error {
	rspString := string(rsp)
	start := "<?xml"
	startIdx := strings.Index(rspString, start)
	// If we can't find the health data, just assume there was an error.
	if startIdx == -1 {
		return fmt.Errorf("error from service: %v", rspString)
	}
	fmt.Printf("Response (XML):\n%s\n", rspString[startIdx:])
	xml := rsp[startIdx:]
	jsonified, err := xj.Convert(bytes.NewReader(xml))
	if err != nil {
		return err
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(jsonified.Bytes(), &parsed); err != nil {
		return err
	}
	f := colorjson.NewFormatter()
	f.Indent = 2
	s, err := f.Marshal(parsed)
	if err != nil {
		return err
	}
	fmt.Printf("Response (JSON):\n%s\n", string(s))
	return nil
}
