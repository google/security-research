package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/google/security-research/pocs/bios/tpm-carte-blanche/lib/akscep"
)

func main() {
	os.Exit(mainWithExit())
}

type certifiedAK struct {
	Template    []byte
	Certificate []byte
}

func generateFilename(template []byte) string {
	// Name the file after the first 6 bytes of the hash of the template
	hash := sha256.Sum256(template)
	return fmt.Sprintf("%x.aik", hash[:6])
}

func mainWithExit() int {
	cli, err := akscep.NewClientContext()
	if err != nil {
		fmt.Fprintf(os.Stderr, "creating client context: %v\n", err)
		return -1
	}
	defer cli.Close()
	template, cert, err := cli.GetAKCert()
	if err != nil {
		fmt.Fprintf(os.Stderr, "getting AK cert: %v\n", err)
		return -1
	}

	certified := certifiedAK{
		Template:    template,
		Certificate: cert,
	}

	encoded, err := json.MarshalIndent(certified, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshalling JSON: %v\n", err)
		return -1
	}

	filename := generateFilename(template)
	if err := ioutil.WriteFile(filename, encoded, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "writing file: %v\n", err)
		return -1
	}
	fmt.Printf("Wrote certified AIK to %v.\n", filename)

	return 0
}
