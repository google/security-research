package main

import (
	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

func ReplayLog(tcgLog []byte, alg tpm2.Algorithm) error {
	tpm, err := tpm2.OpenTPM("/dev/tpmrm0")
	if err != nil {
		return err
	}
	defer tpm.Close()

	log, err := attest.ParseEventLog(tcgLog)
	if err != nil {
		return err
	}
	for _, e := range log.Events(attest.HashAlg(alg)) {
		if e.Index < 0 || e.Index > 23 {
			continue
		}
		err := tpm2.PCRExtend(tpm, tpmutil.Handle(e.Index), alg, e.Digest, "")
		if err != nil {
			return err
		}
	}
	return nil
}
