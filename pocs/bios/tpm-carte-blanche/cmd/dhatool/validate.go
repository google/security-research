package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"text/template"
)

type Validation struct {
	Cert   []byte
	Nonce  []byte
	Claims []byte
}

type validationBase64 struct {
	Cert   string
	Nonce  string
	Claims string
}

func (v *Validation) Marshal() ([]byte, error) {
	req64 := validationBase64{
		Cert:   base64.StdEncoding.EncodeToString(v.Cert),
		Nonce:  hex.EncodeToString(v.Nonce),
		Claims: base64.StdEncoding.EncodeToString(v.Claims),
	}

	tmp, err := template.New("validation").Parse(`<?xml version="1.0" encoding="utf-8"?><HealthCertificateValidationRequest ProtocolVersion='3' xmlns='http://schemas.microsoft.com/windows/security/healthcertificate/validation/request/v3'><Nonce>{{.Nonce}}</Nonce><Claims>{{.Claims}}</Claims><HealthCertificateBlob>{{.Cert}}</HealthCertificateBlob></HealthCertificateValidationRequest>`)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := tmp.Execute(&buf, req64); err != nil {
		return nil, err
	}

	return buf.Bytes(), err
}
