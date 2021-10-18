package main

import (
	"bytes"
	"encoding/base64"
	"text/template"
)

type Request struct {
	Claims []byte
	AIK    []byte
}

type requestBase64 struct {
	Claims string
	AIK    string
}

func (r *Request) Marshal() ([]byte, error) {
	req64 := requestBase64{
		Claims: base64.StdEncoding.EncodeToString(r.Claims),
		AIK:    base64.StdEncoding.EncodeToString(r.AIK),
	}

	tmp, err := template.New("claims").Parse(`<?xml version="1.0" encoding="utf-8"?><HealthCertificateRequest ProtocolVersion="3" xmlns="http://schemas.microsoft.com/windows/security/healthcertificate/request/v3"><Claims>{{.Claims}}</Claims><AIKCertificate>{{.AIK}}</AIKCertificate></HealthCertificateRequest>`)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := tmp.Execute(&buf, req64); err != nil {
		return nil, err
	}

	return buf.Bytes(), err
}
