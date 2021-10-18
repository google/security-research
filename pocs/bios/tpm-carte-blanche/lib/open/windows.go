//go:build windows
// +build windows

package open

import (
	"fmt"
	"io"

	"github.com/google/go-tpm/tpm2"
)

func TPM(pathHint string) (io.ReadWriteCloser, error) {
	if pathHint != "" {
		return nil, fmt.Errorf("TPM on Windows uses TBS, which does not take a path")
	}
	return tpm2.OpenTPM()
}
