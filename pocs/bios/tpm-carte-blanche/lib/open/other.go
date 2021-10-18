//go:build !windows
// +build !windows

package open

import (
	"io"

	"github.com/google/go-tpm/tpm2"
)

func TPM(pathHint string) (io.ReadWriteCloser, error) {
	path := pathHint
	if path == "" {
		path = "/dev/tpm0"
	}
	return tpm2.OpenTPM(path)
}
