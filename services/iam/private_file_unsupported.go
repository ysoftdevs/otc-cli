//go:build !unix && !windows

package iam

import (
	"fmt"
	"os"
)

func createPrivateFile(string) (*os.File, error) {
	return nil, fmt.Errorf("private IAM files are not supported on this platform")
}
