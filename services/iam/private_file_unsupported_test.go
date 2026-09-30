//go:build !unix && !windows

package iam

import "testing"

func assertPrivateFilePermissions(t *testing.T, _ string) {
	t.Helper()
	t.Fatal("private IAM files are not supported on this platform")
}
