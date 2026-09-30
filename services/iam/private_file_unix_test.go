//go:build unix

package iam

import (
	"os"
	"testing"
)

func assertPrivateFilePermissions(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("private file mode = %04o, want 0600", got)
	}
}
