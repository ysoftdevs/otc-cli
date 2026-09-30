//go:build unix || windows

package iam

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateFileCreationAndExclusiveProtection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	file, err := createPrivateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("secret"); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	assertPrivateFilePermissions(t, path)
	if other, err := createPrivateFile(path); err == nil {
		other.Close()
		t.Fatal("existing private file was overwritten")
	} else if !errors.Is(err, os.ErrExist) {
		t.Fatalf("second create error = %v, want file exists", err)
	}
	contents, err := os.ReadFile(path)
	if err != nil || string(contents) != "secret" {
		t.Fatalf("existing private file changed: %q, %v", contents, err)
	}
}
