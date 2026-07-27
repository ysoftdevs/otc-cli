package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSaveCloudsYAMLReplacesExistingFileWithMode0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clouds.yaml")
	if err := os.WriteFile(path, []byte("old contents"), 0644); err != nil {
		t.Fatalf("failed to create clouds.yaml: %v", err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatalf("failed to set initial permissions: %v", err)
	}

	clouds := &CloudsYAML{
		Clouds: map[string]CloudConfig{
			"otc-dev": {
				Auth: AuthConfig{
					Token: "short-lived-token",
				},
				AuthType: "token",
			},
		},
	}
	if err := SaveCloudsYAML(path, clouds); err != nil {
		t.Fatalf("SaveCloudsYAML returned error: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("failed to stat clouds.yaml: %v", err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("unexpected clouds.yaml permissions: got %04o, want 0600", got)
	}

	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read clouds.yaml: %v", err)
	}
	if !strings.Contains(string(saved), "short-lived-token") {
		t.Fatalf("saved clouds.yaml does not contain the token: %q", saved)
	}
}

func TestSaveCloudsYAMLWritesThroughSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "clouds.real.yaml")
	link := filepath.Join(dir, "clouds.yaml")

	if err := os.WriteFile(target, []byte("clouds: {}\n"), 0600); err != nil {
		t.Fatalf("failed to create target: %v", err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	clouds := &CloudsYAML{
		Clouds: map[string]CloudConfig{
			"otc-dev": {Auth: AuthConfig{Token: "short-lived-token"}},
		},
	}
	if err := SaveCloudsYAML(link, clouds); err != nil {
		t.Fatalf("SaveCloudsYAML returned error: %v", err)
	}

	info, err := os.Lstat(link)
	if err != nil {
		t.Fatalf("failed to lstat link: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("symlink was replaced by a regular file")
	}

	saved, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("failed to read symlink target: %v", err)
	}
	if !strings.Contains(string(saved), "short-lived-token") {
		t.Fatalf("symlink target was not updated: %q", saved)
	}
}

func TestWriteFileAtomicallyPreservesExistingFileWhenRenameFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "clouds.yaml")
	original := []byte("original contents")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatalf("failed to create clouds.yaml: %v", err)
	}

	renameErr := errors.New("forced rename failure")
	err := writeFileAtomically(path, []byte("replacement contents"), 0600, func(string, string) error {
		return renameErr
	})
	if !errors.Is(err, renameErr) {
		t.Fatalf("expected rename error, got %v", err)
	}

	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read original clouds.yaml: %v", err)
	}
	if string(saved) != string(original) {
		t.Fatalf("clouds.yaml changed after failed rename: got %q, want %q", saved, original)
	}

	tempFiles, err := filepath.Glob(filepath.Join(dir, ".clouds.yaml.tmp-*"))
	if err != nil {
		t.Fatalf("failed to search for temporary files: %v", err)
	}
	if len(tempFiles) != 0 {
		t.Fatalf("temporary files were not cleaned up: %v", tempFiles)
	}
}
