//go:build unix

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveCloudsYAMLSetsMode0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clouds.yaml")
	if err := os.WriteFile(path, []byte("old contents"), 0644); err != nil {
		t.Fatalf("failed to create clouds.yaml: %v", err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatalf("failed to set initial permissions: %v", err)
	}

	if err := SaveCloudsYAML(path, &CloudsYAML{Clouds: map[string]CloudConfig{}}); err != nil {
		t.Fatalf("SaveCloudsYAML returned error: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("failed to stat clouds.yaml: %v", err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("unexpected clouds.yaml permissions: got %04o, want 0600", got)
	}
}
