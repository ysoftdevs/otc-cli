package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAugmentFromFilesRejectsUnknownCloud(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	configDir := filepath.Join(home, ".config", "openstack")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatalf("failed to create config dir: %v", err)
	}
	cloudsPath := filepath.Join(configDir, "clouds.yaml")
	if err := os.WriteFile(cloudsPath, []byte(`clouds:
  otc-prod-eu-de-prod:
    region_name: eu-de
    auth:
      project_name: eu-de_prod
`), 0600); err != nil {
		t.Fatalf("failed to write clouds.yaml: %v", err)
	}

	cfg := CommonConfig{
		EnvPrefix: "OTC_",
		CloudName: "otc-prod-eu-prod",
	}

	err := cfg.AugmentFromFiles()
	if err == nil {
		t.Fatal("expected error for unknown cloud")
	}
	if !strings.Contains(err.Error(), `cloud "otc-prod-eu-prod" was not found`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAugmentFromFilesLoadsKnownCloud(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	configDir := filepath.Join(home, ".config", "openstack")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatalf("failed to create config dir: %v", err)
	}
	cloudsPath := filepath.Join(configDir, "clouds.yaml")
	if err := os.WriteFile(cloudsPath, []byte(`clouds:
  otc-prod-eu-de-prod:
    region_name: eu-de
    auth:
      project_name: eu-de_prod
`), 0600); err != nil {
		t.Fatalf("failed to write clouds.yaml: %v", err)
	}

	cfg := CommonConfig{
		EnvPrefix: "OTC_",
		CloudName: "otc-prod-eu-de-prod",
	}

	if err := cfg.AugmentFromFiles(); err != nil {
		t.Fatalf("AugmentFromFiles returned error: %v", err)
	}
	if cfg.SelectedCloud == nil {
		t.Fatal("expected selected cloud")
	}
	if cfg.ProjectName != "eu-de_prod" {
		t.Fatalf("unexpected project name: %q", cfg.ProjectName)
	}
}
