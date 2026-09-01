package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setTestHome(t *testing.T, home string) {
	t.Helper()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
}

func TestAugmentFromFilesDoesNotRejectUnknownCloud(t *testing.T) {
	// A cloud name with no matching clouds.yaml entry is a supported way to
	// carry purely env-based auth (e.g. OTC_AK/OTC_SK) through the CLI, so
	// AugmentFromFiles must not fail here on its own; see RequireCloudFound
	// for the opt-in strict check used when --cloud is passed explicitly.
	home := t.TempDir()
	setTestHome(t, home)

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

	if err := cfg.AugmentFromFiles(); err != nil {
		t.Fatalf("AugmentFromFiles returned error: %v", err)
	}
	if cfg.SelectedCloud != nil {
		t.Fatal("expected no selected cloud for an unknown cloud name")
	}

	err := cfg.RequireCloudFound()
	if err == nil {
		t.Fatal("expected RequireCloudFound to reject an unknown cloud")
	}
	if !strings.Contains(err.Error(), `cloud "otc-prod-eu-prod" was not found`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAugmentFromFilesLoadsKnownCloud(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)

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
