package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPersistentPreRunRejectsFormatBeforeLoadingCloud(t *testing.T) {
	originalFormat := format
	originalConfig := *commonConfig
	t.Cleanup(func() {
		format = originalFormat
		*commonConfig = originalConfig
	})

	format = "xml"
	commonConfig.CloudName = "cloud-that-does-not-exist"

	err := rootCmd.PersistentPreRunE(rootCmd, nil)
	if err == nil {
		t.Fatal("expected unsupported output format to be rejected")
	}
	if !strings.Contains(err.Error(), "unsupported output format") {
		t.Fatalf("format validation did not run before cloud loading: %v", err)
	}
}

func setRootTestHome(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	configDir := filepath.Join(home, ".config", "openstack")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatalf("failed to create config dir: %v", err)
	}
}

func TestPersistentPreRunAllowsUnknownCloudFromEnv(t *testing.T) {
	setRootTestHome(t)

	originalFormat := format
	originalConfig := *commonConfig
	t.Cleanup(func() {
		format = originalFormat
		*commonConfig = originalConfig
	})

	format = "table"
	// Simulates a cloud name supplied via OTC_CLOUD rather than --cloud:
	// the --cloud flag itself was never touched, so it stays "unchanged".
	commonConfig.CloudName = "ci-automation"

	if err := rootCmd.PersistentPreRunE(rootCmd, nil); err != nil {
		t.Fatalf("expected env-supplied unknown cloud name to be allowed, got: %v", err)
	}
}

func TestPersistentPreRunRejectsUnknownCloudFromFlag(t *testing.T) {
	setRootTestHome(t)

	originalFormat := format
	originalConfig := *commonConfig
	cloudFlag := rootCmd.PersistentFlags().Lookup("cloud")
	originalChanged := cloudFlag.Changed
	t.Cleanup(func() {
		format = originalFormat
		*commonConfig = originalConfig
		cloudFlag.Changed = originalChanged
	})

	format = "table"
	// ParseFlags mirrors what cobra's Execute() does before running the
	// PersistentPreRunE hooks: it merges persistent flags into cmd.Flags()
	// and marks "cloud" as Changed, which is what the code under test checks.
	if err := rootCmd.ParseFlags([]string{"-c", "cloud-that-does-not-exist"}); err != nil {
		t.Fatalf("failed to parse --cloud flag: %v", err)
	}

	err := rootCmd.PersistentPreRunE(rootCmd, nil)
	if err == nil {
		t.Fatal("expected explicit --cloud with an unknown name to be rejected")
	}
	if !strings.Contains(err.Error(), `cloud "cloud-that-does-not-exist" was not found`) {
		t.Fatalf("unexpected error: %v", err)
	}
}
