package cmd

import (
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
