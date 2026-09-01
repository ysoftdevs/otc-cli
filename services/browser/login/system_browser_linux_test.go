//go:build linux

package login

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseDesktopExecReturnsExecutableName(t *testing.T) {
	got := parseDesktopExec("google-chrome-stable %U")
	if got != "google-chrome-stable" {
		t.Fatalf("unexpected executable: %q", got)
	}
}

func TestParseDesktopExecPreservesExecutablePath(t *testing.T) {
	got := parseDesktopExec("/usr/bin/chromium --new-window %U")
	if got != "/usr/bin/chromium" {
		t.Fatalf("unexpected executable: %q", got)
	}
}

func TestParseDesktopExecSkipsFieldCodes(t *testing.T) {
	got := parseDesktopExec("%U chromium-browser")
	if got != "chromium-browser" {
		t.Fatalf("unexpected executable: %q", got)
	}
}

func TestSystemBrowserLoginRejectsDefaultFirefox(t *testing.T) {
	dataHome := t.TempDir()
	applicationsDir := filepath.Join(dataHome, "applications")
	if err := os.MkdirAll(applicationsDir, 0755); err != nil {
		t.Fatalf("failed to create applications dir: %v", err)
	}
	desktopPath := filepath.Join(applicationsDir, "firefox.desktop")
	if err := os.WriteFile(desktopPath, []byte("[Desktop Entry]\nExec=firefox %u\n"), 0644); err != nil {
		t.Fatalf("failed to write desktop entry: %v", err)
	}

	t.Setenv("XDG_DATA_HOME", dataHome)
	t.Setenv("PATH", t.TempDir())

	defaultBrowserDesktopIDFunc = func() (string, error) {
		return "firefox.desktop", nil
	}
	t.Cleanup(func() {
		defaultBrowserDesktopIDFunc = defaultBrowserDesktopID
	})

	err := SystemBrowserLogin(validLoginArgs())
	if err == nil {
		t.Fatal("expected error for default Firefox")
	}
	if !strings.Contains(err.Error(), `default browser "firefox" is not supported`) {
		t.Fatalf("unexpected error: %v", err)
	}
}
