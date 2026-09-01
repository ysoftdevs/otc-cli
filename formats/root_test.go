package formats

import (
	"strings"
	"testing"
)

func TestNewRendererAcceptsSupportedFormats(t *testing.T) {
	formats := []string{"", "table", "json", "yaml"}

	for _, format := range formats {
		if _, err := newRenderer[struct{}](format); err != nil {
			t.Fatalf("newRenderer(%q) returned error: %v", format, err)
		}
	}
}

func TestNewRendererRejectsUnsupportedFormat(t *testing.T) {
	_, err := newRenderer[struct{}]("xml")
	if err == nil {
		t.Fatal("expected error for unsupported output format")
	}
	if !strings.Contains(err.Error(), "supported formats are table, json, yaml") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRejectsUnsupportedFormat(t *testing.T) {
	err := Validate("xml")
	if err == nil {
		t.Fatal("expected error for unsupported output format")
	}
	if !strings.Contains(err.Error(), "supported formats are table, json, yaml") {
		t.Fatalf("unexpected error: %v", err)
	}
}
