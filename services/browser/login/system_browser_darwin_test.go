//go:build darwin

package login

import (
	"strings"
	"testing"
)

func TestDefaultBrowserBundleIDFromLaunchServicesPrefersHTTPSHandler(t *testing.T) {
	handlers := `
(
        {
        LSHandlerContentType = "com.apple.default-app.web-browser";
        LSHandlerRoleAll = "com.apple.safari";
    },
        {
        LSHandlerRoleAll = "com.apple.SafariTechnologyPreview";
        LSHandlerURLScheme = http;
    },
        {
        LSHandlerRoleAll = "com.apple.safari";
        LSHandlerURLScheme = https;
    }
)
`

	got, err := defaultBrowserBundleIDFromLaunchServices(handlers)
	if err != nil {
		t.Fatalf("defaultBrowserBundleIDFromLaunchServices returned error: %v", err)
	}
	if got != safariBundleID {
		t.Fatalf("unexpected browser bundle ID: %q", got)
	}
}

func TestDefaultBrowserBundleIDFromLaunchServicesFallsBackToWebBrowserContentType(t *testing.T) {
	handlers := `
(
        {
        LSHandlerContentType = "com.apple.default-app.web-browser";
        LSHandlerRoleAll = "com.apple.safari";
    }
)
`

	got, err := defaultBrowserBundleIDFromLaunchServices(handlers)
	if err != nil {
		t.Fatalf("defaultBrowserBundleIDFromLaunchServices returned error: %v", err)
	}
	if got != safariBundleID {
		t.Fatalf("unexpected browser bundle ID: %q", got)
	}
}

func TestDefaultBrowserBundleIDFromLaunchServicesRejectsMissingBrowser(t *testing.T) {
	_, err := defaultBrowserBundleIDFromLaunchServices(`({ LSHandlerURLScheme = mailto; LSHandlerRoleAll = "com.apple.mail"; })`)
	if err == nil {
		t.Fatal("expected error for missing browser handler")
	}
	if !strings.Contains(err.Error(), "failed to find") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSafariAutomationHintAddsJavaScriptHint(t *testing.T) {
	err := safariAutomationHint(assertableError("execution error: JavaScript execution through Apple Events is not allowed"))
	if !strings.Contains(err.Error(), "Allow JavaScript from Apple Events") {
		t.Fatalf("missing Safari JavaScript hint: %v", err)
	}
}

func TestIsFatalSafariAutomationError(t *testing.T) {
	err := safariAutomationHint(assertableError("Safari got an error: You must enable 'Allow JavaScript from Apple Events'"))
	if !isFatalSafariAutomationError(err) {
		t.Fatalf("expected fatal Safari automation error: %v", err)
	}
}

func TestAppleScriptStringEscapesQuotesAndBackslashes(t *testing.T) {
	got := appleScriptString(`https://example.test/?q="value"\next`)
	want := `"https://example.test/?q=\"value\"\\next"`
	if got != want {
		t.Fatalf("unexpected AppleScript string: %q", got)
	}
}

func TestParseSafariProbeExtractsCredentialsWithoutLoggingThem(t *testing.T) {
	output := strings.Join([]string{
		"COUNT\t2",
		"DOC\t1\thttps://login.example.test/callback?token=secret\tnoncredential\t200\t128\ttext/html",
		`DOC	2	https://console.example.test/console	credential	97	{"retinfo":"success","data":{"credential":{"access":"a","secret":"s","securitytoken":"t"}}}`,
	}, "\n")

	probe := parseSafariProbe(output, "https://console.example.test")
	if probe.documentCount != 2 {
		t.Fatalf("unexpected document count: %d", probe.documentCount)
	}
	if len(probe.documents) != 2 {
		t.Fatalf("unexpected document probe count: %d", len(probe.documents))
	}
	if probe.credentials == "" {
		t.Fatal("expected credentials to be extracted")
	}
	if probe.documents[0].httpStatus != "200" || probe.documents[0].length != "128" || probe.documents[0].contentType != "text/html" {
		t.Fatalf("unexpected noncredential probe: %#v", probe.documents[0])
	}
	if probe.documents[1].status != "credential" || probe.documents[1].length != "97" {
		t.Fatalf("unexpected credential probe: %#v", probe.documents[1])
	}
}

func TestParseSafariProbeIgnoresCredentialsFromUntrustedDocuments(t *testing.T) {
	trustedCredentials := `{"retinfo":"success","data":{"credential":{"access":"trusted","secret":"s","securitytoken":"t"}}}`
	untrustedCredentials := `{"retinfo":"success","data":{"credential":{"access":"evil","secret":"s","securitytoken":"t"}}}`
	output := strings.Join([]string{
		"COUNT\t2",
		"DOC\t1\thttps://console.example.test/console\tcredential\t97\t" + trustedCredentials,
		"DOC\t2\thttps://console.example.test.evil/iam/server/aklist\tcredential\t97\t" + untrustedCredentials,
	}, "\n")

	probe := parseSafariProbe(output, "https://console.example.test")
	if probe.credentials != trustedCredentials {
		t.Fatalf("unexpected credentials: %q", probe.credentials)
	}
}

func TestParseSafariProbeRejectsOnlyUntrustedCredentials(t *testing.T) {
	output := strings.Join([]string{
		"COUNT\t1",
		`DOC	1	https://console.example.test.evil/iam/server/aklist	credential	97	{"retinfo":"success","data":{"credential":{"access":"evil","secret":"s","securitytoken":"t"}}}`,
	}, "\n")

	probe := parseSafariProbe(output, "https://console.example.test")
	if probe.credentials != "" {
		t.Fatalf("expected untrusted credentials to be ignored, got %q", probe.credentials)
	}
}

func TestSafariCredentialOriginDerivesConsoleOriginFromOTCAuthURL(t *testing.T) {
	got, err := safariCredentialOrigin("https://auth.otc.t-systems.com/authui/federation/websso")
	if err != nil {
		t.Fatalf("safariCredentialOrigin returned error: %v", err)
	}
	if got != "https://console.otc.t-systems.com" {
		t.Fatalf("unexpected origin: %q", got)
	}
}

func TestSafariCredentialOriginRejectsUnknownHost(t *testing.T) {
	_, err := safariCredentialOrigin("https://auth.example.test/authui/federation/websso")
	if err == nil {
		t.Fatal("expected unknown host to be rejected")
	}
	if !strings.Contains(err.Error(), "configure OIDC login") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSafariCredentialOriginRequiresStandardHTTPSOrigin(t *testing.T) {
	untrusted := []string{
		"http://console.otc.t-systems.com/console",
		"https://console.otc.t-systems.com:8443/console",
		"https://user@console.otc.t-systems.com/console",
	}
	for _, baseURL := range untrusted {
		t.Run(baseURL, func(t *testing.T) {
			if _, err := safariCredentialOrigin(baseURL); err == nil {
				t.Fatalf("expected origin to be rejected: %s", baseURL)
			}
		})
	}
}

func TestIsSafariTrustedURLRequiresSameOrigin(t *testing.T) {
	trustedOrigin := "https://console.otc.t-systems.com"
	trusted := []string{
		"https://console.otc.t-systems.com",
		"https://console.otc.t-systems.com/",
		"https://console.otc.t-systems.com/console?token=redacted",
	}
	for _, rawURL := range trusted {
		if !isSafariTrustedURL(rawURL, trustedOrigin) {
			t.Fatalf("expected trusted URL: %s", rawURL)
		}
	}

	untrusted := []string{
		"https://console.otc.t-systems.com.evil/console",
		"https://console.otc.t-systems.com@evil.test/console",
		"https://user@console.otc.t-systems.com/console",
		"https://console.otc.t-systems.com:8443/console",
		"http://console.otc.t-systems.com/console",
		"https://auth.otc.t-systems.com/authui/federation/websso",
		"missing value",
	}
	for _, rawURL := range untrusted {
		if isSafariTrustedURL(rawURL, trustedOrigin) {
			t.Fatalf("expected untrusted URL: %s", rawURL)
		}
	}
}

func TestRedactURLRemovesQueryAndFragment(t *testing.T) {
	got := redactURL("https://auth.example.test/path?token=secret#fragment")
	want := "https://auth.example.test/path"
	if got != want {
		t.Fatalf("unexpected redacted URL: %q", got)
	}
}

type assertableError string

func (e assertableError) Error() string {
	return string(e)
}
