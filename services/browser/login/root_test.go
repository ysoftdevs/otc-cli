package login

import (
	"strings"
	"testing"
	"time"

	"github.com/ysoftdevs/otc-cli/config"
)

func validLoginArgs() LoginArgs {
	return LoginArgs{
		BaseURL:    "https://auth.otc.t-systems.com/authui/federation/websso",
		AuthURL:    "https://iam.eu-de.otc.t-systems.com/v3",
		DomainID:   "domain-id",
		Idp:        "Y_Soft_Entra_ID_PROD",
		Protocol:   "saml",
		Expiration: 3600,
		CommonConfig: &config.CommonConfig{
			CloudName:   "otc-prod",
			ProjectName: "eu-de_prod",
		},
	}
}

func TestBuildURLEscapesQueryParameters(t *testing.T) {
	args := validLoginArgs()
	args.Idp = "Y Soft Entra ID PROD"

	got := args.buildURL()
	want := "https://auth.otc.t-systems.com/authui/federation/websso?domain_id=domain-id&idp=Y+Soft+Entra+ID+PROD&protocol=saml"
	if got != want {
		t.Fatalf("unexpected login URL: %q", got)
	}
}

func TestValidateLoginArgsAcceptsCompleteConfiguration(t *testing.T) {
	if err := validateLoginArgs(validLoginArgs()); err != nil {
		t.Fatalf("validateLoginArgs returned error: %v", err)
	}
}

func TestValidateLoginArgsRejectsMissingSSOParameters(t *testing.T) {
	args := validLoginArgs()
	args.DomainID = ""
	args.Idp = ""

	err := validateLoginArgs(args)
	if err == nil {
		t.Fatal("expected error for missing SSO parameters")
	}
	if !strings.Contains(err.Error(), "--domain-id") || !strings.Contains(err.Error(), "--idp") {
		t.Fatalf("error does not list missing SSO parameters: %v", err)
	}
}

func TestValidateLoginArgsRejectsDeviceCodeForLegacySSO(t *testing.T) {
	args := validLoginArgs()
	args.DeviceCode = true

	err := validateLoginArgs(args)
	if err == nil {
		t.Fatal("expected error for device-code with legacy SSO")
	}
	if !strings.Contains(err.Error(), "supported only for OIDC login") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateLoginArgsRejectsBrowserWithDeviceCode(t *testing.T) {
	args := validLoginArgs()
	args.OIDC = config.OIDCConfig{
		TenantID: "tenant-id",
		ClientID: "client-id",
		Idp:      "oidc-idp",
	}
	args.DeviceCode = true
	args.Browser = "firefox"

	err := validateLoginArgs(args)
	if err == nil {
		t.Fatal("expected error for browser with device-code")
	}
	if !strings.Contains(err.Error(), "cannot be combined") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateLoginArgsRequiresSecureOIDCAuthURL(t *testing.T) {
	for _, authURL := range []string{
		"http://iam.example.test/v3",
		"https://user@iam.example.test/v3",
		"https://iam.example.test/v3?redirect=other",
		"https://iam.example.test/v3#fragment",
		"missing-url",
	} {
		t.Run(authURL, func(t *testing.T) {
			args := validLoginArgs()
			args.AuthURL = authURL
			args.OIDC = config.OIDCConfig{
				TenantID: "tenant-id",
				ClientID: "client-id",
				Idp:      "oidc-idp",
			}

			err := validateLoginArgs(args)
			if err == nil {
				t.Fatal("expected insecure OIDC auth URL to be rejected")
			}
			if !strings.Contains(err.Error(), "must be an HTTPS base URL") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidateLoginArgsAcceptsSecureOIDCConfiguration(t *testing.T) {
	args := validLoginArgs()
	args.BaseURL = ""
	args.Browser = "default"
	args.OIDC = config.OIDCConfig{
		TenantID: "tenant-id",
		ClientID: "client-id",
		Idp:      "oidc-idp",
	}

	if err := validateLoginArgs(args); err != nil {
		t.Fatalf("validateLoginArgs returned error: %v", err)
	}
}

func TestOpenLoginBrowserRejectsBrowserValueWithPathSeparators(t *testing.T) {
	err := openLoginBrowser("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "http://127.0.0.1/otc-cli")
	if err == nil {
		t.Fatal("expected error for browser path")
	}
	if !strings.Contains(err.Error(), "executable name from PATH") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOpenLoginBrowserRejectsMissingBrowserExecutable(t *testing.T) {
	err := openLoginBrowser("otc-browser-that-does-not-exist", "http://127.0.0.1/otc-cli")
	if err == nil {
		t.Fatal("expected error for missing browser executable")
	}
	if !strings.Contains(err.Error(), "failed to find browser executable") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoginRejectsBrowserFlagForLegacySSO(t *testing.T) {
	args := validLoginArgs()
	args.Browser = "firefox"

	err := Login(args)
	if err == nil {
		t.Fatal("expected error for browser flag with legacy SSO")
	}
	if !strings.Contains(err.Error(), "supported only for OIDC login") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateControlledBrowserAcceptsChromiumBrowsers(t *testing.T) {
	browsers := []string{
		"brave-browser",
		"chromium",
		"chromium-browser",
		"google-chrome",
		"google-chrome-stable",
		"microsoft-edge",
	}

	for _, browser := range browsers {
		if err := validateControlledBrowser(browser); err != nil {
			t.Fatalf("validateControlledBrowser(%q) returned error: %v", browser, err)
		}
	}
}

func TestValidateControlledBrowserRejectsFirefox(t *testing.T) {
	err := validateControlledBrowser("firefox")
	if err == nil {
		t.Fatal("expected error for Firefox")
	}
	if !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateCredentialsRequiresTemporarySecrets(t *testing.T) {
	err := validateCredentials(STSCredential{
		Access:        "access",
		Secret:        "secret",
		SecurityToken: "token",
	})
	if err != nil {
		t.Fatalf("validateCredentials returned error: %v", err)
	}
}

func TestValidateCredentialsRejectsMissingSecrets(t *testing.T) {
	err := validateCredentials(STSCredential{
		Access: "access",
		Secret: "secret",
	})
	if err == nil {
		t.Fatal("expected error for missing security token")
	}
}

func TestValidateCredentialsRejectsExpiredCredentials(t *testing.T) {
	err := validateCredentials(STSCredential{
		Access:        "access",
		Secret:        "secret",
		SecurityToken: "token",
		ExpiresAt:     time.Now().Add(-time.Hour).Format(time.RFC3339),
	})
	if err == nil {
		t.Fatal("expected error for expired credentials")
	}
}

func TestValidateCredentialResponseAcceptsValidResponse(t *testing.T) {
	response := `{
		"retinfo": "success",
		"data": {
			"credential": {
				"access": "access",
				"secret": "secret",
				"securitytoken": "token"
			}
		}
	}`

	if err := validateCredentialResponse(response); err != nil {
		t.Fatalf("validateCredentialResponse returned error: %v", err)
	}
}

func TestValidateCredentialResponseRejectsHTML(t *testing.T) {
	if err := validateCredentialResponse("<html>login</html>"); err == nil {
		t.Fatal("expected error for non-JSON response")
	}
}
