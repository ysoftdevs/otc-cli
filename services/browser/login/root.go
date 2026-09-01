package login

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ysoftdevs/otc-cli/config"

	"github.com/chromedp/chromedp"
)

type LoginArgs struct {
	BaseURL     string
	AuthURL     string
	DomainID    string
	Idp         string
	Protocol    string
	Expiration  int
	Browser     string
	Debug       bool
	DeviceCode  bool
	OIDC        config.OIDCConfig
	browserPath string

	CommonConfig *config.CommonConfig
}

// STSCredentialResponse represents the response from the STS credential endpoint
type STSCredentialResponse struct {
	Data struct {
		Credential STSCredential `json:"credential"`
	} `json:"data"`
	RetInfo string `json:"retinfo"`
}

// STSCredential represents the temporary credentials
type STSCredential struct {
	Access        string `json:"access"`
	Secret        string `json:"secret"`
	ExpiresAt     string `json:"expires_at"`
	SecurityToken string `json:"securitytoken"`
}

func (la LoginArgs) buildURL() string {
	values := url.Values{}
	values.Set("domain_id", la.DomainID)
	values.Set("idp", la.Idp)
	values.Set("protocol", la.Protocol)

	return fmt.Sprintf("%s?%s", la.BaseURL, values.Encode())
}

func getUserDataDir() (string, error) {
	// Get user's home directory for storing cookies
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}

	// Create directory for storing browser data
	configDir := filepath.Join(homeDir, ".otc-cli")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return "", fmt.Errorf("failed to create config directory: %w", err)
	}
	if err := os.Chmod(configDir, 0700); err != nil {
		return "", fmt.Errorf("failed to secure config directory: %w", err)
	}

	userDataDir := filepath.Join(configDir, "browser-data")
	if err := os.MkdirAll(userDataDir, 0700); err != nil {
		return "", fmt.Errorf("failed to create user data directory: %w", err)
	}
	if err := os.Chmod(userDataDir, 0700); err != nil {
		return "", fmt.Errorf("failed to secure user data directory: %w", err)
	}

	fmt.Printf("Using user data directory: %s\n", userDataDir)
	return userDataDir, nil
}

func validateLoginArgs(loginArgs LoginArgs) error {
	var missing []string

	if loginArgs.DeviceCode && !loginArgs.hasOIDC() {
		cloudName := ""
		if loginArgs.CommonConfig != nil {
			cloudName = loginArgs.CommonConfig.CloudName
		}
		return fmt.Errorf("--device-code is supported only for OIDC login; configure an oidc block for cloud %q", cloudName)
	}
	if loginArgs.CommonConfig == nil || loginArgs.CommonConfig.CloudName == "" {
		missing = append(missing, "--cloud")
	}
	if loginArgs.CommonConfig == nil || loginArgs.CommonConfig.ProjectName == "" {
		missing = append(missing, "--project")
	}
	if loginArgs.AuthURL == "" {
		missing = append(missing, "--auth-url")
	}
	if loginArgs.hasOIDC() {
		if loginArgs.OIDC.TenantID == "" {
			missing = append(missing, "oidc.tenant_id")
		}
		if loginArgs.OIDC.ClientID == "" {
			missing = append(missing, "oidc.client_id")
		}
		if loginArgs.OIDC.Idp == "" {
			missing = append(missing, "oidc.idp")
		}
		if loginArgs.DomainID == "" {
			missing = append(missing, "auth.domain_id")
		}
		if len(missing) > 0 {
			return fmt.Errorf("missing required login parameters: %s", strings.Join(missing, ", "))
		}
		if err := validateOIDCAuthURL(loginArgs.AuthURL); err != nil {
			return err
		}
		if loginArgs.DeviceCode && loginArgs.Browser != "" && loginArgs.Browser != "default" {
			return fmt.Errorf("--browser cannot be combined with --device-code")
		}
		return nil
	}
	if loginArgs.BaseURL == "" {
		missing = append(missing, "--url")
	}
	if loginArgs.DomainID == "" {
		missing = append(missing, "--domain-id")
	}
	if loginArgs.Idp == "" {
		missing = append(missing, "--idp")
	}
	if loginArgs.Protocol == "" {
		missing = append(missing, "--protocol")
	}
	if loginArgs.Expiration <= 0 {
		missing = append(missing, "--expiration")
	}

	if len(missing) > 0 {
		return fmt.Errorf("missing required login parameters: %s", strings.Join(missing, ", "))
	}

	return nil
}

func validateOIDCAuthURL(authURL string) error {
	parsed, err := url.Parse(authURL)
	if err != nil || !strings.EqualFold(parsed.Scheme, "https") || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("OIDC authentication URL must be an HTTPS base URL without user information, query, or fragment, got %q", authURL)
	}
	return nil
}

func Login(loginArgs LoginArgs) error {
	if err := validateLoginArgs(loginArgs); err != nil {
		return err
	}

	if loginArgs.hasOIDC() {
		return OIDCLogin(loginArgs)
	}
	if loginArgs.Browser != "" && loginArgs.Browser != "default" {
		return fmt.Errorf("--browser is supported only for OIDC login; configure an oidc block for cloud %q", loginArgs.CommonConfig.CloudName)
	}

	loginArgs.Browser = "default"
	return SystemBrowserLogin(loginArgs)
}

func (la LoginArgs) hasOIDC() bool {
	return la.OIDC.TenantID != "" || la.OIDC.ClientID != "" || la.OIDC.Idp != ""
}

func validateControlledBrowser(browserName string) error {
	name := strings.ToLower(filepath.Base(browserName))
	if isFirefoxBrowserName(name) {
		return fmt.Errorf("browser %q is not supported for legacy automated credential extraction; configure OIDC login or use a Chrome/Chromium-compatible default browser", browserName)
	}
	if isChromiumBrowserName(name) {
		return nil
	}
	return fmt.Errorf("browser %q is not supported for legacy automated credential extraction; configure OIDC login or use a Chrome/Chromium-compatible default browser", browserName)
}

func isChromiumBrowserName(name string) bool {
	chromiumNames := []string{
		"brave",
		"brave-browser",
		"chrome",
		"chromium",
		"chromium-browser",
		"google-chrome",
		"google-chrome-stable",
		"microsoft-edge",
		"microsoft-edge-stable",
		"msedge",
	}
	for _, chromiumName := range chromiumNames {
		if name == chromiumName {
			return true
		}
	}
	return false
}

func isFirefoxBrowserName(name string) bool {
	return strings.Contains(strings.ToLower(filepath.Base(name)), "firefox")
}

func ManagedBrowserLogin(loginArgs LoginArgs) error {
	userDataDir, err := getUserDataDir()
	if err != nil {
		return err
	}

	allocOpts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", false),
		chromedp.Flag("disable-gpu", false),
		chromedp.Flag("no-default-browser-check", true),
		chromedp.Flag("no-first-run", true),
		chromedp.Flag("disable-default-apps", true),
		chromedp.Flag("window-size", "800,900"),
		chromedp.UserDataDir(userDataDir),
	)
	if p := loginArgs.browserPath; p != "" {
		allocOpts = append(allocOpts, chromedp.ExecPath(p))
	} else if p := findChromePath(); p != "" {
		allocOpts = append(allocOpts, chromedp.ExecPath(p))
	}

	// Create Chrome allocator with visible browser
	allocCtx, allocCancel := chromedp.NewExecAllocator(
		context.Background(),
		allocOpts...,
	)
	defer allocCancel()

	// Create Chrome context
	ctx, cancel := chromedp.NewContext(
		allocCtx,
		chromedp.WithLogf(logf),
		//chromedp.WithDebugf(logf),
		//chromedp.WithErrorf(logf),
	)
	defer cancel()

	creds, err := loginInBrowser(ctx, loginArgs)
	chromedp.Cancel(ctx) // Close browser

	if err != nil {
		fmt.Printf("Login failed: %v\n", err)
		return err
	}

	err = storeCredentials(creds, &loginArgs)
	if err != nil {
		fmt.Printf("Failed to update clouds.yaml: %v\n", err)
		return err
	}

	return nil
}

func loginInBrowser(ctx context.Context, loginArgs LoginArgs) (string, error) {
	fmt.Println("Opening controlled browser for login...")
	fmt.Println("Waiting for authentication...")

	err := chromedp.Run(ctx,
		chromedp.Navigate(loginArgs.buildURL()),
		chromedp.WaitReady("body", chromedp.ByQuery),
	)
	if err != nil {
		fmt.Printf("Failed to open browser: %v\n", err)
		return "", err
	}

	fmt.Println("Please complete the login in the opened browser window.")
	fmt.Println("Waiting for temporary credentials...")

	creds, err := fetchTempCredentials(ctx, loginArgs)
	if err != nil {
		fmt.Printf("Failed to fetch credentials: %v\n", err)
		return "", err
	}

	return creds, nil
}

func fetchTempCredentials(ctx context.Context, loginArgs LoginArgs) (string, error) {
	fmt.Println("Fetching credentials...")

	var creds string
	var lastErr error

	deadline := time.Now().Add(5 * time.Minute)
	for time.Now().Before(deadline) {
		err := chromedp.Run(ctx,
			chromedp.Evaluate(fmt.Sprintf(`
						__credentials__ = null;
						fetch('/iam/server/aklist?type=sts&duration=%d', {
							method: 'GET',
							credentials: 'include'
						})
						.then(response => response.text())
						.then(text => { __credentials__ = text; });
					`, loginArgs.Expiration), nil),
			chromedp.Poll("__credentials__", &creds,
				chromedp.WithPollingInterval(time.Second),
				chromedp.WithPollingTimeout(10*time.Second)),
		)

		if err == nil && creds != "" {
			if err := validateCredentialResponse(creds); err == nil {
				fmt.Printf("Credentials received\n")
				return creds, nil
			} else {
				lastErr = err
			}
		} else if err != nil {
			lastErr = err
		}

		fmt.Println("Waiting for login to complete...")
		time.Sleep(2 * time.Second)
	}

	if lastErr != nil {
		return "", fmt.Errorf("timed out waiting for credentials: %w", lastErr)
	}

	return "", fmt.Errorf("timed out waiting for credentials")
}

func storeCredentials(creds string, loginArgs *LoginArgs) error {
	if err := validateCredentialResponse(creds); err != nil {
		return err
	}

	var credResp STSCredentialResponse
	_ = json.Unmarshal([]byte(creds), &credResp)

	commonConfig := loginArgs.CommonConfig
	if err := config.UpdateCloudConfig(commonConfig.CloudName, func(cloud *config.CloudConfig) {
		cloud.SSO.BaseURL = loginArgs.BaseURL
		cloud.SSO.Protocol = loginArgs.Protocol
		cloud.SSO.Idp = loginArgs.Idp
		cloud.SSO.Expiration = loginArgs.Expiration

		cloud.Auth.AuthURL = loginArgs.AuthURL
		cloud.Auth.DomainID = loginArgs.DomainID
		cloud.Auth.AccessKey = credResp.Data.Credential.Access
		cloud.Auth.SecretKey = credResp.Data.Credential.Secret
		cloud.Auth.SecurityToken = credResp.Data.Credential.SecurityToken
		cloud.Auth.DomainID = loginArgs.DomainID
		cloud.Auth.ProjectName = commonConfig.ProjectName

		cloud.AuthType = "aksk"
		cloud.RegionName = commonConfig.Region
	}); err != nil {
		return err
	}
	fmt.Printf("Credentials stored in clouds.yaml under cloud '%s'\n", commonConfig.CloudName)
	return nil
}

func validateCredentialResponse(creds string) error {
	var credResp STSCredentialResponse
	if err := json.Unmarshal([]byte(creds), &credResp); err != nil {
		return fmt.Errorf("failed to parse credential response: %w", err)
	}

	if credResp.RetInfo != "success" {
		return fmt.Errorf("credential request failed: %s", credResp.RetInfo)
	}

	return validateCredentials(credResp.Data.Credential)
}

func validateCredentials(creds STSCredential) error {
	if creds.Access == "" || creds.Secret == "" || creds.SecurityToken == "" {
		return fmt.Errorf("credential response is missing access key, secret key, or security token")
	}

	if creds.ExpiresAt == "" {
		return nil
	}

	expiresAt, err := time.Parse(time.RFC3339, creds.ExpiresAt)
	if err != nil {
		return fmt.Errorf("failed to parse credential expiration %q: %w", creds.ExpiresAt, err)
	}
	if time.Now().After(expiresAt) {
		return fmt.Errorf("credential response is already expired at %s", creds.ExpiresAt)
	}

	return nil
}

func logf(format string, args ...any) {
	fmt.Printf(format+"\n", args...)
}
