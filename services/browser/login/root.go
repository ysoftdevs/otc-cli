package login

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"otc-cli/config"

	"github.com/chromedp/chromedp"
)

type LoginArgs struct {
	BaseURL    string
	AuthURL    string
	DomainID   string
	Idp        string
	Protocol   string
	Expiration int

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
	return fmt.Sprintf("%s?domain_id=%s&idp=%s&protocol=%s",
		la.BaseURL, la.DomainID, la.Idp, la.Protocol)
}

func getUserDataDir() (string, error) {
	// Get user's home directory for storing cookies
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}

	// Create directory for storing browser data
	userDataDir := filepath.Join(homeDir, ".otc-cli", "browser-data")
	if err := os.MkdirAll(userDataDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create user data directory: %w", err)
	}

	fmt.Printf("Using user data directory: %s\n", userDataDir)
	return userDataDir, nil
}

func BrowserLogin(loginArgs LoginArgs) error {
	userDataDir, err := getUserDataDir()
	if err != nil {
		return err
	}

	// Create Chrome allocator with visible browser
	allocCtx, allocCancel := chromedp.NewExecAllocator(
		context.Background(),
		chromedp.Flag("headless", false),
		chromedp.Flag("disable-gpu", false),
		// chromedp.Flag("no-sandbox", true),
		chromedp.Flag("no-default-browser-check", true),
		chromedp.Flag("no-first-run", true),
		chromedp.Flag("disable-default-apps", true),
		chromedp.Flag("window-size", "800,900"),
		chromedp.UserDataDir(userDataDir),
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
	fmt.Println("Opening managed browser for login...")
	fmt.Println("Waiting for authentication...")

	err := chromedp.Run(ctx,
		chromedp.Navigate(loginArgs.buildURL()),
		chromedp.WaitReady("body", chromedp.ByQuery),
	)
	if err != nil {
		fmt.Printf("Failed to open browser: %v\n", err)
		return "", err
	}

	// Wait for user to complete login and be redirected to console
	fmt.Println("Please complete the login in the opened browser window.")
	fmt.Println("Waiting for redirect to console...")

	err = chromedp.Run(ctx,
		chromedp.WaitVisible("cf_logo", chromedp.ByID),
	)
	if err != nil {
		fmt.Printf("Login timeout or failed: %v\n", err)
		return "", err
	}

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
	var err error

	for range 10 {
		err = chromedp.Run(ctx,
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
			break
		}

		fmt.Println("Retrying to fetch credentials...")
		time.Sleep(2 * time.Second)
	}

	if err != nil {
		fmt.Printf("Failed to fetch credentials: %v\n", err)
		return "", err
	} else {
		fmt.Printf("Credentials received\n")
		return creds, nil
	}
}

func storeCredentials(creds string, loginArgs *LoginArgs) error {
	var credResp STSCredentialResponse
	if err := json.Unmarshal([]byte(creds), &credResp); err != nil {
		return fmt.Errorf("failed to parse credential response: %w", err)
	}

	if credResp.RetInfo != "success" {
		return fmt.Errorf("credential request failed: %s", credResp.RetInfo)
	}

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

func logf(format string, args ...any) {
	fmt.Printf(format+"\n", args...)
}
