package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/chromedp/chromedp"
)

type loginArgs struct {
	baseURL  string
	domainID string
	idp      string
	protocol string
	cloudId  string
}

func parseLoginArgs(args []string) loginArgs {
	// Default values
	la := loginArgs{
		baseURL:  "https://auth.otc.t-systems.com/authui/federation/websso",
		domainID: "99370f87daf946bba4938c30330cbafd",
		idp:      "Y_Soft_Entra_ID_PROD",
		protocol: "saml",
		cloudId:  "otc-prod",
	}

	// Parse arguments (if provided)
	// Usage: login [domain_id] [idp] [protocol]
	if len(args) > 0 {
		la.domainID = args[0]
	}
	if len(args) > 1 {
		la.idp = args[1]
	}
	if len(args) > 2 {
		la.protocol = args[2]
	}

	return la
}

func (la loginArgs) buildURL() string {
	return fmt.Sprintf("%s?domain_id=%s&idp=%s&protocol=%s",
		la.baseURL, la.domainID, la.idp, la.protocol)
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

func runLogin(args []string) error {
	loginArgs := parseLoginArgs(args)

	userDataDir, err := getUserDataDir()
	if err != nil {
		return err
	}

	// Create Chrome allocator with visible browser
	allocCtx, allocCancel := chromedp.NewExecAllocator(
		context.Background(),
		chromedp.Flag("headless", false),
		chromedp.Flag("disable-gpu", false),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("no-default-browser-check", true),
		chromedp.Flag("no-first-run", true),
		chromedp.Flag("disable-default-apps", true),
		//chromedp.Flag("window-size", "800,900"),
		chromedp.UserDataDir(userDataDir),
	)
	defer allocCancel()

	// Create Chrome context
	ctx, _ := chromedp.NewContext(
		allocCtx,
		chromedp.WithLogf(logf),
		//chromedp.WithDebugf(logf),
		//chromedp.WithErrorf(logf),
	)
	defer chromedp.Cancel(ctx)

	fmt.Println("Opening managed browser for login...")
	fmt.Println("Waiting for authentication...")

	err = chromedp.Run(ctx,
		chromedp.Navigate(loginArgs.buildURL()),
		chromedp.WaitReady("body", chromedp.ByQuery),
	)
	if err != nil {
		fmt.Printf("Failed to open browser: %v\n", err)
		return err
	}

	// Wait for user to complete login and be redirected to console
	fmt.Println("Please complete the login in the opened browser window.")
	fmt.Println("Waiting for redirect to console...")

	err = chromedp.Run(ctx,
		chromedp.WaitVisible("cf_logo", chromedp.ByID),
	)
	if err != nil {
		fmt.Printf("Login timeout or failed: %v\n", err)
		return err
	}

	creds, err := fetchTempCredentials(ctx)
	if err != nil {
		fmt.Printf("Failed to fetch credentials: %v\n", err)
		return err
	}

	err = UpdateCloudsWithSTSCredentials(loginArgs.cloudId, loginArgs.domainID, creds)
	if err != nil {
		fmt.Printf("Failed to update clouds.yaml: %v\n", err)
		return err
	}

	// for true {

	// 	select {
	// 	case <-redirected:
	// 		fetchTempCredentials(ctx, errors, credentials)

	// 	case creds := <-credentials:
	// 		// Update clouds.yaml with the credentials
	// 		if err := UpdateCloudsWithSTSCredentials(loginArgs.cloudId, loginArgs.domainID, creds); err != nil {
	// 			fmt.Printf("Failed to update clouds.yaml: %v\n", err)
	// 			return err
	// 		}

	// 	case err := <-errors:
	// 		fmt.Printf("Error during login process: %v\n", err)
	// 		return err
	// 	case <-time.After(10 * time.Minute):
	// 		fmt.Println("Login timed out after 10 minutes.")
	// 		//cancel()
	// 		return fmt.Errorf("login timed out")

	// 	case <-ctx.Done():
	// 		fmt.Println("Browser closed")
	// 		return fmt.Errorf("Browser closed before login completed")
	// 	}
	// }

	return nil
}

func fetchTempCredentials(ctx context.Context) (string, error) {
	fmt.Println("Fetching credentials...")

	var creds string
	err := chromedp.Run(ctx,
		chromedp.Evaluate(`
					__credentials__ = null;
					fetch('https://console.otc.t-systems.com/iam/server/aklist?type=sts&duration=54000', {
						method: 'GET',
						credentials: 'include'
					})
					.then(response => response.text())
					.then(text => { __credentials__ = text; });
				`, nil),
		chromedp.Poll("__credentials__", &creds, chromedp.WithPollingInterval(time.Second)),
	)
	if err != nil {
		fmt.Printf("Failed to fetch credentials: %v\n", err)
		return "", err
	} else {
		fmt.Printf("Credentials received\n")
		return creds, nil
	}
}

func logf(format string, args ...any) {
	fmt.Printf(format+"\n", args...)
}
