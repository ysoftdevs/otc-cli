//go:build windows

package login

// SystemBrowserLogin preserves legacy SSO support on Windows by letting
// chromedp discover an installed Chrome or Edge executable.
func SystemBrowserLogin(loginArgs LoginArgs) error {
	loginArgs.Browser = "managed Chromium"
	return ManagedBrowserLogin(loginArgs)
}
