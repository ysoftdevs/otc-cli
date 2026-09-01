//go:build darwin

package login

import (
	"fmt"
	"net/url"
	"os/exec"
	"strings"
	"time"
)

const safariBundleID = "com.apple.safari"
const otcAuthHost = "auth.otc.t-systems.com"
const otcConsoleOrigin = "https://console.otc.t-systems.com"

type fatalLoginError struct {
	err error
}

func (e fatalLoginError) Error() string {
	return e.err.Error()
}

func (e fatalLoginError) Unwrap() error {
	return e.err
}

func SystemBrowserLogin(loginArgs LoginArgs) error {
	bundleID, err := defaultBrowserBundleID()
	if err != nil {
		return err
	}

	switch bundleID {
	case safariBundleID:
		return SafariLogin(loginArgs)
	default:
		return fmt.Errorf("default browser %q is not supported for legacy credential extraction; configure OIDC login or use Safari as the macOS default browser", bundleID)
	}
}

func SafariLogin(loginArgs LoginArgs) error {
	trustedOrigin, err := safariCredentialOrigin(loginArgs.BaseURL)
	if err != nil {
		return err
	}

	if err := openSafariLoginURL(loginArgs.buildURL()); err != nil {
		return err
	}

	fmt.Println("Opened Safari for login.")
	fmt.Println("Please complete the login in Safari.")
	fmt.Println("Waiting for temporary credentials...")

	creds, err := fetchSafariCredentials(loginArgs.Expiration, 5*time.Minute, trustedOrigin, loginArgs.Debug)
	if err != nil {
		return err
	}

	return storeCredentials(creds, &loginArgs)
}

func openSafariLoginURL(loginURL string) error {
	output, err := exec.Command("open", loginURL).CombinedOutput()
	if err != nil {
		if message := strings.TrimSpace(string(output)); message != "" {
			return fmt.Errorf("failed to open login URL in the macOS default browser: %w: %s", err, message)
		}
		return fmt.Errorf("failed to open login URL in the macOS default browser: %w", err)
	}

	return nil
}

func fetchSafariCredentials(expiration int, timeout time.Duration, trustedOrigin string, debug bool) (string, error) {
	deadline := time.Now().Add(timeout)
	var lastErr error
	printedWaiting := false

	for time.Now().Before(deadline) {
		creds, probe, err := safariCredentialResponse(expiration, trustedOrigin)
		if debug {
			printSafariProbe(probe, err)
		}
		if err == nil {
			if err := validateCredentialResponse(creds); err == nil {
				fmt.Printf("Credentials received\n")
				return creds, nil
			} else {
				lastErr = err
			}
		} else {
			lastErr = err
			if _, ok := err.(fatalLoginError); ok {
				return "", err
			}
		}

		if !printedWaiting {
			fmt.Println("Waiting for login to complete...")
			printedWaiting = true
		}
		time.Sleep(2 * time.Second)
	}

	if lastErr != nil {
		return "", fmt.Errorf("timed out waiting for Safari credentials: %w", lastErr)
	}

	return "", fmt.Errorf("timed out waiting for Safari credentials")
}

func safariCredentialResponse(expiration int, trustedOrigin string) (string, safariProbe, error) {
	javascript := safariCredentialJavaScript(expiration)
	escapedTrustedOrigin := appleScriptString(trustedOrigin)

	script := fmt.Sprintf(`
tell application "Safari"
	if not (exists document 1) then
		error "Safari has no open document"
	end if

	set probeOutput to "COUNT	" & (count of documents) & linefeed
	repeat with documentIndex from 1 to count of documents
		set safariDocument to document documentIndex
		set documentURL to ""
		try
			set documentURL to URL of safariDocument as text
		on error errMsg
			set documentURL to "<url-error: " & errMsg & ">"
		end try

		if documentURL is %s or documentURL starts with (%s & "/") or documentURL starts with (%s & "?") or documentURL starts with (%s & "#") then
			try
				set credentialResponse to do JavaScript %s in safariDocument
			on error errMsg
				set credentialResponse to "appleevent-error	" & errMsg
			end try
		else
			set credentialResponse to "skipped-untrusted"
		end if

		set probeOutput to probeOutput & "DOC	" & documentIndex & "	" & documentURL & "	" & credentialResponse & linefeed
	end repeat

	return probeOutput
end tell
`, escapedTrustedOrigin, escapedTrustedOrigin, escapedTrustedOrigin, escapedTrustedOrigin, appleScriptString(javascript))

	output, err := runAppleScript(script)
	if err != nil {
		hintedErr := safariAutomationHint(err)
		wrappedErr := fmt.Errorf("failed to query Safari for temporary credentials: %w", hintedErr)
		if isFatalSafariAutomationError(hintedErr) {
			return "", safariProbe{}, fatalLoginError{err: wrappedErr}
		}
		return "", safariProbe{}, wrappedErr
	}

	probe := parseSafariProbe(output, trustedOrigin)
	return probe.credentials, probe, nil
}

func safariCredentialJavaScript(expiration int) string {
	return fmt.Sprintf(`
(function() {
	try {
		var xhr = new XMLHttpRequest();
		xhr.open('GET', '/iam/server/aklist?type=sts&duration=%d', false);
		xhr.withCredentials = true;
		xhr.send(null);

		var response = xhr.responseText || '';
		if (response.indexOf('"retinfo"') !== -1 || response.indexOf('"credential"') !== -1) {
			try {
				response = JSON.stringify(JSON.parse(response));
			} catch (parseError) {
			}
			return 'credential\t' + response.length + '\t' + response;
		}
		return 'noncredential\t' + xhr.status + '\t' + response.length + '\t' + (xhr.getResponseHeader('content-type') || '');
	} catch (e) {
		return 'error\t' + ((e && e.name) ? e.name : 'Error') + ': ' + ((e && e.message) ? e.message : String(e));
	}
})()
`, expiration)
}

type safariProbe struct {
	documentCount int
	documents     []safariDocumentProbe
	credentials   string
}

type safariDocumentProbe struct {
	index       string
	url         string
	status      string
	httpStatus  string
	length      string
	contentType string
	errorText   string
}

func parseSafariProbe(output string, trustedOrigin string) safariProbe {
	var probe safariProbe

	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "COUNT\t") {
			fmt.Sscanf(strings.TrimPrefix(line, "COUNT\t"), "%d", &probe.documentCount)
			continue
		}

		if !strings.HasPrefix(line, "DOC\t") {
			continue
		}

		fields := strings.SplitN(line, "\t", 6)
		if len(fields) < 4 {
			continue
		}

		document := safariDocumentProbe{
			index:  fields[1],
			url:    fields[2],
			status: fields[3],
		}

		switch document.status {
		case "credential":
			if len(fields) >= 5 {
				document.length = fields[4]
			}
			if len(fields) == 6 && isSafariTrustedURL(document.url, trustedOrigin) {
				probe.credentials = fields[5]
			}
		case "noncredential":
			if len(fields) >= 5 {
				document.httpStatus = fields[4]
			}
			if len(fields) >= 6 {
				rest := strings.SplitN(fields[5], "\t", 2)
				document.length = rest[0]
				if len(rest) == 2 {
					document.contentType = rest[1]
				}
			}
		case "error", "appleevent-error":
			if len(fields) >= 5 {
				document.errorText = fields[4]
			}
		}

		probe.documents = append(probe.documents, document)
	}

	return probe
}

func safariCredentialOrigin(baseURL string) (string, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil || !strings.EqualFold(parsed.Scheme, "https") || parsed.Host == "" || parsed.User != nil || parsed.Port() != "" {
		return "", fmt.Errorf("failed to derive Safari credential origin from login URL %q", baseURL)
	}

	host := strings.ToLower(parsed.Hostname())
	switch host {
	case otcAuthHost, "console.otc.t-systems.com":
		return otcConsoleOrigin, nil
	default:
		return "", fmt.Errorf("legacy credential extraction in Safari is supported only for OTC console SSO, not login host %q; configure OIDC login instead", parsed.Host)
	}
}

func isSafariTrustedURL(rawURL string, trustedOrigin string) bool {
	parsedURL, err := url.Parse(rawURL)
	if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" || parsedURL.User != nil {
		return false
	}
	parsedOrigin, err := url.Parse(trustedOrigin)
	if err != nil || parsedOrigin.Scheme == "" || parsedOrigin.Host == "" || parsedOrigin.User != nil {
		return false
	}

	return strings.EqualFold(parsedURL.Scheme, parsedOrigin.Scheme) &&
		strings.EqualFold(parsedURL.Host, parsedOrigin.Host)
}

func printSafariProbe(probe safariProbe, probeErr error) {
	if probeErr != nil {
		fmt.Printf("Debug: Safari credential probe error: %v\n", probeErr)
		return
	}

	fmt.Printf("Debug: Safari documents: %d\n", probe.documentCount)
	for _, document := range probe.documents {
		fmt.Printf("Debug: Safari document %s url=%s status=%s", document.index, redactURL(document.url), document.status)
		if document.httpStatus != "" {
			fmt.Printf(" http=%s", document.httpStatus)
		}
		if document.length != "" {
			fmt.Printf(" bytes=%s", document.length)
		}
		if document.contentType != "" {
			fmt.Printf(" content-type=%s", document.contentType)
		}
		if document.errorText != "" {
			fmt.Printf(" error=%s", document.errorText)
		}
		fmt.Println()
	}
}

func redactURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return raw
	}
	parsed.RawQuery = ""
	parsed.ForceQuery = false
	parsed.Fragment = ""
	return parsed.String()
}

func safariAutomationHint(err error) error {
	message := err.Error()
	switch {
	case strings.Contains(message, "Not authorized to send Apple events"):
		return fmt.Errorf("%w; allow this terminal application to control Safari in macOS Privacy & Security > Automation", err)
	case strings.Contains(message, "not allowed") && strings.Contains(message, "JavaScript"):
		return fmt.Errorf("%w; enable Safari Develop > Allow JavaScript from Apple Events", err)
	case strings.Contains(message, "JavaScript") && strings.Contains(message, "Apple Events"):
		return fmt.Errorf("%w; enable Safari Develop > Allow JavaScript from Apple Events", err)
	default:
		return err
	}
}

func isFatalSafariAutomationError(err error) bool {
	message := err.Error()
	return strings.Contains(message, "Allow JavaScript from Apple Events") ||
		strings.Contains(message, "Privacy & Security > Automation")
}

func appleScriptString(value string) string {
	escaped := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value)
	return `"` + escaped + `"`
}

func defaultBrowserBundleID() (string, error) {
	output, err := exec.Command("defaults", "read", "com.apple.LaunchServices/com.apple.launchservices.secure", "LSHandlers").Output()
	if err != nil {
		return "", fmt.Errorf("failed to detect the macOS default browser: %w", err)
	}

	return defaultBrowserBundleIDFromLaunchServices(string(output))
}

func defaultBrowserBundleIDFromLaunchServices(launchServicesHandlers string) (string, error) {
	handlerBlocks := topLevelHandlerBlocks(launchServicesHandlers)
	for _, block := range handlerBlocks {
		if !strings.Contains(block, "LSHandlerURLScheme = https;") {
			continue
		}

		if bundleID := handlerRoleAll(block); bundleID != "" {
			return bundleID, nil
		}
	}

	for _, block := range handlerBlocks {
		if !strings.Contains(block, `LSHandlerContentType = "com.apple.default-app.web-browser";`) {
			continue
		}

		if bundleID := handlerRoleAll(block); bundleID != "" {
			return bundleID, nil
		}
	}

	return "", fmt.Errorf("failed to find the macOS default browser in LaunchServices handlers")
}

func topLevelHandlerBlocks(launchServicesHandlers string) []string {
	var blocks []string
	var current strings.Builder
	depth := 0

	for _, line := range strings.Split(launchServicesHandlers, "\n") {
		opening := strings.Count(line, "{")
		closing := strings.Count(line, "}")

		if depth > 0 {
			current.WriteString(line)
			current.WriteByte('\n')
		}

		depth += opening - closing
		if depth == 0 && current.Len() > 0 {
			blocks = append(blocks, current.String())
			current.Reset()
		}
	}

	return blocks
}

func handlerRoleAll(handlerBlock string) string {
	depth := 1
	for _, line := range strings.Split(handlerBlock, "\n") {
		depth += strings.Count(line, "{")
		depth -= strings.Count(line, "}")

		if depth != 1 || !strings.Contains(line, "LSHandlerRoleAll =") {
			continue
		}

		value := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "LSHandlerRoleAll ="))
		value = strings.TrimSuffix(value, ";")
		value = strings.Trim(value, `"`)
		return value
	}

	return ""
}

func runAppleScript(script string) (string, error) {
	output, err := exec.Command("osascript", "-e", script).Output()
	if err != nil {
		stderr := ""
		if exitErr, ok := err.(*exec.ExitError); ok {
			stderr = strings.TrimSpace(string(exitErr.Stderr))
		}
		if stderr == "" {
			return "", err
		}
		return "", fmt.Errorf("%w: %s", err, stderr)
	}

	return strings.TrimSpace(string(output)), nil
}
