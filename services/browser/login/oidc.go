package login

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/ysoftdevs/otc-cli/config"
)

const (
	oidcCallbackPath          = "/otc-cli"
	oidcHTTPTimeout           = 30 * time.Second
	oidcCallbackTimeout       = 5 * time.Minute
	oidcServerShutdownTimeout = 2 * time.Second
	oidcMaxResponseBytes      = 1 << 20
)

type deviceCodeResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	Message         string `json:"message"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

type entraTokenResponse struct {
	TokenType        string `json:"token_type"`
	AccessToken      string `json:"access_token"`
	IDToken          string `json:"id_token"`
	RefreshToken     string `json:"refresh_token"`
	ExpiresIn        int    `json:"expires_in"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

type scopedTokenResponse struct {
	Token struct {
		ExpiresAt string `json:"expires_at"`
		Project   struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"project"`
	} `json:"token"`
}

type oidcCallbackResult struct {
	code string
	err  error
}

type oidcCallbackServer interface {
	Shutdown(context.Context) error
	Close() error
}

func OIDCLogin(loginArgs LoginArgs) error {
	httpClient := newOIDCHTTPClient(oidcHTTPTimeout)
	scopes := loginArgs.OIDC.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}

	var idToken string
	var err error
	if loginArgs.DeviceCode {
		idToken, err = entraIDTokenWithDeviceCode(httpClient, loginArgs.OIDC.TenantID, loginArgs.OIDC.ClientID, scopes)
	} else {
		idToken, err = entraIDTokenWithBrowser(httpClient, loginArgs.OIDC.TenantID, loginArgs.OIDC.ClientID, scopes, loginArgs.Browser)
	}
	if err != nil {
		return err
	}
	if loginArgs.Debug {
		printIDTokenDebug(idToken)
	}

	// OTC Keystone validates the ID token signature, issuer, audience, and
	// mapping rules during OS-FEDERATION exchange; otc only forwards it there.
	unscopedToken, err := otcUnscopedToken(httpClient, loginArgs.AuthURL, loginArgs.OIDC.Idp, idToken)
	if err != nil {
		return err
	}

	scopedToken, expiresAt, err := otcScopedToken(httpClient, loginArgs.AuthURL, unscopedToken, loginArgs.CommonConfig.ProjectName, loginArgs.DomainID)
	if err != nil {
		return err
	}

	if err := storeOIDCToken(scopedToken, expiresAt, &loginArgs); err != nil {
		return err
	}

	return nil
}

// entraIDTokenWithDeviceCode signs in without a local browser or callback
// listener. It remains an interactive user flow intended for headless hosts,
// not unattended CI.
func entraIDTokenWithDeviceCode(httpClient *http.Client, tenantID, clientID string, scopes []string) (string, error) {
	values := url.Values{}
	values.Set("client_id", clientID)
	values.Set("scope", strings.Join(scopes, " "))

	tokenEndpoint := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenantID)
	resp, err := httpClient.PostForm(fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/devicecode", tenantID), values)
	if err != nil {
		return "", fmt.Errorf("failed to start Entra device-code login: %w", err)
	}
	defer resp.Body.Close()

	body, err := readOIDCResponseBody(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read Entra device-code response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Errorf("failed to start Entra device-code login: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var device deviceCodeResponse
	if err := json.Unmarshal(body, &device); err != nil {
		return "", fmt.Errorf("failed to parse Entra device-code response: %w", err)
	}
	if device.DeviceCode == "" {
		return "", fmt.Errorf("device-code response from Entra did not contain device_code")
	}

	if device.Message != "" {
		fmt.Println(device.Message)
	} else {
		fmt.Printf("Open %s and enter code %s\n", device.VerificationURI, device.UserCode)
	}

	interval := time.Duration(device.Interval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}
	deadline := time.Now().Add(time.Duration(device.ExpiresIn) * time.Second)
	if device.ExpiresIn <= 0 {
		deadline = time.Now().Add(15 * time.Minute)
	}

	for time.Now().Before(deadline) {
		time.Sleep(interval)

		values := url.Values{}
		values.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
		values.Set("client_id", clientID)
		values.Set("device_code", device.DeviceCode)

		token, err := postEntraToken(httpClient, tokenEndpoint, values)
		if err != nil {
			return "", err
		}
		switch token.Error {
		case "":
			if token.IDToken == "" {
				return "", fmt.Errorf("token response from Entra did not contain id_token")
			}
			return token.IDToken, nil
		case "authorization_pending":
			continue
		case "slow_down":
			interval += 5 * time.Second
			continue
		default:
			return "", fmt.Errorf("device-code login via Entra failed: %s: %s", token.Error, token.ErrorDescription)
		}
	}

	return "", fmt.Errorf("timed out waiting for Entra device-code login")
}

func entraIDTokenWithBrowser(httpClient *http.Client, tenantID, clientID string, scopes []string, browser string) (string, error) {
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return "", fmt.Errorf("failed to start local login callback listener: %w", err)
	}
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port
	redirectURI := fmt.Sprintf("http://localhost:%d%s", port, oidcCallbackPath)
	state, err := randomURLToken(32)
	if err != nil {
		return "", err
	}
	codeVerifier, err := randomURLToken(64)
	if err != nil {
		return "", err
	}
	codeChallenge := pkceChallenge(codeVerifier)

	resultCh := make(chan oidcCallbackResult, 1)
	server := &http.Server{
		Handler:           oidcCallbackHandler(state, resultCh),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			sendOIDCCallbackResult(resultCh, oidcCallbackResult{err: err})
		}
	}()
	defer func() { _ = stopOIDCCallbackServer(server) }()

	authURL := entraAuthorizeURL(tenantID, clientID, redirectURI, scopes, state, codeChallenge)

	// Always print the URL: xdg-open exits 0 even when it cannot reach a
	// browser, so a silent hand-off would leave a headless host with no way to
	// reach the login page and no indication that anything went wrong.
	fmt.Printf("Sign in to Entra at:\n\n  %s\n\n", authURL)
	if err := openLoginBrowser(browser, authURL); err != nil {
		fmt.Printf("Could not open a browser automatically: %v\n", err)
		fmt.Println("Open the URL above manually to continue.")
	}
	fmt.Printf("Waiting for the login callback on %s ...\n", redirectURI)
	fmt.Println("On a machine without a browser, cancel and run 'otc login --device-code' instead.")

	var result oidcCallbackResult
	select {
	case result = <-resultCh:
	case <-time.After(oidcCallbackTimeout):
		return "", fmt.Errorf("timed out waiting for Entra browser login callback")
	}
	if result.err != nil {
		return "", result.err
	}
	if err := stopOIDCCallbackServer(server); err != nil {
		fmt.Printf("Warning: %v\n", err)
	}

	values := url.Values{}
	values.Set("grant_type", "authorization_code")
	values.Set("client_id", clientID)
	values.Set("code", result.code)
	values.Set("redirect_uri", redirectURI)
	values.Set("code_verifier", codeVerifier)
	values.Set("scope", strings.Join(scopes, " "))

	tokenEndpoint := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenantID)
	token, err := postEntraToken(httpClient, tokenEndpoint, values)
	if err != nil {
		return "", err
	}
	if token.Error != "" {
		return "", fmt.Errorf("authorization-code exchange with Entra failed: %s: %s", token.Error, token.ErrorDescription)
	}
	if token.IDToken == "" {
		return "", fmt.Errorf("token response from Entra did not contain id_token")
	}
	return token.IDToken, nil
}

func oidcCallbackHandler(expectedState string, resultCh chan<- oidcCallbackResult) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(oidcCallbackPath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if got := r.URL.Query().Get("state"); got != expectedState {
			http.Error(w, "invalid login state", http.StatusBadRequest)
			return
		}
		if authErr := r.URL.Query().Get("error"); authErr != "" {
			description := r.URL.Query().Get("error_description")
			http.Error(w, "login failed", http.StatusBadRequest)
			sendOIDCCallbackResult(resultCh, oidcCallbackResult{
				err: fmt.Errorf("browser login via Entra failed: %s: %s", authErr, description),
			})
			return
		}
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "missing authorization code", http.StatusBadRequest)
			sendOIDCCallbackResult(resultCh, oidcCallbackResult{
				err: fmt.Errorf("callback from Entra did not contain an authorization code"),
			})
			return
		}

		fmt.Fprintln(w, "Entra sign-in received. Return to the terminal to complete OTC login.")
		sendOIDCCallbackResult(resultCh, oidcCallbackResult{code: code})
	})
	return mux
}

func sendOIDCCallbackResult(resultCh chan<- oidcCallbackResult, result oidcCallbackResult) {
	select {
	case resultCh <- result:
	default:
	}
}

func stopOIDCCallbackServer(server oidcCallbackServer) error {
	ctx, cancel := context.WithTimeout(context.Background(), oidcServerShutdownTimeout)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		if closeErr := server.Close(); closeErr != nil {
			return fmt.Errorf("failed to stop local login callback listener gracefully: %v; force close also failed: %w", err, closeErr)
		}
		return fmt.Errorf("failed to stop local login callback listener gracefully; listener was force closed: %w", err)
	}
	return nil
}

func entraAuthorizeURL(tenantID, clientID, redirectURI string, scopes []string, state, codeChallenge string) string {
	values := url.Values{}
	values.Set("client_id", clientID)
	values.Set("response_type", "code")
	values.Set("redirect_uri", redirectURI)
	values.Set("response_mode", "query")
	values.Set("scope", strings.Join(scopes, " "))
	values.Set("state", state)
	values.Set("code_challenge", codeChallenge)
	values.Set("code_challenge_method", "S256")
	return fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/authorize?%s", tenantID, values.Encode())
}

func newOIDCHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func postEntraToken(httpClient *http.Client, endpoint string, values url.Values) (entraTokenResponse, error) {
	resp, err := httpClient.PostForm(endpoint, values)
	if err != nil {
		return entraTokenResponse{}, fmt.Errorf("failed to call Entra token endpoint: %w", err)
	}
	defer resp.Body.Close()

	body, err := readOIDCResponseBody(resp.Body)
	if err != nil {
		return entraTokenResponse{}, fmt.Errorf("failed to read Entra token response: %w", err)
	}

	var token entraTokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		return entraTokenResponse{}, fmt.Errorf("failed to parse Entra token response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		if token.Error != "" {
			return token, nil
		}
		return entraTokenResponse{}, fmt.Errorf("token endpoint of Entra returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return token, nil
}

func readOIDCResponseBody(body io.Reader) ([]byte, error) {
	limited := io.LimitReader(body, oidcMaxResponseBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(data) > oidcMaxResponseBytes {
		return nil, fmt.Errorf("OIDC HTTP response exceeds %d bytes", oidcMaxResponseBytes)
	}
	return data, nil
}

func otcUnscopedToken(httpClient *http.Client, authURL, idp, idToken string) (string, error) {
	endpoint := fmt.Sprintf("%s/OS-FEDERATION/identity_providers/%s/protocols/oidc/auth", strings.TrimRight(authURL, "/"), url.PathEscape(idp))
	req, err := http.NewRequest(http.MethodPost, endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+idToken)

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to exchange Entra ID token for OTC unscoped token: %w", err)
	}
	defer resp.Body.Close()

	body, err := readOIDCResponseBody(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read OTC OIDC token exchange response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Errorf("OTC OIDC token exchange failed: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	token := resp.Header.Get("X-Subject-Token")
	if token == "" {
		return "", fmt.Errorf("OTC OIDC token exchange did not return X-Subject-Token")
	}
	return token, nil
}

func otcScopedToken(httpClient *http.Client, authURL, unscopedToken, projectName, domainID string) (string, string, error) {
	request := map[string]any{
		"auth": map[string]any{
			"identity": map[string]any{
				"methods": []string{"token"},
				"token": map[string]any{
					"id": unscopedToken,
				},
			},
			"scope": map[string]any{
				"project": map[string]any{
					"name": projectName,
					"domain": map[string]any{
						"id": domainID,
					},
				},
			},
		},
	}

	body, err := json.Marshal(request)
	if err != nil {
		return "", "", err
	}

	endpoint := fmt.Sprintf("%s/auth/tokens", strings.TrimRight(authURL, "/"))
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(string(body)))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("failed to scope OTC token to project %q: %w", projectName, err)
	}
	defer resp.Body.Close()

	responseBody, err := readOIDCResponseBody(resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("failed to read OTC project scope response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", "", fmt.Errorf("failed to scope OTC token to project %q: HTTP %d: %s", projectName, resp.StatusCode, strings.TrimSpace(string(responseBody)))
	}

	token := resp.Header.Get("X-Subject-Token")
	if token == "" {
		return "", "", fmt.Errorf("OTC project scope response did not return X-Subject-Token")
	}

	var scoped scopedTokenResponse
	_ = json.Unmarshal(responseBody, &scoped)
	return token, scoped.Token.ExpiresAt, nil
}

func storeOIDCToken(scopedToken, expiresAt string, loginArgs *LoginArgs) error {
	commonConfig := loginArgs.CommonConfig
	if err := config.UpdateCloudConfig(commonConfig.CloudName, func(cloud *config.CloudConfig) {
		cloud.OIDC = loginArgs.OIDC

		cloud.Auth.AuthURL = loginArgs.AuthURL
		cloud.Auth.DomainID = loginArgs.DomainID
		cloud.Auth.ProjectName = commonConfig.ProjectName
		cloud.Auth.Token = scopedToken
		cloud.Auth.AccessKey = ""
		cloud.Auth.SecretKey = ""
		cloud.Auth.SecurityToken = ""
		cloud.Auth.Password = ""

		cloud.AuthType = "token"
		cloud.RegionName = commonConfig.Region
	}); err != nil {
		return err
	}

	if expiresAt != "" {
		fmt.Printf("OIDC token stored in clouds.yaml under cloud '%s' (expires at %s)\n", commonConfig.CloudName, expiresAt)
	} else {
		fmt.Printf("OIDC token stored in clouds.yaml under cloud '%s'\n", commonConfig.CloudName)
	}
	return nil
}

func openLoginBrowser(browser, loginURL string) error {
	if browser == "" || browser == "default" || browser == "system" {
		return openDefaultBrowser(loginURL)
	}
	if strings.ContainsAny(browser, `/\`) {
		return fmt.Errorf("browser must be default or an executable name from PATH, got %q", browser)
	}
	if runtime.GOOS == "darwin" && isMacOSApplicationBrowserName(browser) {
		return runBrowserLauncher(exec.Command("open", "-a", macOSApplicationName(browser), loginURL))
	}
	path, err := exec.LookPath(browser)
	if err != nil {
		return fmt.Errorf("failed to find browser executable %q in PATH: %w", browser, err)
	}
	return startBrowserProcess(exec.Command(path, loginURL))
}

func openDefaultBrowser(loginURL string) error {
	switch runtime.GOOS {
	case "darwin":
		return runBrowserLauncher(exec.Command("open", loginURL))
	case "linux":
		return runBrowserLauncher(exec.Command("xdg-open", loginURL))
	case "windows":
		return runBrowserLauncher(exec.Command("rundll32", "url.dll,FileProtocolHandler", loginURL))
	default:
		return fmt.Errorf("default browser login is not implemented for %s", runtime.GOOS)
	}
}

// runBrowserLauncher runs a launcher such as open or xdg-open, which hands the
// URL over and exits immediately, so waiting for it surfaces launch failures
// instead of leaving a zombie behind. Note that xdg-open still reports success
// on a host with no browser, which is why the caller prints the URL as well.
func runBrowserLauncher(cmd *exec.Cmd) error {
	output, err := cmd.CombinedOutput()
	if err != nil {
		if message := strings.TrimSpace(string(output)); message != "" {
			return fmt.Errorf("%s failed: %w: %s", cmd.Args[0], err, message)
		}
		return fmt.Errorf("%s failed: %w", cmd.Args[0], err)
	}
	return nil
}

// startBrowserProcess starts a browser binary that keeps running for the whole
// browsing session, so it is reaped in the background rather than waited for.
func startBrowserProcess(cmd *exec.Cmd) error {
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start browser %q: %w", cmd.Path, err)
	}
	go func() { _ = cmd.Wait() }()
	return nil
}

func isMacOSApplicationBrowserName(browser string) bool {
	switch strings.ToLower(browser) {
	case "safari", "firefox", "chrome", "google-chrome", "chromium", "brave", "brave-browser", "microsoft-edge", "edge":
		return true
	default:
		return false
	}
}

func macOSApplicationName(browser string) string {
	switch strings.ToLower(browser) {
	case "safari":
		return "Safari"
	case "firefox":
		return "Firefox"
	case "chrome", "google-chrome":
		return "Google Chrome"
	case "chromium":
		return "Chromium"
	case "brave", "brave-browser":
		return "Brave Browser"
	case "microsoft-edge", "edge":
		return "Microsoft Edge"
	default:
		return browser
	}
}

func randomURLToken(size int) (string, error) {
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func printIDTokenDebug(idToken string) {
	header, payload, err := decodeIDTokenDebug(idToken)
	if err != nil {
		fmt.Printf("Debug: failed to decode Entra ID token claims: %v\n", err)
		return
	}
	fmt.Printf("Debug: Entra ID token header alg=%v kid=%v typ=%v x5t=%v\n", header["alg"], header["kid"], header["typ"], header["x5t"])
	fmt.Printf("Debug: Entra ID token claims iss=%v aud=%v tid=%v oid=%v preferred_username=%v email=%v roles=%v scp=%v exp=%v\n",
		payload["iss"],
		payload["aud"],
		payload["tid"],
		payload["oid"],
		payload["preferred_username"],
		payload["email"],
		payload["roles"],
		payload["scp"],
		payload["exp"],
	)
}

func decodeIDTokenDebug(idToken string) (map[string]any, map[string]any, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, nil, fmt.Errorf("expected JWT with 3 parts, got %d", len(parts))
	}

	header, err := decodeJWTPart(parts[0])
	if err != nil {
		return nil, nil, fmt.Errorf("header: %w", err)
	}
	payload, err := decodeJWTPart(parts[1])
	if err != nil {
		return nil, nil, fmt.Errorf("payload: %w", err)
	}
	return header, payload, nil
}

func decodeJWTPart(part string) (map[string]any, error) {
	raw, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		return nil, err
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil, err
	}
	return decoded, nil
}
