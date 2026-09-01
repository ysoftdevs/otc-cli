package login

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestEntraAuthorizeURLIncludesStateAndPKCE(t *testing.T) {
	rawURL := entraAuthorizeURL(
		"tenant-id",
		"client-id",
		"http://localhost:12345/otc-cli",
		[]string{"openid", "profile", "email"},
		"state-value",
		"challenge-value",
	)

	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("failed to parse authorization URL: %v", err)
	}
	if parsed.Scheme != "https" || parsed.Host != "login.microsoftonline.com" {
		t.Fatalf("unexpected authorization endpoint: %s", parsed)
	}
	if parsed.Path != "/tenant-id/oauth2/v2.0/authorize" {
		t.Fatalf("unexpected authorization path: %q", parsed.Path)
	}

	query := parsed.Query()
	expected := map[string]string{
		"client_id":             "client-id",
		"response_type":         "code",
		"redirect_uri":          "http://localhost:12345/otc-cli",
		"response_mode":         "query",
		"scope":                 "openid profile email",
		"state":                 "state-value",
		"code_challenge":        "challenge-value",
		"code_challenge_method": "S256",
	}
	for key, value := range expected {
		if got := query.Get(key); got != value {
			t.Fatalf("unexpected %s query value: got %q, want %q", key, got, value)
		}
	}
}

func TestOIDCCallbackHandlerReturnsAuthorizationCode(t *testing.T) {
	resultCh := make(chan oidcCallbackResult, 1)
	handler := oidcCallbackHandler("expected-state", resultCh)
	request := httptest.NewRequest(http.MethodGet, oidcCallbackPath+"?state=expected-state&code=authorization-code", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("unexpected callback status: %d", response.Code)
	}
	body := response.Body.String()
	if !strings.Contains(body, "Return to the terminal") {
		t.Fatalf("callback response does not describe the remaining step: %q", body)
	}
	if strings.Contains(body, "OTC login finished") {
		t.Fatalf("callback response reports OTC success before token exchange: %q", body)
	}

	result := <-resultCh
	if result.err != nil {
		t.Fatalf("unexpected callback error: %v", result.err)
	}
	if result.code != "authorization-code" {
		t.Fatalf("unexpected authorization code: %q", result.code)
	}
}

func TestOIDCCallbackHandlerRejectsInvalidState(t *testing.T) {
	resultCh := make(chan oidcCallbackResult, 1)
	handler := oidcCallbackHandler("expected-state", resultCh)
	request := httptest.NewRequest(http.MethodGet, oidcCallbackPath+"?state=wrong-state&code=authorization-code", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("unexpected callback status: %d", response.Code)
	}
	select {
	case result := <-resultCh:
		t.Fatalf("invalid state aborted the legitimate login flow: %#v", result)
	case <-time.After(20 * time.Millisecond):
	}
}

func TestOIDCCallbackHandlerDoesNotBlockOnDuplicateCallback(t *testing.T) {
	resultCh := make(chan oidcCallbackResult, 1)
	resultCh <- oidcCallbackResult{code: "first-code"}
	handler := oidcCallbackHandler("expected-state", resultCh)
	request := httptest.NewRequest(http.MethodGet, oidcCallbackPath+"?state=expected-state&code=duplicate-code", nil)
	response := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		handler.ServeHTTP(response, request)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("duplicate callback blocked while reporting its result")
	}
}

func TestStopOIDCCallbackServerForceClosesAfterShutdownFailure(t *testing.T) {
	server := &callbackServerStub{
		shutdownErr: errors.New("shutdown timed out"),
	}

	err := stopOIDCCallbackServer(server)
	if err == nil {
		t.Fatal("expected graceful shutdown failure to be reported")
	}
	if !server.closeCalled {
		t.Fatal("expected listener to be force closed after graceful shutdown failure")
	}
	if !strings.Contains(err.Error(), "listener was force closed") {
		t.Fatalf("unexpected shutdown error: %v", err)
	}
}

func TestStopOIDCCallbackServerReportsForceCloseFailure(t *testing.T) {
	server := &callbackServerStub{
		shutdownErr: errors.New("shutdown timed out"),
		closeErr:    errors.New("close failed"),
	}

	err := stopOIDCCallbackServer(server)
	if err == nil {
		t.Fatal("expected callback listener cleanup failure")
	}
	if !strings.Contains(err.Error(), "force close also failed") {
		t.Fatalf("unexpected shutdown error: %v", err)
	}
}

func TestPostEntraTokenHonorsHTTPTimeout(t *testing.T) {
	httpClient := newOIDCHTTPClient(20 * time.Millisecond)
	httpClient.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		<-request.Context().Done()
		return nil, request.Context().Err()
	})

	started := time.Now()
	_, err := postEntraToken(httpClient, "https://login.example.test/token", url.Values{})
	if err == nil {
		t.Fatal("expected token request to time out")
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("token request ignored configured timeout: %s", elapsed)
	}
}

func TestOIDCHTTPClientDoesNotFollowRedirects(t *testing.T) {
	var targetCalled atomic.Bool
	httpClient := newOIDCHTTPClient(time.Second)
	httpClient.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Host == "target.example.test" {
			targetCalled.Store(true)
			return jsonResponse(request, http.StatusOK, nil, `{"id_token":"unexpected-token"}`), nil
		}
		headers := http.Header{}
		headers.Set("Location", "https://target.example.test/token")
		return jsonResponse(request, http.StatusFound, headers, `{}`), nil
	})

	_, _ = postEntraToken(httpClient, "https://login.example.test/token", url.Values{})
	if targetCalled.Load() {
		t.Fatal("OIDC HTTP client followed a redirect to another origin")
	}
}

func TestReadOIDCResponseBodyRejectsOversizedResponse(t *testing.T) {
	body := strings.NewReader(strings.Repeat("x", oidcMaxResponseBytes+1))
	if _, err := readOIDCResponseBody(body); err == nil {
		t.Fatal("expected oversized response to be rejected")
	}
}

func TestOTCTokenExchangeRequests(t *testing.T) {
	var unscopedRequestSeen bool
	var scopedRequestSeen bool

	httpClient := newOIDCHTTPClient(time.Second)
	httpClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/v3/OS-FEDERATION/identity_providers/oidc-idp/protocols/oidc/auth":
			unscopedRequestSeen = true
			if r.Method != http.MethodPost {
				t.Errorf("unexpected unscoped method: %s", r.Method)
			}
			if got := r.Header.Get("Authorization"); got != "Bearer entra-id-token" {
				t.Errorf("unexpected authorization header: %q", got)
			}
			headers := http.Header{}
			headers.Set("X-Subject-Token", "unscoped-token")
			return jsonResponse(r, http.StatusCreated, headers, `{}`), nil
		case "/v3/auth/tokens":
			scopedRequestSeen = true
			if r.Method != http.MethodPost {
				t.Errorf("unexpected scoped method: %s", r.Method)
			}
			if got := r.Header.Get("Content-Type"); got != "application/json" {
				t.Errorf("unexpected content type: %q", got)
			}

			var request struct {
				Auth struct {
					Identity struct {
						Token struct {
							ID string `json:"id"`
						} `json:"token"`
					} `json:"identity"`
					Scope struct {
						Project struct {
							Name   string `json:"name"`
							Domain struct {
								ID string `json:"id"`
							} `json:"domain"`
						} `json:"project"`
					} `json:"scope"`
				} `json:"auth"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Errorf("failed to decode scoped request: %v", err)
			}
			if request.Auth.Identity.Token.ID != "unscoped-token" {
				t.Errorf("unexpected unscoped token: %q", request.Auth.Identity.Token.ID)
			}
			if request.Auth.Scope.Project.Name != "eu-de_dev" {
				t.Errorf("unexpected project: %q", request.Auth.Scope.Project.Name)
			}
			if request.Auth.Scope.Project.Domain.ID != "domain-id" {
				t.Errorf("unexpected domain ID: %q", request.Auth.Scope.Project.Domain.ID)
			}

			headers := http.Header{}
			headers.Set("X-Subject-Token", "scoped-token")
			return jsonResponse(r, http.StatusCreated, headers, `{"token":{"expires_at":"2026-07-28T17:03:48Z","project":{"id":"project-id","name":"eu-de_dev"}}}`), nil
		default:
			return jsonResponse(r, http.StatusNotFound, nil, `{}`), nil
		}
	})

	unscopedToken, err := otcUnscopedToken(httpClient, "https://iam.example.test/v3", "oidc-idp", "entra-id-token")
	if err != nil {
		t.Fatalf("otcUnscopedToken returned error: %v", err)
	}
	if unscopedToken != "unscoped-token" {
		t.Fatalf("unexpected unscoped token: %q", unscopedToken)
	}

	scopedToken, expiresAt, err := otcScopedToken(httpClient, "https://iam.example.test/v3", unscopedToken, "eu-de_dev", "domain-id")
	if err != nil {
		t.Fatalf("otcScopedToken returned error: %v", err)
	}
	if scopedToken != "scoped-token" {
		t.Fatalf("unexpected scoped token: %q", scopedToken)
	}
	if expiresAt != "2026-07-28T17:03:48Z" {
		t.Fatalf("unexpected token expiration: %q", expiresAt)
	}
	if !unscopedRequestSeen || !scopedRequestSeen {
		t.Fatalf("missing token exchange requests: unscoped=%t scoped=%t", unscopedRequestSeen, scopedRequestSeen)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func jsonResponse(request *http.Request, status int, headers http.Header, body string) *http.Response {
	if headers == nil {
		headers = http.Header{}
	}
	headers.Set("Content-Type", "application/json")
	return &http.Response{
		StatusCode: status,
		Header:     headers,
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    request,
	}
}

type callbackServerStub struct {
	shutdownErr error
	closeErr    error
	closeCalled bool
}

func (server *callbackServerStub) Shutdown(context.Context) error {
	return server.shutdownErr
}

func (server *callbackServerStub) Close() error {
	server.closeCalled = true
	return server.closeErr
}
