package iam

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	golangsdk "github.com/opentelekomcloud/gophertelekomcloud"
)

func TestIAMConstructorBlocksAuthenticationRedirects(t *testing.T) {
	tests := []struct {
		name    string
		request string
		opts    func(string) golangsdk.AuthOptionsProvider
		check   func(*testing.T, *http.Request)
	}{
		{
			name:    "cached token",
			request: "GET /v3/auth/tokens",
			opts: func(endpoint string) golangsdk.AuthOptionsProvider {
				return golangsdk.AuthOptions{IdentityEndpoint: endpoint, TokenID: "cached-token-sentinel"}
			},
			check: func(t *testing.T, r *http.Request) {
				t.Helper()
				if r.Header.Get("X-Auth-Token") != "cached-token-sentinel" || r.Header.Get("X-Subject-Token") != "cached-token-sentinel" {
					t.Error("initial token inspection must carry both token headers")
				}
			},
		},
		{
			name:    "password",
			request: "POST /v3/auth/tokens",
			opts: func(endpoint string) golangsdk.AuthOptionsProvider {
				return golangsdk.AuthOptions{
					IdentityEndpoint: endpoint, Username: "fixture-user",
					DomainName: "fixture-domain", Password: "password-sentinel",
				}
			},
			check: func(t *testing.T, r *http.Request) {
				t.Helper()
				body, err := io.ReadAll(r.Body)
				if err != nil || !strings.Contains(string(body), "password-sentinel") {
					t.Error("initial password authentication did not reach the trusted endpoint")
				}
			},
		},
		{
			name:    "signed access key",
			request: "GET /v3/auth/catalog",
			opts: func(endpoint string) golangsdk.AuthOptionsProvider {
				return golangsdk.AKSKAuthOptions{
					IdentityEndpoint: endpoint, AccessKey: "access-key-sentinel", SecretKey: "secret-key-sentinel",
					SecurityToken: "security-token-sentinel", ProjectId: "project-1", DomainID: "account-1",
				}
			},
			check: func(t *testing.T, r *http.Request) {
				t.Helper()
				if !strings.HasPrefix(r.Header.Get("Authorization"), "SDK-HMAC-SHA256 ") || r.Header.Get("X-Security-Token") != "security-token-sentinel" {
					t.Error("initial access key authentication must carry its signature and security token")
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var leaked, initial atomic.Int32
			untrusted := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				leaked.Add(1)
				w.WriteHeader(http.StatusForbidden)
			}))
			t.Cleanup(untrusted.Close)
			trusted := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				initial.Add(1)
				if got := r.Method + " " + r.URL.Path; got != test.request {
					t.Errorf("initial request = %q, want %q", got, test.request)
				}
				test.check(t, r)
				http.Redirect(w, r, untrusted.URL+r.URL.Path, http.StatusTemporaryRedirect)
			}))
			t.Cleanup(trusted.Close)

			service, err := newAuthenticatedService(test.opts(trusted.URL + "/v3"))
			if err == nil || service != nil {
				t.Fatal("constructor accepted an authentication redirect to another host")
			}
			if initial.Load() != 1 || leaked.Load() != 0 {
				t.Fatalf("authentication requests: trusted=%d, untrusted=%d; want 1 and 0", initial.Load(), leaked.Load())
			}
		})
	}
}

func TestIAMConstructorScopesCachedProjectTokenOnce(t *testing.T) {
	var inspections, exchanges atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v3/auth/tokens" || r.Header.Get("X-Auth-Token") != "cached-project-token" {
			t.Errorf("unexpected constructor request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		switch r.Method {
		case http.MethodGet:
			inspections.Add(1)
			if r.Header.Get("X-Subject-Token") != "cached-project-token" {
				t.Error("constructor inspected a different token")
			}
			fmt.Fprint(w, projectTokenMetadata)
		case http.MethodPost:
			exchanges.Add(1)
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode token exchange: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			want := map[string]any{"auth": map[string]any{
				"identity": map[string]any{"methods": []any{"token"}, "token": map[string]any{"id": "cached-project-token"}},
				"scope":    map[string]any{"domain": map[string]any{"id": "account-1"}},
			}}
			if !reflect.DeepEqual(body, want) {
				t.Error("constructor did not exchange the cached token for the project's account")
			}
			w.Header().Set("X-Subject-Token", "iam-domain-token")
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, `{"token":{"domain":{"id":"account-1"}}}`)
		default:
			t.Errorf("unexpected authentication method %s", r.Method)
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	t.Cleanup(server.Close)
	opts := golangsdk.AuthOptions{IdentityEndpoint: server.URL + "/v3", TokenID: "cached-project-token"}
	service, err := newAuthenticatedService(opts)
	if err != nil {
		t.Fatal(err)
	}
	if inspections.Load() != 1 || exchanges.Load() != 1 {
		t.Fatalf("token requests: inspections=%d, exchanges=%d; want 1 each", inspections.Load(), exchanges.Load())
	}
	if service.client.Token() != "iam-domain-token" || service.projectToken != opts.TokenID || opts.TokenID != "cached-project-token" {
		t.Error("constructor did not isolate the domain token from the original project token")
	}
	if service.client.DomainID != "account-1" || service.client.ProjectID != "" || service.client.ReauthFunc != nil {
		t.Error("constructor retained project scope or project reauthentication")
	}
}

func TestIAMConstructorErrorsDoNotEchoCredentials(t *testing.T) {
	for _, method := range []string{"password", "token", "exchange"} {
		t.Run(method, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if method == "exchange" && r.Method == http.MethodGet {
					fmt.Fprint(w, projectTokenMetadata)
					return
				}
				w.WriteHeader(http.StatusForbidden)
				fmt.Fprint(w, `{"error":{"message":"echoed-credential-sentinel"}}`)
			}))
			defer server.Close()
			opts := golangsdk.AuthOptions{IdentityEndpoint: server.URL + "/v3", TokenID: "test-token"}
			if method == "password" {
				opts.TokenID = ""
				opts.Username = "user"
				opts.Password = "password"
				opts.DomainName = "domain"
			}
			_, err := newAuthenticatedService(opts)
			if err == nil || strings.Contains(err.Error(), "echoed-credential-sentinel") {
				t.Fatalf("authentication error echoed server response: %v", err)
			}
		})
	}
}
