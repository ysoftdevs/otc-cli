package iam

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	golangsdk "github.com/opentelekomcloud/gophertelekomcloud"
)

const projectTokenMetadata = `{"token":{"project":{"id":"project-1","domain":{"id":"account-1"}},"user":{"id":"user-1","domain":{"id":"user-home-account"}}}}`

func TestEnsureDomainTokenUsesProjectAccountAndKeepsProjectCredentials(t *testing.T) {
	cachedAuth := golangsdk.AuthOptions{TokenID: "cached-project-token"}
	otherProjectClient := &golangsdk.ProviderClient{TokenID: cachedAuth.TokenID}
	var requests []string
	service, _ := testService(t, func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		switch r.Method + " " + r.URL.Path {
		case "GET /v3/auth/tokens":
			if r.Header.Get("X-Auth-Token") != cachedAuth.TokenID || r.Header.Get("X-Subject-Token") != cachedAuth.TokenID {
				t.Error("token inspection must authenticate with and inspect the configured project token")
			}
			w.Header().Set("X-Subject-Token", cachedAuth.TokenID)
			fmt.Fprint(w, projectTokenMetadata)
		case "POST /v3/auth/tokens":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode exchange request: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			want := map[string]any{"auth": map[string]any{
				"identity": map[string]any{"methods": []any{"token"}, "token": map[string]any{"id": cachedAuth.TokenID}},
				"scope":    map[string]any{"domain": map[string]any{"id": "account-1"}},
			}}
			if !reflect.DeepEqual(body, want) {
				t.Errorf("exchange must use only token identity and the project's account: got %#v", body)
			}
			w.Header().Set("X-Subject-Token", "iam-domain-token")
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, `{"token":{"domain":{"id":"account-1"}}}`)
		case "GET /v3/groups":
			if r.Header.Get("X-Auth-Token") != "iam-domain-token" {
				t.Error("IAM request did not use the exchanged domain token")
			}
			fmt.Fprint(w, `{"groups":[{"id":"group-1"}]}`)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	service.client.SetToken(cachedAuth.TokenID)
	service.client.ProjectID = "project-1"
	// The SDK can populate this from user.domain, which differs from the
	// resource account and must not become the requested IAM scope.
	service.client.DomainID = "user-home-account"
	service.client.ReauthFunc = func() error {
		t.Error("the previous project authentication must not be retried")
		return fmt.Errorf("unexpected project authentication")
	}
	service.client.EndpointLocator = func(golangsdk.EndpointOpts) (string, error) {
		t.Error("IAM exchange must use the configured identity endpoint")
		return "", fmt.Errorf("unexpected catalog lookup")
	}

	if err := service.ensureDomainToken(); err != nil {
		t.Fatal(err)
	}
	groups, err := service.ListGroups("", "")
	if err != nil || len(groups) != 1 || groups[0]["id"] != "group-1" {
		t.Fatalf("IAM read after exchange failed: groups=%v err=%v", groups, err)
	}
	if service.client.Token() != "iam-domain-token" || service.client.ProjectID != "" || service.client.DomainID != "account-1" {
		t.Error("IAM provider did not adopt the returned domain scope")
	}
	if service.client.ReauthFunc != nil {
		t.Error("old project reauthentication could silently restore the wrong scope")
	}
	if cachedAuth.TokenID != "cached-project-token" || otherProjectClient.Token() != "cached-project-token" {
		t.Error("IAM exchange changed credentials used by project services")
	}
	wantRequests := []string{"GET /v3/auth/tokens", "POST /v3/auth/tokens", "GET /v3/groups"}
	if !reflect.DeepEqual(requests, wantRequests) {
		t.Fatalf("unexpected request sequence: %v", requests)
	}
}

func TestEnsureDomainTokenReusesDomainToken(t *testing.T) {
	var requests []string
	service, _ := testService(t, func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		if r.Method != http.MethodGet || r.Header.Get("X-Auth-Token") != "test-token" {
			t.Errorf("domain token must be reused for GET requests: %s %s", r.Method, r.URL)
		}
		switch r.URL.Path {
		case "/v3/auth/tokens":
			w.Header().Set("X-Subject-Token", "test-token")
			fmt.Fprint(w, `{"token":{"domain":{"id":"account-1"}}}`)
		case "/v3/groups":
			fmt.Fprint(w, `{"groups":[]}`)
		default:
			t.Errorf("unexpected request %s", r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	if err := service.ensureDomainToken(); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ListGroups("", ""); err != nil {
		t.Fatal(err)
	}
	if service.client.Token() != "test-token" || !reflect.DeepEqual(requests, []string{"GET /v3/auth/tokens", "GET /v3/groups"}) {
		t.Fatalf("existing domain token was unnecessarily exchanged: %v", requests)
	}
}

func TestEnsureDomainTokenPreservesAKSKAuthentication(t *testing.T) {
	requests := 0
	service, _ := testService(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodGet || r.URL.Path != "/v3/groups" {
			t.Errorf("AK/SK must not inspect or exchange bearer tokens: %s %s", r.Method, r.URL)
		}
		if auth := r.Header.Get("Authorization"); !strings.HasPrefix(auth, "SDK-HMAC-SHA256 ") || !strings.Contains(auth, "test-access-key") {
			t.Error("IAM request lost AK/SK authentication")
		}
		if r.Header.Get("X-Auth-Token") != "" || r.Header.Get("X-Security-Token") != "temporary-security-token" || r.Header.Get("X-Project-Id") != "project-1" {
			t.Error("IAM request changed signed temporary credential headers")
		}
		fmt.Fprint(w, `{"groups":[]}`)
	})
	service.client.SetToken("")
	aksk := golangsdk.AKSKAuthOptions{
		AccessKey:     "test-access-key",
		SecretKey:     "test-secret-key",
		SecurityToken: "temporary-security-token",
		ProjectId:     "project-1",
	}
	service.client.AKSKAuthOptions = aksk
	if err := service.ensureDomainToken(); err != nil {
		t.Fatal(err)
	}
	if requests != 0 {
		t.Fatal("AK/SK authentication triggered token requests")
	}
	if _, err := service.ListGroups("", ""); err != nil {
		t.Fatal(err)
	}
	if requests != 1 || !reflect.DeepEqual(service.client.AKSKOptions(), aksk) {
		t.Error("AK/SK credentials or IAM request count changed")
	}
}

func TestEnsureDomainTokenRejectsFailedOrInvalidExchange(t *testing.T) {
	tests := []struct {
		name   string
		status int
		token  string
		body   string
	}{
		{"forbidden", http.StatusForbidden, "", `{"error":{"code":403,"message":"Access denied"}}`},
		{"missing issued token", http.StatusCreated, "", `{"token":{"domain":{"id":"account-1"}}}`},
		{"missing domain", http.StatusCreated, "new-token", `{"token":{}}`},
		{"different domain", http.StatusCreated, "new-token", `{"token":{"domain":{"id":"another-account"}}}`},
		{"project scope retained", http.StatusCreated, "new-token", `{"token":{"domain":{"id":"account-1"},"project":{"id":"project-1","domain":{"id":"account-1"}}}}`},
		{"malformed response", http.StatusCreated, "new-token", `{`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			requests := 0
			service, _ := testService(t, func(w http.ResponseWriter, r *http.Request) {
				requests++
				switch r.Method + " " + r.URL.Path {
				case "GET /v3/auth/tokens":
					w.Header().Set("X-Subject-Token", "test-token")
					fmt.Fprint(w, projectTokenMetadata)
				case "POST /v3/auth/tokens":
					if test.token != "" {
						w.Header().Set("X-Subject-Token", test.token)
					}
					w.WriteHeader(test.status)
					fmt.Fprint(w, test.body)
				default:
					t.Errorf("invalid exchange caused an unexpected request: %s %s", r.Method, r.URL)
					w.WriteHeader(http.StatusNotFound)
				}
			})
			service.client.ProjectID = "project-1"
			service.client.DomainID = "account-1"
			if err := service.ensureDomainToken(); err == nil {
				t.Fatal("invalid domain exchange was accepted")
			}
			if requests != 2 || service.client.Token() != "test-token" || service.client.ProjectID != "project-1" || service.client.DomainID != "account-1" {
				t.Error("failed exchange changed provider credentials or made extra requests")
			}
		})
	}
}

func TestEnsureDomainTokenRejectsMissingProjectAccount(t *testing.T) {
	requests := 0
	service, _ := testService(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodGet || r.URL.Path != "/v3/auth/tokens" {
			t.Errorf("account-less token must not trigger an exchange: %s %s", r.Method, r.URL)
		}
		w.Header().Set("X-Subject-Token", "test-token")
		fmt.Fprint(w, `{"token":{"project":{"id":"project-1"},"user":{"domain":{"id":"user-home-account"}}}}`)
	})
	service.client.DomainID = "user-home-account"
	if err := service.ensureDomainToken(); err == nil {
		t.Fatal("missing project account was replaced with the user's home account")
	}
	if requests != 1 || service.client.Token() != "test-token" {
		t.Error("missing project account changed credentials or triggered an exchange")
	}
}

func TestEnsureDomainTokenDoesNotFollowExchangeAcrossHosts(t *testing.T) {
	var leakedRequests atomic.Int32
	untrusted := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leakedRequests.Add(1)
		w.Header().Set("X-Subject-Token", "untrusted-token")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"token":{"domain":{"id":"account-1"}}}`)
	}))
	t.Cleanup(untrusted.Close)
	service, _ := testService(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /v3/auth/tokens":
			w.Header().Set("X-Subject-Token", "test-token")
			fmt.Fprint(w, projectTokenMetadata)
		case "POST /v3/auth/tokens":
			http.Redirect(w, r, untrusted.URL+"/v3/auth/tokens", http.StatusTemporaryRedirect)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	if err := service.ensureDomainToken(); err == nil {
		t.Fatal("cross-host token exchange redirect was accepted")
	}
	if leakedRequests.Load() != 0 || service.client.Token() != "test-token" {
		t.Error("redirect leaked a token request or changed local credentials")
	}
}
