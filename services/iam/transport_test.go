package iam

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExtensionPaginationPreservesFiltersAndNumbers(t *testing.T) {
	requests := 0
	service, _ := testService(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path != "/v3.0/OS-CREDENTIAL/credentials" || r.URL.Query().Get("user_id") != "user" {
			t.Errorf("unexpected request: %s", r.URL)
		}
		if requests == 1 {
			fmt.Fprint(w, `{"credentials":[{"access":"first","future":9007199254740993}],"links":{"next_marker":"next&literal"}}`)
			return
		}
		if r.URL.Query().Get("marker") != "next&literal" {
			t.Errorf("marker changed: %s", r.URL)
		}
		fmt.Fprint(w, `{"credentials":[{"access":"second"}],"links":{"next_marker":null}}`)
	})
	endpoint, err := service.versionEndpoint("v3.0", "OS-CREDENTIAL", "credentials")
	if err != nil {
		t.Fatal(err)
	}
	endpoint.RawQuery = "user_id=user"
	records, err := service.list("credentials", endpoint)
	if err != nil || len(records) != 2 || requests != 2 {
		t.Fatalf("list = %v, %v; requests = %d", records, err, requests)
	}
	if got := fmt.Sprint(records[0]["future"]); got != "9007199254740993" {
		t.Errorf("large value changed to %s", got)
	}
}

func TestExtensionRepeatedMarkerFailsWithoutPartialOutput(t *testing.T) {
	requests := 0
	service, _ := testService(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		fmt.Fprint(w, `{"credentials":[{"access":"first"}],"links":{"next_marker":"same"}}`)
	})
	rows, err := service.listVersion("v3.0", "credentials", nil, "OS-CREDENTIAL", "credentials")
	if err == nil || rows != nil || requests != 2 {
		t.Fatalf("rows = %v, err = %v, requests = %d; want failure and no partial output", rows, err, requests)
	}
}

func TestExtensionRejectsUntrustedRedirectBeforeSendingCredentials(t *testing.T) {
	for _, version := range []string{"v3", "v3.0", "v3-ext"} {
		t.Run(version, func(t *testing.T) {
			untrusted := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Errorf("IAM request reached untrusted host: %s", r.URL)
			}))
			defer untrusted.Close()
			service, _ := testService(t, func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, untrusted.URL+"/"+version+"/users", http.StatusTemporaryRedirect)
			})
			if _, err := service.getVersion(version, "user", "users", "user"); err == nil {
				t.Fatal("untrusted redirect accepted")
			}
		})
	}
}

func TestExtensionURLValidation(t *testing.T) {
	service, _ := testService(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("invalid path caused request: %s", r.URL)
	})
	for _, version := range []string{"v2", "v3.0/../v3", "v3evil", "https://example.org"} {
		if _, err := service.versionEndpoint(version, "users"); err == nil {
			t.Errorf("accepted version %q", version)
		}
	}
	for _, path := range []string{"../users", "a/b", "%2e%2e", "//other", "user?query"} {
		if _, err := service.getVersion("v3.0", "user", "users", path); err == nil {
			t.Errorf("accepted ID %q", path)
		}
	}
}

func TestCatalogUsesProjectTokenWithoutChangingIAMClient(t *testing.T) {
	service, _ := testService(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v3/auth/catalog" {
			if got := r.Header.Get("X-Auth-Token"); got != "project-token" {
				t.Errorf("catalog token = %q; want project token", got)
			}
			fmt.Fprint(w, `{"catalog":[{"id":"compute","endpoints":[{"region":"eu-de"}]}]}`)
			return
		}
		if got := r.Header.Get("X-Auth-Token"); got != "test-token" {
			t.Errorf("IAM token changed to %q", got)
		}
		fmt.Fprint(w, `{"groups":[]}`)
	})
	service.projectToken = "project-token"
	catalog, err := service.listProjectCatalog()
	if err != nil || len(catalog) != 1 {
		t.Fatalf("catalog = %v, err = %v", catalog, err)
	}
	if _, err := service.ListGroups("", ""); err != nil {
		t.Fatal(err)
	}
	if service.client.Token() != "test-token" {
		t.Error("catalog replaced account token")
	}
}

func TestCatalogWithoutProjectTokenDoesNotRequest(t *testing.T) {
	service, _ := testService(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("catalog request sent without project scope")
	})
	if _, err := service.listProjectCatalog(); err == nil || !strings.Contains(err.Error(), "project-scoped") {
		t.Fatalf("error = %v; want project scope explanation", err)
	}
}

func TestMetadataXMLAndBoundedRead(t *testing.T) {
	for _, size := range []int{10, (2 << 20) + 1} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			service, _ := testService(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v3-ext/auth/OS-FEDERATION/SSO/metadata" {
					t.Errorf("unexpected path %s", r.URL.Path)
				}
				fmt.Fprint(w, strings.Repeat("x", size))
			})
			value, err := service.readTextVersion("v3-ext", "auth", "OS-FEDERATION", "SSO", "metadata")
			if size == 10 && (err != nil || len(value) != size) {
				t.Fatalf("metadata length = %d, err = %v", len(value), err)
			}
			if size > 2<<20 && (err == nil || value != "") {
				t.Fatal("oversized metadata accepted")
			}
		})
	}
}
