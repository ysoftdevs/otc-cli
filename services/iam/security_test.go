package iam

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestSecurityCredentialMetadataAndUserFilter(t *testing.T) {
	for _, userID := range []string{"", "user-1"} {
		t.Run("user="+userID, func(t *testing.T) {
			service, _ := testService(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/v3.0/OS-CREDENTIAL/credentials" ||
					r.URL.Query().Get("user_id") != userID || r.URL.Query().Has("user_id") != (userID != "") {
					t.Errorf("unexpected credentials request %s %s", r.Method, r.URL)
				}
				if r.Header.Get("X-Auth-Token") != "test-token" {
					t.Error("authentication token missing")
				}
				fmt.Fprint(w, `{"credentials":[{"access":"key-1","user_id":"user-1","status":"active","create_time":"2026-01-02T03:04:05Z","description":"automation","secret":"must-not-print","extra":{"secret":"also-private"}}]}`)
			})
			records, err := service.ListCredentials(userID)
			if err != nil {
				t.Fatal(err)
			}
			if len(records) != 1 || records[0]["access"] != "key-1" || records[0]["create_time"] != "2026-01-02T03:04:05Z" {
				t.Fatalf("unexpected metadata: %v", records)
			}
			if _, found := records[0]["last_use_time"]; found {
				t.Fatal("list invented last-use metadata")
			}
			data, err := json.Marshal(records)
			if err != nil || strings.Contains(string(data), "secret") || strings.Contains(string(data), "private") {
				t.Fatalf("credential inspection leaked non-metadata: %s, %v", data, err)
			}
		})
	}
}

func TestSecurityCredentialLastUseAndPagination(t *testing.T) {
	requests := 0
	service, _ := testService(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodGet {
			t.Errorf("credential inspection sent %s", r.Method)
		}
		if r.URL.Path == "/v3.0/OS-CREDENTIAL/credentials/key-1" {
			fmt.Fprint(w, `{"credential":{"access":"key-1","last_use_time":"2026-07-04T12:13:14Z","secret":"must-not-print"}}`)
			return
		}
		if r.URL.Path != "/v3.0/OS-CREDENTIAL/credentials" || r.URL.Query().Get("user_id") != "user-1" {
			t.Errorf("unexpected request %s", r.URL)
		}
		if r.URL.Query().Get("marker") == "" {
			fmt.Fprint(w, `{"credentials":[{"access":"key-1"}],"links":{"next":"?user_id=user-1&marker=key-1"}}`)
		} else {
			fmt.Fprint(w, `{"credentials":[{"access":"key-2"}],"links":{"next":null}}`)
		}
	})
	keys, err := service.ListCredentials("user-1")
	if err != nil || len(keys) != 2 || keys[1]["access"] != "key-2" {
		t.Fatalf("pagination: keys=%v err=%v", keys, err)
	}
	key, err := service.GetCredential("key-1")
	if err != nil || key["last_use_time"] != "2026-07-04T12:13:14Z" || key["secret"] != nil || requests != 3 {
		t.Fatalf("key detail: key=%v err=%v requests=%d", key, err, requests)
	}
}

func TestSecurityReadEndpointsAndEnvelopes(t *testing.T) {
	tests := []struct {
		name, path, body string
		call             func(*Service) ([]Record, error)
	}{
		{"MFA list", "/v3.0/OS-MFA/virtual-mfa-devices", `{"virtual_mfa_devices":[{"user_id":"u","serial_number":"iam/mfa/u","base32_string_seed":"private"}]}`,
			func(s *Service) ([]Record, error) { return s.ListMFADevices() }},
		{"MFA user", "/v3.0/OS-MFA/users/u/virtual-mfa-device", `{"virtual_mfa_device":{"user_id":"u","serial_number":"iam/mfa/u","base32_string_seed":"private"}}`,
			func(s *Service) ([]Record, error) { r, e := s.GetMFADevice("u"); return []Record{r}, e }},
		{"login protection list", "/v3.0/OS-USER/login-protects", `{"login_protects":[{"user_id":"u","enabled":false,"verification_method":"none"}]}`,
			func(s *Service) ([]Record, error) { return s.ListLoginProtections() }},
		{"login protection user", "/v3.0/OS-USER/users/u/login-protect", `{"login_protect":{"user_id":"u","enabled":true,"verification_method":"vmfa"}}`,
			func(s *Service) ([]Record, error) { r, e := s.GetLoginProtection("u"); return []Record{r}, e }},
	}
	for _, policy := range []struct{ path, key string }{
		{"password-policy", "password_policy"}, {"login-policy", "login_policy"}, {"protect-policy", "protect_policy"},
		{"api-acl-policy", "api_acl_policy"}, {"console-acl-policy", "console_acl_policy"},
	} {
		tests = append(tests, struct {
			name, path, body string
			call             func(*Service) ([]Record, error)
		}{policy.path, "/v3.0/OS-SECURITYPOLICY/domains/d/" + policy.path,
			`{"` + policy.key + `":{"nested":{"future_setting":true}}}`,
			func(s *Service) ([]Record, error) {
				r, e := s.GetSecurityPolicy("d", policy.path)
				return []Record{r}, e
			}})
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service, _ := testService(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != test.path || r.URL.RawQuery != "" {
					t.Errorf("unexpected request %s %s", r.Method, r.URL)
				}
				fmt.Fprint(w, test.body)
			})
			rows, err := test.call(service)
			if err != nil || len(rows) != 1 || len(rows[0]) == 0 {
				t.Fatalf("response envelope lost: rows=%v err=%v", rows, err)
			}
			if rows[0]["base32_string_seed"] != nil {
				t.Fatal("MFA assignment inspection exposed a seed")
			}
			if strings.HasSuffix(test.name, "-policy") && rows[0]["nested"] == nil {
				t.Fatal("policy extension was dropped")
			}
			if !strings.HasSuffix(test.name, "-policy") && rows[0]["user_id"] != "u" {
				t.Fatal("user assignment was dropped")
			}
		})
	}
}

func TestSecurityValidationBeforeHTTP(t *testing.T) {
	service, _ := testService(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("invalid input caused request %s", r.URL)
	})
	for _, call := range []func() error{
		func() error { _, err := service.ListCredentials("u?user_id=v"); return err },
		func() error { _, err := service.GetCredential("../key"); return err },
		func() error { _, err := service.GetMFADevice(""); return err },
		func() error { _, err := service.GetLoginProtection("u?admin=true"); return err },
		func() error { _, err := service.GetSecurityPolicy("d", "other-policy"); return err },
		func() error { _, err := service.GetSecurityPolicy("../d", "password-policy"); return err },
	} {
		if err := call(); err == nil {
			t.Error("invalid security argument accepted")
		}
	}
}

func TestSecurityNotFoundAndEmptyAreDistinct(t *testing.T) {
	service, _ := testService(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v3.0/OS-USER/login-protects" {
			fmt.Fprint(w, `{"login_protects":[]}`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"error_code":"IAM.0004","error_msg":"Could not find login protection"}`)
	})
	rows, err := service.ListLoginProtections()
	if err != nil || rows == nil || len(rows) != 0 {
		t.Fatalf("empty configured-user list: rows=%v err=%v", rows, err)
	}
	row, err := service.GetLoginProtection("never-configured")
	if err == nil || row != nil || !strings.Contains(err.Error(), "IAM.0004") {
		t.Fatalf("not-found must not become disabled or empty success: row=%v err=%v", row, err)
	}
}
