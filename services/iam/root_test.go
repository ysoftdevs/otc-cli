package iam

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	golangsdk "github.com/opentelekomcloud/gophertelekomcloud"
	"gopkg.in/yaml.v2"
)

func testService(t *testing.T, handler http.HandlerFunc) (*Service, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	service, err := newService(&golangsdk.ServiceClient{
		ProviderClient: &golangsdk.ProviderClient{HTTPClient: *server.Client(), TokenID: "test-token"},
		Endpoint:       server.URL + "/v3/",
	})
	if err != nil {
		t.Fatal(err)
	}
	return service, server
}

func TestListUsersPaginationAndFilters(t *testing.T) {
	requests := 0
	service, _ := testService(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodGet || r.URL.Path != "/v3/users" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
		}
		if r.Header.Get("X-Auth-Token") != "test-token" {
			t.Error("common client authentication header missing")
		}
		if requests == 1 {
			if r.URL.Query().Get("name") != "a&name=other" || r.URL.Query().Get("domain_id") != "domain-1" {
				t.Errorf("filters were not encoded correctly: %s", r.URL.RawQuery)
			}
			fmt.Fprint(w, `{"users":[{"id":"first","enabled":true}],"links":{"next":"?marker=first"}}`)
		} else {
			if r.URL.Query().Get("marker") != "first" {
				t.Errorf("missing next page marker: %s", r.URL.RawQuery)
			}
			fmt.Fprint(w, `{"users":[{"id":"second"}],"links":{"next":null}}`)
		}
	})
	users, err := service.ListUsers("domain-1", "a&name=other")
	if err != nil {
		t.Fatal(err)
	}
	if requests != 2 || len(users) != 2 || users[1]["id"] != "second" {
		t.Fatalf("unexpected paginated result: requests=%d users=%v", requests, users)
	}
}

func TestLaterPageFailureReturnsNoPartialInventory(t *testing.T) {
	requests := 0
	service, _ := testService(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		if requests == 1 {
			fmt.Fprint(w, `{"groups":[{"id":"first"}],"links":{"next":"?marker=first"}}`)
			return
		}
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"error":{"code":403,"message":"Access denied"}}`)
	})
	groups, err := service.ListGroups("", "")
	if err == nil || !strings.Contains(err.Error(), "403") || groups != nil || requests != 2 {
		t.Fatalf("must preserve error and discard partial data: groups=%v err=%v requests=%d", groups, err, requests)
	}
}

func TestRolePolicyAndUnknownFieldsPreserved(t *testing.T) {
	service, _ := testService(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v3/roles/custom-role" {
			t.Errorf("unexpected request %s", r.URL)
		}
		fmt.Fprint(w, `{"role":{"id":"custom-role","display_name":"Cloud_ReadOnly","future_field":{"counter":9007199254740993},"policy":{"Version":"1.1","Statement":[{"Effect":"Deny","Action":["kms:cmk:decrypt"],"Resource":["*"],"Condition":{"StringEquals":{"g:ProjectId":["project-1"]}}}]}}}`)
	})
	role, err := service.GetRole("custom-role")
	if err != nil {
		t.Fatal(err)
	}
	policy := role["policy"].(map[string]any)
	statement := policy["Statement"].([]any)[0].(map[string]any)
	if statement["Condition"] == nil || statement["Resource"] == nil || role["display_name"] != "Cloud_ReadOnly" {
		t.Fatalf("policy fields lost: %#v", role)
	}
	if got := role["future_field"].(map[string]any)["counter"].(json.Number).String(); got != "9007199254740993" {
		t.Fatalf("unknown numeric field lost precision: %s", got)
	}
}

func TestDecodedPolicyNumbersStayNumericInJSONAndYAML(t *testing.T) {
	service, _ := testService(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"role":{"id":"policy","policy":{"Statement":[{"Condition":{"NumericEquals":{"limit":123,"large":9007199254740993}}}]}}}`)
	})
	role, err := service.GetRole("policy")
	if err != nil {
		t.Fatal(err)
	}
	jsonData, err := json.Marshal(role)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"limit":123`, `"large":9007199254740993`} {
		if !strings.Contains(string(jsonData), want) {
			t.Fatalf("JSON changed numeric condition %s: %s", want, jsonData)
		}
	}
	yamlData, err := yaml.Marshal(role)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[any]any
	if err := yaml.Unmarshal(yamlData, &decoded); err != nil {
		t.Fatal(err)
	}
	policy := decoded["policy"].(map[any]any)
	condition := policy["Statement"].([]any)[0].(map[any]any)["Condition"].(map[any]any)
	numbers := condition["NumericEquals"].(map[any]any)
	for key, want := range map[string]string{"limit": "123", "large": "9007199254740993"} {
		if _, isString := numbers[key].(string); isString || fmt.Sprint(numbers[key]) != want {
			t.Fatalf("YAML changed %s into %T (%v): %s", key, numbers[key], numbers[key], yamlData)
		}
	}
}

func TestGroupGrantScopes(t *testing.T) {
	tests := []struct {
		name  string
		scope Scope
		path  string
	}{
		{"domain", Scope{DomainID: "domain-1"}, "/v3/domains/domain-1/groups/group-1/roles"},
		{"project", Scope{ProjectID: "project-1"}, "/v3/projects/project-1/groups/group-1/roles"},
		{"inherited", Scope{DomainID: "domain-1", AllProjects: true}, "/v3/OS-INHERIT/domains/domain-1/groups/group-1/roles/inherited_to_projects"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service, _ := testService(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != test.path {
					t.Errorf("got %s want %s", r.URL.Path, test.path)
				}
				fmt.Fprint(w, `{"roles":[],"links":{"next":null}}`)
			})
			roles, err := service.ListGroupRoles("group-1", test.scope)
			if err != nil || roles == nil || len(roles) != 0 {
				t.Fatalf("want non-nil empty array: roles=%v err=%v", roles, err)
			}
		})
	}
}

func TestRoleListingScope(t *testing.T) {
	for _, domain := range []string{"", "domain-1"} {
		t.Run("domain="+domain, func(t *testing.T) {
			service, _ := testService(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v3/roles" || r.URL.Query().Get("domain_id") != domain || r.URL.Query().Get("name") != "readonly" {
					t.Errorf("unexpected system/custom role request: %s", r.URL)
				}
				if domain == "" && r.URL.Query().Has("domain_id") {
					t.Error("system role request must omit domain_id")
				}
				fmt.Fprint(w, `{"roles":[]}`)
			})
			if _, err := service.ListRoles(domain, "readonly"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFederationAndMembershipEndpoints(t *testing.T) {
	tests := []struct {
		name string
		path string
		body string
		call func(*Service) error
	}{
		{"user", "/v3/users/u", `{"user":{"id":"u"}}`, func(s *Service) error { _, e := s.GetUser("u"); return e }},
		{"group", "/v3/groups/g", `{"group":{"id":"g"}}`, func(s *Service) error { _, e := s.GetGroup("g"); return e }},
		{"user groups", "/v3/users/u/groups", `{"groups":[]}`, func(s *Service) error { _, e := s.ListUserGroups("u"); return e }},
		{"group users", "/v3/groups/g/users", `{"users":[]}`, func(s *Service) error { _, e := s.ListGroupUsers("g"); return e }},
		{"providers", "/v3/OS-FEDERATION/identity_providers", `{"identity_providers":[]}`, func(s *Service) error { _, e := s.ListProviders(); return e }},
		{"provider", "/v3/OS-FEDERATION/identity_providers/Y_Soft_Entra_ID_PROD", `{"identity_provider":{"id":"Y_Soft_Entra_ID_PROD"}}`, func(s *Service) error { _, e := s.GetProvider("Y_Soft_Entra_ID_PROD"); return e }},
		{"protocols", "/v3/OS-FEDERATION/identity_providers/idp/protocols", `{"protocols":[]}`, func(s *Service) error { _, e := s.ListProtocols("idp"); return e }},
		{"protocol", "/v3/OS-FEDERATION/identity_providers/idp/protocols/saml", `{"protocol":{"id":"saml","mapping_id":"mapping-1"}}`, func(s *Service) error { _, e := s.GetProtocol("idp", "saml"); return e }},
		{"mappings", "/v3/OS-FEDERATION/mappings", `{"mappings":[]}`, func(s *Service) error { _, e := s.ListMappings(); return e }},
		{"mapping", "/v3/OS-FEDERATION/mappings/mapping-1", `{"mapping":{"id":"mapping-1","rules":[{"local":[{"groups":"{2}"}],"remote":[{"type":"roles","future_option":true}]}]}}`, func(s *Service) error {
			m, e := s.GetMapping("mapping-1")
			if e == nil && !m["rules"].([]any)[0].(map[string]any)["remote"].([]any)[0].(map[string]any)["future_option"].(bool) {
				return fmt.Errorf("mapping rule field lost")
			}
			return e
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service, _ := testService(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != test.path {
					t.Errorf("unexpected request %s %s", r.Method, r.URL)
				}
				fmt.Fprint(w, test.body)
			})
			if err := test.call(service); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestInvalidIDsAndScopesRejectedBeforeRequest(t *testing.T) {
	service, _ := testService(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("invalid arguments caused request: %s", r.URL)
	})
	for _, id := range []string{"", ".", "..", "../roles", "a/b", "a\\b", "a?x=y", "a#b", "%2e%2e", "a\x00b", "a\nb", " trailing ", "a..b"} {
		if _, err := service.GetUser(id); err == nil {
			t.Errorf("ID %q accepted", id)
		}
	}
	for _, scope := range []Scope{{}, {DomainID: "d", ProjectID: "p"}, {ProjectID: "p", AllProjects: true}, {AllProjects: true}, {DomainID: "../"}} {
		if _, err := service.ListGroupRoles("group", scope); err == nil {
			t.Errorf("scope %#v accepted", scope)
		}
	}
	if err := ValidateID("provider", "Y_Soft_Entra_ID_PROD"); err != nil {
		t.Fatal(err)
	}
}

func TestUnsafePaginationRejected(t *testing.T) {
	for _, next := range []string{
		"https://untrusted.invalid/v3/groups",
		"//untrusted.invalid/v3/groups",
		"/v2/groups", "/v3evil/groups", "/v3/%2e%2e/v2/groups",
		"/v3/%5c../groups", "/v3/groups#fragment", "/v3/groups",
	} {
		t.Run(next, func(t *testing.T) {
			requests := 0
			service, _ := testService(t, func(w http.ResponseWriter, r *http.Request) {
				requests++
				fmt.Fprintf(w, `{"groups":[{"id":"first"}],"links":{"next":%q}}`, next)
			})
			groups, err := service.ListGroups("", "")
			if err == nil || groups != nil || requests != 1 {
				t.Fatalf("unsafe/looping page accepted: groups=%v err=%v requests=%d", groups, err, requests)
			}
		})
	}
}

func TestRedirectCannotLeaveIAMEndpoint(t *testing.T) {
	service, _ := testService(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://untrusted.invalid/v3/users", http.StatusFound)
	})
	if users, err := service.ListUsers("", ""); err == nil || users != nil {
		t.Fatalf("cross-origin redirect accepted: users=%v err=%v", users, err)
	}
}

func TestMalformedResponseIsNotEmptySuccess(t *testing.T) {
	for _, body := range []string{`{}`, `{"users":null}`, `{"users":{}}`, `{"users":[null]}`, `{"users":[],"links":{"next":42}}`} {
		t.Run(body, func(t *testing.T) {
			service, _ := testService(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) })
			if users, err := service.ListUsers("", ""); err == nil || users != nil {
				t.Fatalf("malformed response accepted: users=%v err=%v", users, err)
			}
		})
	}
}
