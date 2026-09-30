package iam

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func TestInventoryDocumentedReadEndpoints(t *testing.T) {
	tests := []struct {
		name  string
		path  string
		query url.Values
		key   string
		list  bool
		call  func(*Service) ([]Record, error)
	}{
		{"regions", "/v3/regions", nil, "regions", true, func(s *Service) ([]Record, error) { return s.ListRegions() }},
		{"region", "/v3/regions/eu-de", nil, "region", false, func(s *Service) ([]Record, error) { return inventoryTestOne(s.GetRegion("eu-de")) }},
		{"projects", "/v3/projects", url.Values{"domain_id": {"d"}, "name": {"dev&next=other"}, "parent_id": {"p"}, "enabled": {"false"}}, "projects", true, func(s *Service) ([]Record, error) {
			enabled := false
			return s.ListProjects(ProjectListOptions{DomainID: "d", Name: "dev&next=other", ParentID: "p", Enabled: &enabled})
		}},
		{"project", "/v3/projects/p", nil, "project", false, func(s *Service) ([]Record, error) { return inventoryTestOne(s.GetProject("p")) }},
		{"project status", "/v3-ext/projects/p", nil, "project", false, func(s *Service) ([]Record, error) { return inventoryTestOne(s.GetProjectStatus("p")) }},
		{"accessible projects", "/v3/auth/projects", nil, "projects", true, func(s *Service) ([]Record, error) { return s.ListAccessibleProjects() }},
		{"user projects", "/v3/users/u/projects", nil, "projects", true, func(s *Service) ([]Record, error) { return s.ListUserProjects("u") }},
		{"accessible domains", "/v3/auth/domains", nil, "domains", true, func(s *Service) ([]Record, error) { return s.ListAccessibleDomains() }},
		{"services", "/v3/services", url.Values{"type": {"compute"}}, "services", true, func(s *Service) ([]Record, error) { return s.ListServices("compute") }},
		{"service", "/v3/services/s", nil, "service", false, func(s *Service) ([]Record, error) { return inventoryTestOne(s.GetService("s")) }},
		{"endpoints", "/v3/endpoints", url.Values{"service_id": {"s"}, "interface": {"public"}}, "endpoints", true, func(s *Service) ([]Record, error) { return s.ListEndpoints("s", "public") }},
		{"endpoint", "/v3/endpoints/e", nil, "endpoint", false, func(s *Service) ([]Record, error) { return inventoryTestOne(s.GetEndpoint("e")) }},
		{"agencies", "/v3.0/OS-AGENCY/agencies", url.Values{"domain_id": {"d"}, "name": {"name&field=value"}, "trust_domain_id": {"trusted"}}, "agencies", true, func(s *Service) ([]Record, error) {
			return s.ListAgencies(AgencyListOptions{DomainID: "d", Name: "name&field=value", TrustDomainID: "trusted"})
		}},
		{"agency", "/v3.0/OS-AGENCY/agencies/a", nil, "agency", false, func(s *Service) ([]Record, error) { return inventoryTestOne(s.GetAgency("a")) }},
		{"agency domain grants", "/v3.0/OS-AGENCY/domains/d/agencies/a/roles", nil, "roles", true, func(s *Service) ([]Record, error) { return s.ListAgencyRoles("a", Scope{DomainID: "d"}) }},
		{"agency project grants", "/v3.0/OS-AGENCY/projects/p/agencies/a/roles", nil, "roles", true, func(s *Service) ([]Record, error) { return s.ListAgencyRoles("a", Scope{ProjectID: "p"}) }},
		{"agency inherited grants", "/v3.0/OS-INHERIT/domains/d/agencies/a/roles/inherited_to_projects", nil, "roles", true, func(s *Service) ([]Record, error) {
			return s.ListAgencyRoles("a", Scope{DomainID: "d", AllProjects: true})
		}},
		{"project quotas", "/v3.0/OS-QUOTA/projects/p", nil, "quotas", false, func(s *Service) ([]Record, error) { return inventoryTestOne(s.GetProjectQuotas("p")) }},
		{"domain quotas", "/v3.0/OS-QUOTA/domains/d", url.Values{"type": {"agency"}}, "quotas", false, func(s *Service) ([]Record, error) { return inventoryTestOne(s.GetDomainQuotas("d", "agency")) }},
		{"version", "/v3", nil, "version", false, func(s *Service) ([]Record, error) { return inventoryTestOne(s.GetIdentityVersion()) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service, _ := testService(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != test.path || r.URL.Query().Encode() != test.query.Encode() {
					t.Errorf("unexpected request: %s %s; want GET %s?%s", r.Method, r.URL, test.path, test.query.Encode())
				}
				if r.Header.Get("X-Auth-Token") != "test-token" {
					t.Error("IAM authentication missing")
				}
				record := `{"id":"fixture","future":{"large":9007199254740993}}`
				if test.list {
					record = "[" + record + "]"
				}
				fmt.Fprintf(w, `{%q:%s}`, test.key, record)
			})
			rows, err := test.call(service)
			if err != nil || len(rows) != 1 {
				t.Fatalf("unexpected result rows=%v err=%v", rows, err)
			}
			large := rows[0]["future"].(map[string]any)["large"]
			if number, ok := large.(json.Number); !ok || number.String() != "9007199254740993" {
				t.Errorf("API fields lost fidelity: %#v", rows)
			}
		})
	}
}

func inventoryTestOne(record Record, err error) ([]Record, error) {
	if err != nil {
		return nil, err
	}
	return []Record{record}, nil
}

func TestInventoryAssignmentsPaginationAndFilters(t *testing.T) {
	requests := 0
	includeGroup, inherited := false, true
	opts := AssignmentListOptions{DomainID: "account", UserID: "user", RoleID: "role", ScopeDomainID: "account", IncludeGroup: &includeGroup, IsInherited: &inherited}
	service, _ := testService(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		wantQuery := url.Values{
			"domain_id": {"account"}, "subject.user_id": {"user"}, "role_id": {"role"}, "scope.domain_id": {"account"},
			"include_group": {"false"}, "is_inherited": {"true"}, "page": {fmt.Sprint(requests)}, "per_page": {"50"},
		}
		if r.Method != http.MethodGet || r.URL.Path != "/v3.0/OS-PERMISSION/role-assignments" || !reflect.DeepEqual(r.URL.Query(), wantQuery) {
			t.Errorf("unexpected assignment request: %s %s", r.Method, r.URL)
		}
		start, end := 0, 50
		if requests == 2 {
			start, end = 50, 51
		}
		rows := make([]Record, 0, end-start)
		for i := start; i < end; i++ {
			rows = append(rows, Record{"user": Record{"id": fmt.Sprint(i)}, "role": Record{"id": "role"}, "scope": Record{"domain": Record{"id": "account"}}, "is_inherited": true})
		}
		if err := json.NewEncoder(w).Encode(Record{"role_assignments": rows, "total_num": 51}); err != nil {
			t.Errorf("encode fixture: %v", err)
		}
	})
	rows, err := service.ListAssignments(opts)
	if err != nil || len(rows) != 51 || requests != 2 {
		t.Fatalf("incomplete authorization inventory: rows=%d requests=%d err=%v", len(rows), requests, err)
	}
	if rows[50]["scope"].(map[string]any)["domain"].(map[string]any)["id"] != "account" || rows[50]["is_inherited"] != true {
		t.Fatal("assignment scope or inheritance fields were lost")
	}
}

func TestInventoryAssignmentsRejectPartialPageOverlap(t *testing.T) {
	requests := 0
	service, _ := testService(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		if requests == 1 {
			rows := make([]Record, 0, 50)
			for i := 0; i < 50; i++ {
				rows = append(rows, Record{"user": Record{"id": fmt.Sprint(i)}, "role": Record{"id": "role"}})
			}
			if err := json.NewEncoder(w).Encode(Record{"role_assignments": rows, "total_num": 51}); err != nil {
				t.Errorf("encode fixture: %v", err)
			}
			return
		}
		// The last page repeats one earlier assignment with its JSON fields in
		// a different order. The count remains stable and reaches total_num.
		fmt.Fprint(w, `{"role_assignments":[{"user":{"id":"49"},"role":{"id":"role"}}],"total_num":51}`)
	})
	rows, err := service.ListAssignments(AssignmentListOptions{DomainID: "account"})
	if err == nil || !strings.Contains(err.Error(), "repeated a record") || rows != nil || requests != 2 {
		t.Fatalf("overlapping authorization inventory accepted: rows=%v err=%v requests=%d", rows, err, requests)
	}
}

func TestInventoryAssignmentsRejectIncompletePages(t *testing.T) {
	tests := []struct {
		name   string
		body   string
		status int
	}{
		{"empty before total", `{"role_assignments":[],"total_num":2}`, http.StatusOK},
		{"count changed", `{"role_assignments":[{"role":{"id":"second"}}],"total_num":3}`, http.StatusOK},
		{"repeated page at total", `{"role_assignments":[{"role":{"id":"first"}}],"total_num":2}`, http.StatusOK},
		{"missing count", `{"role_assignments":[]}`, http.StatusOK},
		{"negative count", `{"role_assignments":[],"total_num":-1}`, http.StatusOK},
		{"fractional count", `{"role_assignments":[],"total_num":2.5}`, http.StatusOK},
		{"object instead of array", `{"role_assignments":{"role":{"id":"second"}},"total_num":2}`, http.StatusOK},
		{"null record", `{"role_assignments":[null],"total_num":2}`, http.StatusOK},
		{"too many rows", `{"role_assignments":[{"id":"2"},{"id":"3"}],"total_num":2}`, http.StatusOK},
		{"forbidden page", `{"error":{"message":"denied"}}`, http.StatusForbidden},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			requests := 0
			service, _ := testService(t, func(w http.ResponseWriter, r *http.Request) {
				requests++
				if requests == 1 {
					fmt.Fprint(w, `{"role_assignments":[{"role":{"id":"first"}}],"total_num":2}`)
					return
				}
				w.WriteHeader(test.status)
				fmt.Fprint(w, test.body)
			})
			rows, err := service.ListAssignments(AssignmentListOptions{DomainID: "account"})
			if err == nil || rows != nil || requests != 2 {
				t.Fatalf("partial authorization inventory accepted: rows=%v err=%v requests=%d", rows, err, requests)
			}
		})
	}
}

func TestInventoryAssignmentEnterpriseScopeAndEmptyResult(t *testing.T) {
	service, _ := testService(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("scope") != "enterprise_project" || r.URL.Query().Has("scope.enterprise_projects_id") || r.URL.Query().Has("scope.enterprise_project_id") || r.URL.Query().Has("include_group") || r.URL.Query().Has("is_inherited") {
			t.Errorf("optional assignment filters changed: %s", r.URL.RawQuery)
		}
		fmt.Fprint(w, `{"role_assignments":[],"total_num":0}`)
	})
	rows, err := service.ListAssignments(AssignmentListOptions{DomainID: "account", Scope: "enterprise_project"})
	if err != nil || rows == nil || len(rows) != 0 {
		t.Fatalf("empty result must be a nonnil array: rows=%v err=%v", rows, err)
	}
}

func TestInventoryValidationRejectsRequestsBeforeHTTP(t *testing.T) {
	service, _ := testService(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("invalid input caused an HTTP request: %s", r.URL)
	})
	for _, call := range []func() error{
		func() error { _, err := service.GetRegion("../region"); return err },
		func() error { _, err := service.GetProjectStatus("p?query=value"); return err },
		func() error { _, err := service.ListUserProjects(""); return err },
		func() error { _, err := service.ListProjects(ProjectListOptions{ParentID: "a/b"}); return err },
		func() error { _, err := service.ListAgencies(AgencyListOptions{}); return err },
		func() error {
			_, err := service.ListAgencyRoles("a", Scope{ProjectID: "p", AllProjects: true})
			return err
		},
		func() error { _, err := service.ListEndpoints("s", "other"); return err },
		func() error { _, err := service.GetDomainQuotas("d", "server"); return err },
		func() error {
			_, err := service.ListAssignments(AssignmentListOptions{DomainID: "d", Subject: "user", UserID: "u"})
			return err
		},
		func() error {
			_, err := service.ListAssignments(AssignmentListOptions{DomainID: "d", Scope: "domain", ProjectID: "p"})
			return err
		},
	} {
		if err := call(); err == nil {
			t.Error("invalid IAM inventory input was accepted")
		}
	}
}

func TestInventoryProjectPaginationPreservesFilters(t *testing.T) {
	requests := 0
	service, _ := testService(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Query().Get("domain_id") != "d" {
			t.Error("project pagination lost domain filter")
		}
		if requests == 1 {
			fmt.Fprint(w, `{"projects":[{"id":"first"}],"links":{"next":"?domain_id=d&page=2&per_page=1"}}`)
		} else {
			fmt.Fprint(w, `{"projects":[{"id":"second"}],"links":{"next":null}}`)
		}
	})
	rows, err := service.ListProjects(ProjectListOptions{DomainID: "d"})
	if err != nil || requests != 2 || len(rows) != 2 || !strings.Contains(fmt.Sprint(rows), "second") {
		t.Fatalf("project pagination failed: rows=%v requests=%d err=%v", rows, requests, err)
	}
}
