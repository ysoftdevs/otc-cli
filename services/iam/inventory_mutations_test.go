package iam

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func TestInventoryMutationResourceRoutes(t *testing.T) {
	// Expected requests and success codes come from the OTC API reference,
	// including the v3.0 user PUT and the empty HTTP 200 policy DELETE.
	for _, test := range []struct {
		name, method, path, body, snapshot, response string
		status                                       int
		create                                       bool
	}{
		{"user-create", "POST", "/v3.0/OS-USER/users", "user", "", "user", 201, true},
		{"user-update", "PUT", "/v3.0/OS-USER/users/resource", "user", "/v3.0/OS-USER/users/resource", "user", 200, false},
		{"user-delete", "DELETE", "/v3/users/resource", "", "/v3.0/OS-USER/users/resource", "", 204, false},
		{"group-create", "POST", "/v3/groups", "group", "", "group", 201, true},
		{"group-update", "PATCH", "/v3/groups/resource", "group", "/v3/groups/resource", "group", 200, false},
		{"group-delete", "DELETE", "/v3/groups/resource", "", "/v3/groups/resource", "", 204, false},
		{"project-create", "POST", "/v3/projects", "project", "", "project", 201, true},
		{"project-update", "PATCH", "/v3/projects/resource", "project", "/v3/projects/resource", "project", 200, false},
		{"project-set-status", "PUT", "/v3-ext/projects/resource", "project", "/v3-ext/projects/resource", "", 204, false},
		{"project-delete", "DELETE", "/v3/projects/resource", "", "/v3/projects/resource", "", 204, false},
		{"agency-create", "POST", "/v3.0/OS-AGENCY/agencies", "agency", "", "agency", 201, true},
		{"agency-update", "PUT", "/v3.0/OS-AGENCY/agencies/resource", "agency", "/v3.0/OS-AGENCY/agencies/resource", "agency", 200, false},
		{"agency-delete", "DELETE", "/v3.0/OS-AGENCY/agencies/resource", "", "/v3.0/OS-AGENCY/agencies/resource", "", 204, false},
		{"policy-create", "POST", "/v3.0/OS-ROLE/roles", "role", "", "role", 201, true},
		{"policy-update", "PATCH", "/v3.0/OS-ROLE/roles/resource", "role", "/v3.0/OS-ROLE/roles/resource", "role", 200, false},
		{"policy-delete", "DELETE", "/v3.0/OS-ROLE/roles/resource", "", "/v3.0/OS-ROLE/roles/resource", "", 200, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			spec := inventoryMutationTestSpec(t, test.name)
			args := []string{"resource"}
			if test.create {
				args = nil
			}
			path := inventoryMutationTestPath(t, spec.Version, spec.Path, args)
			snapshot := inventoryMutationTestPath(t, spec.ReadVersion, spec.ReadPath, args)
			if spec.Method != test.method || path != test.path || snapshot != test.snapshot {
				t.Fatalf("request %s %s, snapshot %s; want %s %s, snapshot %s", spec.Method, path, snapshot, test.method, test.path, test.snapshot)
			}
			if spec.BodyKey != test.body || spec.ResponseKey != test.response || spec.Create != test.create || !reflect.DeepEqual(spec.SuccessCodes, []int{test.status}) {
				t.Fatalf("incorrect request/response contract: %+v", spec)
			}
			if !test.create && (spec.ReadKey == "" || spec.SnapshotMethod != "" || spec.Risk == "") {
				t.Fatal("resource mutation lost its object snapshot or risk description")
			}
		})
	}
}

func TestInventoryMutationRelationsUseExactHEADSnapshots(t *testing.T) {
	for _, test := range []struct {
		name, resource, args, path string
	}{
		{"group-user", "groups", "group user", "/v3/groups/group/users/user"},
		{"group-domain", "groups", "group domain role", "/v3/domains/domain/groups/group/roles/role"},
		{"group-project", "groups", "group project role", "/v3/projects/project/groups/group/roles/role"},
		{"group-inherited", "groups", "group domain role", "/v3/OS-INHERIT/domains/domain/groups/group/roles/role/inherited_to_projects"},
		{"agency-domain", "agencies", "agency domain role", "/v3.0/OS-AGENCY/domains/domain/agencies/agency/roles/role"},
		{"agency-project", "agencies", "agency project role", "/v3.0/OS-AGENCY/projects/project/agencies/agency/roles/role"},
		{"agency-inherited", "agencies", "agency domain role", "/v3.0/OS-INHERIT/domains/domain/agencies/agency/roles/role/inherited_to_projects"},
	} {
		for _, action := range []struct{ name, method string }{{"add", http.MethodPut}, {"remove", http.MethodDelete}} {
			t.Run(test.name+"-"+action.name, func(t *testing.T) {
				spec := inventoryMutationTestSpec(t, test.name+"-"+action.name)
				args := strings.Fields(test.args)
				if spec.Method != action.method || inventoryMutationTestPath(t, spec.Version, spec.Path, args) != test.path || inventoryMutationTestPath(t, spec.ReadVersion, spec.ReadPath, args) != test.path {
					t.Fatalf("incorrect authorization relationship target: %+v", spec)
				}
				if spec.SnapshotMethod != http.MethodHead || spec.Create || spec.BodyKey != "" || spec.ResponseKey != "" || !reflect.DeepEqual(spec.SuccessCodes, []int{204}) || !reflect.DeepEqual(spec.CommandPath, []string{test.resource}) {
					t.Fatalf("relation must preserve HEAD review and bodyless 204 semantics: %+v", spec)
				}
				if err := ValidateMutationInput(spec.Name, args, nil); err != nil {
					t.Fatalf("documented positional argument order rejected: %v", err)
				}
				if err := ValidateMutationInput(spec.Name, args, json.RawMessage(`{}`)); err == nil {
					t.Fatal("bodyless authorization operation accepted a body")
				}
			})
		}
	}
}

func TestInventoryMutationBodiesAcceptDocumentedForms(t *testing.T) {
	for _, test := range []struct{ operation, body string }{
		{"user-create", `{"user":{"name":"Reader","domain_id":"account","password":"password-fixture","enabled":false,"pwd_status":true,"areacode":"00420","phone":"123456789","xuser_type":"TenantIdp","xuser_id":"external"}}`},
		{"user-update", `{"user":{"enabled":false,"access_mode":"programmatic","email":"new@example.com"}}`},
		{"group-create", `{"group":{"name":"Readers","domain_id":"account"}}`},
		{"group-update", `{"group":{"description":""}}`},
		{"project-create", `{"project":{"name":"eu-de_test","parent_id":"parent","domain_id":"account"}}`},
		{"project-update", `{"project":{"name":"eu-de_other","description":""}}`},
		{"project-set-status", `{"project":{"status":"normal"}}`},
		{"project-set-status", `{"project":{"status":"suspended"}}`},
		{"agency-create", `{"agency":{"name":"Support","domain_id":"account","trust_domain_id":"trusted","duration":null}}`},
		{"agency-create", `{"agency":{"name":"Support","domain_id":"account","trust_domain_name":"Trusted","duration":"FOREVER"}}`},
		{"agency-create", `{"agency":{"name":"Support","domain_id":"account","trust_domain_name":"Trusted","duration":"ONEDAY"}}`},
		{"agency-update", `{"agency":{"description":""}}`},
		{"agency-update", `{"agency":{"trust_domain_id":"trusted","trust_domain_name":"Trusted"}}`},
		{"policy-create", inventoryMutationCloudPolicy},
		{"policy-update", inventoryMutationCloudPolicy},
		{"policy-create", `{"role":{"display_name":"AssumeSupport","description":"Delegate support access","type":"AX","policy":{"Version":"1.1","Statement":[{"Effect":"Allow","Action":["iam:agencies:assume"],"Resource":{"uri":["/iam/agencies/support"]}}]}}}`},
	} {
		t.Run(test.operation+"/"+test.body, func(t *testing.T) {
			spec := inventoryMutationTestSpec(t, test.operation)
			args := []string{"resource"}
			if spec.Create {
				args = nil
			}
			if err := ValidateMutationInput(test.operation, args, json.RawMessage(test.body)); err != nil {
				t.Fatalf("documented request rejected: %v", err)
			}
		})
	}
}

const inventoryMutationCloudPolicy = `{"role":{"display_name":"ReadBuckets","description":"Read bucket metadata","type":"AX","policy":{"Version":"1.1","Statement":[{"Effect":"Allow","Action":["obs:bucket:GetBucketAcl"],"Resource":["obs:*:*:bucket:*"],"Condition":{"StringEquals":{"obs:prefix":["public"]}}}]}}}`

func TestInventoryMutationRejectsInvalidBodiesWithoutEchoingValues(t *testing.T) {
	for _, test := range []struct{ operation, body string }{
		{"user-create", `{"user":{"name":"Reader"}}`},
		{"user-create", `{"user":{"name":{},"domain_id":"account"}}`},
		{"user-create", `{"user":{"name":"Reader","domain_id":"../account"}}`},
		{"user-create", `{"user":{"name":"Reader","domain_id":"account","phone":"private-fixture"}}`},
		{"user-update", `{"user":{"enabled":"private-fixture"}}`},
		{"user-update", `{"user":{"password":false}}`},
		{"user-update", `{"user":{"email":null}}`},
		{"user-update", `{"user":{"access_mode":"private-fixture"}}`},
		{"user-update", `{"user":{"xuser_type":"private-fixture"}}`},
		{"user-update", `{"user":{"domain_id":"account"}}`},
		{"group-create", `{"group":{"name":true}}`},
		{"group-update", `{"group":{"name":[],"description":"private-fixture"}}`},
		{"project-create", `{"project":{"name":"eu-de_test"}}`},
		{"project-create", `{"project":{"name":"eu-de_test","parent_id":true}}`},
		{"project-update", `{"project":{"enabled":false}}`},
		{"project-set-status", `{"project":{"status":"private-fixture"}}`},
		{"project-set-status", `{"project":{"status":false}}`},
		{"agency-create", `{"agency":{"name":"Support","domain_id":"account"}}`},
		{"agency-create", `{"agency":{"name":"Support","domain_id":"account","trust_domain_name":""}}`},
		{"agency-create", `{"agency":{"name":"Support","domain_id":"account","trust_domain_id":"trusted","duration":"private-fixture"}}`},
		{"agency-update", `{"agency":{"trust_domain_id":"trusted"}}`},
		{"agency-update", `{"agency":{"trust_domain_name":"Trusted"}}`},
		{"agency-update", `{"agency":{"trust_domain_id":"trusted","trust_domain_name":null}}`},
		{"agency-update", `{"agency":{"duration":"FOREVER"}}`},
		{"policy-update", `{"role":{"description":"private-fixture"}}`},
		{"policy-create", strings.Replace(inventoryMutationCloudPolicy, `"type":"AX"`, `"type":"private-fixture"`, 1)},
		{"policy-create", strings.Replace(inventoryMutationCloudPolicy, `"Version":"1.1"`, `"Version":1.1`, 1)},
		{"policy-update", strings.Replace(inventoryMutationCloudPolicy, `"Version":"1.1"`, `"Version":"1.0"`, 1)},
		{"policy-update", strings.Replace(inventoryMutationCloudPolicy, `"Effect":"Allow"`, `"Effect":"private-fixture"`, 1)},
		{"policy-update", strings.Replace(inventoryMutationCloudPolicy, `"Action":["obs:bucket:GetBucketAcl"]`, `"Action":"private-fixture"`, 1)},
		{"policy-update", strings.Replace(inventoryMutationCloudPolicy, `"Action":["obs:bucket:GetBucketAcl"]`, `"Action":[null]`, 1)},
		{"policy-update", strings.Replace(inventoryMutationCloudPolicy, `"Resource":["obs:*:*:bucket:*"]`, `"Resource":{"uri":"private-fixture"}`, 1)},
		{"policy-update", strings.Replace(inventoryMutationCloudPolicy, `"Resource":["obs:*:*:bucket:*"]`, `"Resource":{"private-fixture":[]}`, 1)},
		{"policy-update", strings.Replace(inventoryMutationCloudPolicy, `"StringEquals":{"obs:prefix":["public"]}`, `"private-fixture"`, 1)},
		{"policy-update", strings.Replace(inventoryMutationCloudPolicy, `"Effect":"Allow"`, `"Effect":"Allow","private-fixture":true`, 1)},
	} {
		t.Run(test.operation+"/"+test.body, func(t *testing.T) {
			spec := inventoryMutationTestSpec(t, test.operation)
			args := []string{"resource"}
			if spec.Create {
				args = nil
			}
			err := ValidateMutationInput(test.operation, args, json.RawMessage(test.body))
			if err == nil || strings.Contains(err.Error(), "private-fixture") {
				t.Fatalf("invalid body accepted or its value exposed: %v", err)
			}
		})
	}
}

func TestInventoryMutationPolicyArrayLimits(t *testing.T) {
	for _, field := range []string{"Statement", "Action", "Resource"} {
		t.Run(field, func(t *testing.T) {
			var envelope Record
			if err := decode(json.RawMessage(inventoryMutationCloudPolicy), &envelope); err != nil {
				t.Fatal(err)
			}
			role := envelope["role"].(map[string]any)
			policy := role["policy"].(map[string]any)
			statement := policy["Statement"].([]any)[0].(map[string]any)
			values, target := make([]any, 9), policy
			if field != "Statement" {
				target = statement
				if field == "Action" {
					values = make([]any, 101)
				} else {
					values = make([]any, 11)
				}
			}
			for i := range values {
				values[i] = "item"
				if field == "Statement" {
					values[i] = statement
				}
			}
			target[field] = values
			if err := validateInventoryPolicy(role); err == nil {
				t.Fatalf("documented %s count limit was ignored", field)
			}
		})
	}
}

func TestInventoryMutationCatalogHasNoUngatedTargets(t *testing.T) {
	specs := inventoryMutationSpecs()
	if len(specs) != 30 {
		t.Fatalf("got %d mutation specs; expected 16 resources and 14 relations", len(specs))
	}
	seenNames, seenCommands := make(map[string]bool), make(map[string]bool)
	for _, spec := range specs {
		command := strings.Join(spec.CommandPath, " ") + " " + strings.Fields(spec.Use)[0]
		if seenNames[spec.Name] || seenCommands[command] {
			t.Fatalf("duplicate operation or command: %s, %s", spec.Name, command)
		}
		seenNames[spec.Name], seenCommands[command] = true, true
		if !spec.Create && len(spec.ReadPath) == 0 {
			t.Errorf("%s has no review snapshot", spec.Name)
		}
		if spec.BodyKey != "" && spec.ValidateBody == nil {
			t.Errorf("%s does not validate its documented body", spec.Name)
		}
		args := make([]string, len(strings.Fields(spec.Use))-1)
		for i := range args {
			args[i] = fmt.Sprintf("resource-%d", i)
		}
		if _, err := mutationParts(spec.Path, args); err != nil {
			t.Errorf("%s cannot bind its explicit resource IDs: %v", spec.Name, err)
		}
		if strings.Contains(strings.Join(spec.Path, "/"), "*") {
			t.Errorf("%s contains a wildcard target", spec.Name)
		}
	}
}

func inventoryMutationTestSpec(t *testing.T, name string) MutationSpec {
	t.Helper()
	for _, spec := range inventoryMutationSpecs() {
		if spec.Name == name {
			return spec
		}
	}
	t.Fatalf("missing inventory mutation %s", name)
	return MutationSpec{}
}

func inventoryMutationTestPath(t *testing.T, version string, template, args []string) string {
	t.Helper()
	if len(template) == 0 {
		return ""
	}
	parts, err := mutationParts(template, args)
	if err != nil {
		t.Fatal(err)
	}
	return "/" + version + "/" + strings.Join(parts, "/")
}
