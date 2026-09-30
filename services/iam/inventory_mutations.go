package iam

import (
	"fmt"
	"net/http"
	"strings"
	"unicode/utf8"
)

// These operations follow the OTC IAM API Reference, released 2025-10-17:
// https://docs.otc.t-systems.com/identity-access-management/iam-api-ref.pdf
// They describe requests only; the common mutation engine controls preview,
// snapshots, confirmation, backups, and execution.
func inventoryMutationSpecs() []MutationSpec {
	specs := []MutationSpec{
		{
			Name: "user-create", CommandPath: []string{"users"}, Use: "create", Short: "Create an IAM user",
			Method: http.MethodPost, Version: "v3.0", Path: []string{"OS-USER", "users"},
			BodyKey: "user", RequiredFields: []string{"name", "domain_id"}, ValidateBody: validateInventoryUserCreate,
			ResponseKey: "user", SuccessCodes: []int{http.StatusCreated}, Create: true,
			Risk: "Creates an identity that can receive permissions. An optional password is not recoverable from subsequent reads.",
		},
		{
			Name: "user-update", CommandPath: []string{"users"}, Use: "update USER_ID", Short: "Update an IAM user's profile and access settings",
			Method: http.MethodPut, Version: "v3.0", Path: []string{"OS-USER", "users", "{0}"},
			BodyKey: "user", ValidateBody: validateInventoryUserUpdate,
			ReadVersion: "v3.0", ReadPath: []string{"OS-USER", "users", "{0}"}, ReadKey: "user",
			ResponseKey: "user", SuccessCodes: []int{http.StatusOK},
			Risk: "Disabling the user or changing login settings can interrupt access. A backup cannot recover the previous password.",
		},
		{
			Name: "user-delete", CommandPath: []string{"users"}, Use: "delete USER_ID", Short: "Delete an IAM user",
			Method: http.MethodDelete, Version: "v3", Path: []string{"users", "{0}"},
			ReadVersion: "v3.0", ReadPath: []string{"OS-USER", "users", "{0}"}, ReadKey: "user",
			SuccessCodes: []int{http.StatusNoContent},
			Risk:         "Deletes this identity. The profile backup cannot recreate its original ID, credentials, memberships, or grants.",
		},
		{
			Name: "group-create", CommandPath: []string{"groups"}, Use: "create", Short: "Create an IAM group",
			Method: http.MethodPost, Version: "v3", Path: []string{"groups"},
			BodyKey: "group", RequiredFields: []string{"name"}, ValidateBody: validateInventoryGroup,
			ResponseKey: "group", SuccessCodes: []int{http.StatusCreated}, Create: true,
		},
		{
			Name: "group-update", CommandPath: []string{"groups"}, Use: "update GROUP_ID", Short: "Update an IAM group",
			Method: http.MethodPatch, Version: "v3", Path: []string{"groups", "{0}"},
			BodyKey: "group", ValidateBody: validateInventoryGroup,
			ReadVersion: "v3", ReadPath: []string{"groups", "{0}"}, ReadKey: "group",
			ResponseKey: "group", SuccessCodes: []int{http.StatusOK},
			Risk: "Changing a group name can affect federation mappings that refer to that name.",
		},
		{
			Name: "group-delete", CommandPath: []string{"groups"}, Use: "delete GROUP_ID", Short: "Delete an IAM group",
			Method: http.MethodDelete, Version: "v3", Path: []string{"groups", "{0}"},
			ReadVersion: "v3", ReadPath: []string{"groups", "{0}"}, ReadKey: "group",
			SuccessCodes: []int{http.StatusNoContent},
			Risk:         "Removes this group and its authorization relationships. The group object backup does not include memberships, grants, or federation mappings.",
		},
		{
			Name: "project-create", CommandPath: []string{"projects"}, Use: "create", Short: "Create an IAM subproject",
			Method: http.MethodPost, Version: "v3", Path: []string{"projects"},
			// The parameter table requires parent_id; the older example omits it.
			BodyKey: "project", RequiredFields: []string{"name", "parent_id"}, ValidateBody: validateInventoryProjectCreate,
			ResponseKey: "project", SuccessCodes: []int{http.StatusCreated}, Create: true,
		},
		{
			Name: "project-update", CommandPath: []string{"projects"}, Use: "update PROJECT_ID", Short: "Update an IAM project's name or description",
			Method: http.MethodPatch, Version: "v3", Path: []string{"projects", "{0}"},
			BodyKey: "project", ValidateBody: validateInventoryProject,
			ReadVersion: "v3", ReadPath: []string{"projects", "{0}"}, ReadKey: "project",
			ResponseKey: "project", SuccessCodes: []int{http.StatusOK},
			Risk: "Renaming a project can affect configurations or policy conditions that refer to its name.",
		},
		{
			Name: "project-set-status", CommandPath: []string{"projects"}, Use: "set-status PROJECT_ID", Short: "Set an IAM project's normal or suspended status",
			Method: http.MethodPut, Version: "v3-ext", Path: []string{"projects", "{0}"},
			BodyKey: "project", RequiredFields: []string{"status"}, ValidateBody: validateInventoryProjectStatus,
			ReadVersion: "v3-ext", ReadPath: []string{"projects", "{0}"}, ReadKey: "project",
			SuccessCodes: []int{http.StatusNoContent},
			Risk:         "Suspending a project freezes it and can interrupt access to its resources.",
		},
		{
			Name: "project-delete", CommandPath: []string{"projects"}, Use: "delete PROJECT_ID", Short: "Delete an IAM project",
			Method: http.MethodDelete, Version: "v3", Path: []string{"projects", "{0}"},
			ReadVersion: "v3", ReadPath: []string{"projects", "{0}"}, ReadKey: "project",
			SuccessCodes: []int{http.StatusNoContent},
			Risk:         "Deletes the project identity. The project object backup does not contain cloud resources or authorization relationships.",
		},
		{
			Name: "agency-create", CommandPath: []string{"agencies"}, Use: "create", Short: "Create an IAM agency",
			Method: http.MethodPost, Version: "v3.0", Path: []string{"OS-AGENCY", "agencies"},
			BodyKey: "agency", RequiredFields: []string{"name", "domain_id"}, ValidateBody: validateInventoryAgencyCreate,
			ResponseKey: "agency", SuccessCodes: []int{http.StatusCreated}, Create: true,
			Risk: "Establishes trust in another account. Granted permissions determine the resources that account can access.",
		},
		{
			Name: "agency-update", CommandPath: []string{"agencies"}, Use: "update AGENCY_ID", Short: "Update an IAM agency's trust or description",
			Method: http.MethodPut, Version: "v3.0", Path: []string{"OS-AGENCY", "agencies", "{0}"},
			BodyKey: "agency", ValidateBody: validateInventoryAgencyUpdate,
			ReadVersion: "v3.0", ReadPath: []string{"OS-AGENCY", "agencies", "{0}"}, ReadKey: "agency",
			ResponseKey: "agency", SuccessCodes: []int{http.StatusOK},
			Risk: "Changing the trusted account transfers access under existing agency grants. When both trust fields are supplied, OTC gives trust_domain_name precedence.",
		},
		{
			Name: "agency-delete", CommandPath: []string{"agencies"}, Use: "delete AGENCY_ID", Short: "Delete an IAM agency",
			Method: http.MethodDelete, Version: "v3.0", Path: []string{"OS-AGENCY", "agencies", "{0}"},
			ReadVersion: "v3.0", ReadPath: []string{"OS-AGENCY", "agencies", "{0}"}, ReadKey: "agency",
			SuccessCodes: []int{http.StatusNoContent},
			Risk:         "Removes delegated access and can interrupt dependent services. The agency object backup does not include its grants or preserve its original ID.",
		},
		{
			Name: "policy-create", CommandPath: []string{"policies"}, Use: "create", Short: "Create an IAM custom policy",
			Method: http.MethodPost, Version: "v3.0", Path: []string{"OS-ROLE", "roles"},
			BodyKey: "role", RequiredFields: []string{"display_name", "type", "description", "policy"}, ValidateBody: validateInventoryPolicy,
			ResponseKey: "role", SuccessCodes: []int{http.StatusCreated}, Create: true,
		},
		{
			Name: "policy-update", CommandPath: []string{"policies"}, Use: "update POLICY_ID", Short: "Update an IAM custom policy",
			Method: http.MethodPatch, Version: "v3.0", Path: []string{"OS-ROLE", "roles", "{0}"},
			// OTC requires the complete policy fields even though this is PATCH.
			BodyKey: "role", RequiredFields: []string{"display_name", "type", "description", "policy"}, ValidateBody: validateInventoryPolicy,
			ReadVersion: "v3.0", ReadPath: []string{"OS-ROLE", "roles", "{0}"}, ReadKey: "role",
			ResponseKey: "role", SuccessCodes: []int{http.StatusOK},
			Risk: "Changes permissions for every existing assignment of this policy.",
		},
		{
			Name: "policy-delete", CommandPath: []string{"policies"}, Use: "delete POLICY_ID", Short: "Delete an IAM custom policy",
			Method: http.MethodDelete, Version: "v3.0", Path: []string{"OS-ROLE", "roles", "{0}"},
			ReadVersion: "v3.0", ReadPath: []string{"OS-ROLE", "roles", "{0}"}, ReadKey: "role",
			// Unlike the other resource DELETE APIs, OTC documents 200, no body.
			SuccessCodes: []int{http.StatusOK},
			Risk:         "Removes a permission definition. The policy backup does not include its assignments or preserve its original ID.",
		},
	}
	// Each relationship has a documented HEAD on exactly the mutation path.
	// 204 means present; 404 means absent. Both adding and removing a relation
	// require a reviewed snapshot, so neither operation is marked Create.
	for _, relation := range []struct {
		name, resource, add, remove, args, version, risk string
		path                                             []string
	}{
		{"group-user", "groups", "add-user", "remove-user", "GROUP_ID USER_ID", "v3", "Changes all permissions the user receives through this group.", []string{"groups", "{0}", "users", "{1}"}},
		{"group-domain", "groups", "grant-domain", "revoke-domain", "GROUP_ID DOMAIN_ID ROLE_ID", "v3", "Changes the group's global-service permissions in this account.", []string{"domains", "{1}", "groups", "{0}", "roles", "{2}"}},
		{"group-project", "groups", "grant-project", "revoke-project", "GROUP_ID PROJECT_ID ROLE_ID", "v3", "Changes the group's permissions in this project.", []string{"projects", "{1}", "groups", "{0}", "roles", "{2}"}},
		{"group-inherited", "groups", "grant-inherited", "revoke-inherited", "GROUP_ID DOMAIN_ID ROLE_ID", "v3", "Changes the group's inherited permissions across all projects in this account.", []string{"OS-INHERIT", "domains", "{1}", "groups", "{0}", "roles", "{2}", "inherited_to_projects"}},
		{"agency-domain", "agencies", "grant-domain", "revoke-domain", "AGENCY_ID DOMAIN_ID ROLE_ID", "v3.0", "Changes delegated access to global services in this account.", []string{"OS-AGENCY", "domains", "{1}", "agencies", "{0}", "roles", "{2}"}},
		{"agency-project", "agencies", "grant-project", "revoke-project", "AGENCY_ID PROJECT_ID ROLE_ID", "v3.0", "Changes delegated access to this project's resources.", []string{"OS-AGENCY", "projects", "{1}", "agencies", "{0}", "roles", "{2}"}},
		{"agency-inherited", "agencies", "grant-inherited", "revoke-inherited", "AGENCY_ID DOMAIN_ID ROLE_ID", "v3.0", "Changes delegated access across all projects in this account.", []string{"OS-INHERIT", "domains", "{1}", "agencies", "{0}", "roles", "{2}", "inherited_to_projects"}},
	} {
		for _, action := range []struct{ name, command, method string }{
			{"add", relation.add, http.MethodPut},
			{"remove", relation.remove, http.MethodDelete},
		} {
			specs = append(specs, MutationSpec{
				Name: relation.name + "-" + action.name, CommandPath: []string{relation.resource}, Use: action.command + " " + relation.args,
				Short: "Change one explicit IAM authorization relationship", Method: action.method, Version: relation.version,
				Path: append([]string(nil), relation.path...), ReadVersion: relation.version, ReadPath: append([]string(nil), relation.path...),
				SnapshotMethod: http.MethodHead, SuccessCodes: []int{http.StatusNoContent}, Risk: relation.risk,
			})
		}
	}
	return specs
}

func validateInventoryUserCreate(body Record) error {
	if err := inventoryMutationFields(body, "name", "domain_id", "password", "email", "areacode", "phone", "enabled", "pwd_status", "xuser_type", "xuser_id", "description"); err != nil {
		return err
	}
	if err := inventoryMutationRequiredStrings(body, "name", "domain_id"); err != nil {
		return err
	}
	return validateInventoryUser(body)
}

func validateInventoryUserUpdate(body Record) error {
	if err := inventoryMutationFields(body, "name", "password", "email", "areacode", "phone", "enabled", "pwd_status", "xuser_type", "xuser_id", "description", "access_mode"); err != nil {
		return err
	}
	return validateInventoryUser(body)
}

func validateInventoryUser(body Record) error {
	if err := inventoryMutationStrings(body, "name", "domain_id", "password", "email", "areacode", "phone", "xuser_type", "xuser_id", "description", "access_mode"); err != nil {
		return err
	}
	for _, field := range []string{"enabled", "pwd_status"} {
		if value, exists := body[field]; exists {
			if _, ok := value.(bool); !ok {
				return fmt.Errorf("%s must be a boolean", field)
			}
		}
	}
	if err := inventoryMutationIDs(body, "domain_id"); err != nil {
		return err
	}
	if err := inventoryMutationPair(body, "areacode", "phone"); err != nil {
		return err
	}
	if err := inventoryMutationPair(body, "xuser_type", "xuser_id"); err != nil {
		return err
	}
	if _, exists := body["access_mode"]; exists {
		return inventoryMutationEnum(body, "access_mode", "default", "programmatic", "console")
	}
	return nil
}

func validateInventoryGroup(body Record) error {
	if err := inventoryMutationFields(body, "name", "description", "domain_id"); err != nil {
		return err
	}
	if err := inventoryMutationStrings(body, "name", "description", "domain_id"); err != nil {
		return err
	}
	return inventoryMutationIDs(body, "domain_id")
}

func validateInventoryProjectCreate(body Record) error {
	if err := inventoryMutationFields(body, "name", "description", "parent_id", "domain_id"); err != nil {
		return err
	}
	if err := inventoryMutationRequiredStrings(body, "name", "parent_id"); err != nil {
		return err
	}
	return validateInventoryProjectFields(body)
}

func validateInventoryProject(body Record) error {
	if err := inventoryMutationFields(body, "name", "description"); err != nil {
		return err
	}
	return validateInventoryProjectFields(body)
}

func validateInventoryProjectFields(body Record) error {
	if err := inventoryMutationStrings(body, "name", "description", "parent_id", "domain_id"); err != nil {
		return err
	}
	return inventoryMutationIDs(body, "parent_id", "domain_id")
}

func validateInventoryProjectStatus(body Record) error {
	if err := inventoryMutationFields(body, "status"); err != nil {
		return err
	}
	return inventoryMutationEnum(body, "status", "normal", "suspended")
}

func validateInventoryAgencyCreate(body Record) error {
	if err := inventoryMutationFields(body, "name", "domain_id", "trust_domain_id", "trust_domain_name", "description", "duration"); err != nil {
		return err
	}
	if err := inventoryMutationRequiredStrings(body, "name", "domain_id"); err != nil {
		return err
	}
	if err := validateInventoryAgency(body); err != nil {
		return err
	}
	_, hasID := body["trust_domain_id"]
	_, hasName := body["trust_domain_name"]
	if !hasID && !hasName {
		return fmt.Errorf("agency creation requires trust_domain_id or trust_domain_name")
	}
	if value, exists := body["duration"]; exists && value != nil {
		return inventoryMutationEnum(body, "duration", "FOREVER", "ONEDAY")
	}
	return nil
}

func validateInventoryAgencyUpdate(body Record) error {
	if err := inventoryMutationFields(body, "trust_domain_id", "trust_domain_name", "description"); err != nil {
		return err
	}
	if err := validateInventoryAgency(body); err != nil {
		return err
	}
	// OTC requires both trust selectors on update, but at least one on create.
	return inventoryMutationPair(body, "trust_domain_id", "trust_domain_name")
}

func validateInventoryAgency(body Record) error {
	if err := inventoryMutationStrings(body, "name", "description", "domain_id", "trust_domain_id", "trust_domain_name"); err != nil {
		return err
	}
	if _, exists := body["trust_domain_name"]; exists {
		if err := inventoryMutationRequiredStrings(body, "trust_domain_name"); err != nil {
			return err
		}
	}
	return inventoryMutationIDs(body, "domain_id", "trust_domain_id")
}

func validateInventoryPolicy(body Record) error {
	if err := inventoryMutationFields(body, "display_name", "description", "description_cn", "type", "policy"); err != nil {
		return err
	}
	if err := inventoryMutationRequiredStrings(body, "display_name", "description"); err != nil {
		return err
	}
	if err := inventoryMutationStrings(body, "description_cn"); err != nil {
		return err
	}
	if err := inventoryMutationEnum(body, "type", "AX", "XA"); err != nil {
		return err
	}
	policy, ok := inventoryMutationObject(body["policy"])
	if !ok {
		return fmt.Errorf("policy must be an object")
	}
	if err := inventoryMutationFields(policy, "Version", "Statement"); err != nil {
		return err
	}
	if err := inventoryMutationEnum(policy, "Version", "1.1"); err != nil {
		return err
	}
	statements, ok := policy["Statement"].([]any)
	if !ok || len(statements) == 0 || len(statements) > 8 {
		return fmt.Errorf("policy.Statement must contain 1 to 8 objects")
	}
	for i, value := range statements {
		statement, ok := inventoryMutationObject(value)
		if !ok {
			return fmt.Errorf("policy.Statement[%d] must be an object", i)
		}
		if err := inventoryMutationFields(statement, "Action", "Effect", "Condition", "Resource"); err != nil {
			return err
		}
		if err := inventoryMutationStringArray(statement["Action"], "Action", 100); err != nil {
			return err
		}
		if err := inventoryMutationEnum(statement, "Effect", "Allow", "Deny"); err != nil {
			return err
		}
		if condition, exists := statement["Condition"]; exists {
			if object, ok := inventoryMutationObject(condition); !ok || len(object) > 10 {
				return fmt.Errorf("policy Condition must be an object with at most 10 conditions")
			}
		}
		if resource, exists := statement["Resource"]; exists {
			// Cloud-service policies use an array; agency policies use {"uri": [...]}.
			maximum := 10
			if object, ok := inventoryMutationObject(resource); ok {
				if err := inventoryMutationFields(object, "uri"); err != nil {
					return err
				}
				resource = object["uri"]
				maximum = 0 // OTC gives no URI-array count limit for agency policies.
			}
			if err := inventoryMutationStringArray(resource, "Resource", maximum); err != nil {
				return err
			}
			for _, value := range resource.([]any) {
				if utf8.RuneCountInString(value.(string)) > 128 {
					return fmt.Errorf("each Resource string must contain at most 128 characters")
				}
			}
		}
	}
	return nil
}

func inventoryMutationStrings(body Record, fields ...string) error {
	for _, field := range fields {
		if value, exists := body[field]; exists {
			if _, ok := value.(string); !ok {
				return fmt.Errorf("%s must be a string", field)
			}
		}
	}
	return nil
}

func inventoryMutationFields(body Record, allowed ...string) error {
	for field := range body {
		known := false
		for _, candidate := range allowed {
			known = known || field == candidate
		}
		if !known {
			return fmt.Errorf("request contains a field not documented for this operation")
		}
	}
	return nil
}

func inventoryMutationRequiredStrings(body Record, fields ...string) error {
	for _, field := range fields {
		value, ok := body[field].(string)
		if !ok || strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s must be a non-empty string", field)
		}
	}
	return nil
}

func inventoryMutationIDs(body Record, fields ...string) error {
	for _, field := range fields {
		if raw, exists := body[field]; exists {
			id, ok := raw.(string)
			if !ok {
				return fmt.Errorf("%s must be a string ID", field)
			}
			if err := ValidateID(field, id); err != nil {
				return err
			}
		}
	}
	return nil
}

func inventoryMutationPair(body Record, first, second string) error {
	_, hasFirst := body[first]
	_, hasSecond := body[second]
	if hasFirst != hasSecond {
		return fmt.Errorf("%s and %s must be supplied together", first, second)
	}
	return nil
}

func inventoryMutationEnum(body Record, field string, choices ...string) error {
	value, ok := body[field].(string)
	if ok {
		for _, choice := range choices {
			if value == choice {
				return nil
			}
		}
	}
	// Never interpolate untrusted values: a misplaced password must not leak.
	return fmt.Errorf("%s must be one of %s", field, strings.Join(choices, ", "))
}

func inventoryMutationStringArray(value any, field string, maximum int) error {
	items, ok := value.([]any)
	if !ok || len(items) == 0 {
		return fmt.Errorf("%s must be a non-empty array of strings", field)
	}
	if maximum > 0 && len(items) > maximum {
		return fmt.Errorf("%s must contain at most %d strings", field, maximum)
	}
	for _, item := range items {
		if value, ok := item.(string); !ok || strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s must contain non-empty strings", field)
		}
	}
	return nil
}

func inventoryMutationObject(value any) (Record, bool) {
	switch object := value.(type) {
	case Record:
		return object, object != nil
	case map[string]any:
		return Record(object), object != nil
	default:
		return nil, false
	}
}
