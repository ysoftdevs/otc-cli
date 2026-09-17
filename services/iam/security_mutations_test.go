package iam

import (
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func TestSecurityMutationContracts(t *testing.T) {
	// These expectations are the API contract: in particular credentials use
	// PUT, password changes use POST, and all policy paths contain hyphens.
	tests := []struct {
		name, method, version, path, body, readPath, readKey string
		code                                                 int
	}{
		{"credentials-create", http.MethodPost, "v3.0", "OS-CREDENTIAL/credentials", "credential", "", "", http.StatusCreated},
		{"credentials-update", http.MethodPut, "v3.0", "OS-CREDENTIAL/credentials/{0}", "credential", "OS-CREDENTIAL/credentials/{0}", "credential", http.StatusOK},
		{"credentials-delete", http.MethodDelete, "v3.0", "OS-CREDENTIAL/credentials/{0}", "", "OS-CREDENTIAL/credentials/{0}", "credential", http.StatusNoContent},
		{"mfa-create", http.MethodPost, "v3.0", "OS-MFA/virtual-mfa-devices", "virtual_mfa_device", "", "", http.StatusCreated},
		{"login-protection-update", http.MethodPut, "v3.0", "OS-USER/users/{0}/login-protect", "login_protect", "OS-USER/users/{0}/login-protect", "login_protect", http.StatusOK},
		{"users-change-password", http.MethodPost, "v3", "users/{0}/password", "user", "users/{0}", "user", http.StatusNoContent},
		{"security-set-password-policy", http.MethodPut, "v3.0", "OS-SECURITYPOLICY/domains/{0}/password-policy", "password_policy", "OS-SECURITYPOLICY/domains/{0}/password-policy", "password_policy", http.StatusOK},
		{"security-set-login-policy", http.MethodPut, "v3.0", "OS-SECURITYPOLICY/domains/{0}/login-policy", "login_policy", "OS-SECURITYPOLICY/domains/{0}/login-policy", "login_policy", http.StatusOK},
		{"security-set-protect-policy", http.MethodPut, "v3.0", "OS-SECURITYPOLICY/domains/{0}/protect-policy", "protect_policy", "OS-SECURITYPOLICY/domains/{0}/protect-policy", "protect_policy", http.StatusOK},
		{"security-set-api-acl-policy", http.MethodPut, "v3.0", "OS-SECURITYPOLICY/domains/{0}/api-acl-policy", "api_acl_policy", "OS-SECURITYPOLICY/domains/{0}/api-acl-policy", "api_acl_policy", http.StatusOK},
		{"security-set-console-acl-policy", http.MethodPut, "v3.0", "OS-SECURITYPOLICY/domains/{0}/console-acl-policy", "console_acl_policy", "OS-SECURITYPOLICY/domains/{0}/console-acl-policy", "console_acl_policy", http.StatusOK},
	}
	specs := make(map[string]MutationSpec)
	for _, spec := range securityMutationSpecs() {
		if _, duplicate := specs[spec.Name]; duplicate {
			t.Fatalf("duplicate security mutation %q", spec.Name)
		}
		specs[spec.Name] = spec
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			spec, ok := specs[test.name]
			if !ok {
				t.Fatal("missing security mutation")
			}
			if spec.Method != test.method || spec.Version != test.version || strings.Join(spec.Path, "/") != test.path || spec.BodyKey != test.body {
				t.Errorf("write does not match documented endpoint: %s /%s/%s, envelope %q", spec.Method, spec.Version, strings.Join(spec.Path, "/"), spec.BodyKey)
			}
			if strings.Join(spec.ReadPath, "/") != test.readPath || spec.ReadKey != test.readKey {
				t.Error("snapshot does not target the resource being changed")
			}
			if test.readPath != "" && (spec.ReadVersion != test.version || spec.SnapshotMethod != "") {
				t.Error("snapshot must use the documented GET API version")
			}
			if !reflect.DeepEqual(spec.SuccessCodes, []int{test.code}) {
				t.Errorf("success codes = %v, want only %d", spec.SuccessCodes, test.code)
			}
			if spec.Risk == "" {
				t.Error("security mutation has no operational risk description")
			}
		})
	}
}

func TestSecurityMutationsRequireSecretOutputForCredentialCreation(t *testing.T) {
	for _, spec := range securityMutationSpecs() {
		switch spec.Name {
		case "credentials-create", "mfa-create":
			if !spec.SensitiveResponse || !spec.Create || spec.ResponseKey == "" {
				t.Errorf("%s could lose or print its one-time secret", spec.Name)
			}
		case "users-change-password":
			if !reflect.DeepEqual(spec.RequiredFields, []string{"password", "original_password"}) || spec.ResponseKey != "" {
				t.Error("password change must require both passwords and expect no response document")
			}
			if !strings.Contains(spec.Risk, "cannot restore") {
				t.Error("password snapshot limitation is not disclosed")
			}
		case "login-protection-update":
			if !spec.AllowMissing || spec.Create {
				t.Error("login-protection update must support a never-configured user and preserve backup requirements")
			}
		}
	}
}

func TestSecurityMutationInputRequiresCompleteEnvelope(t *testing.T) {
	for _, test := range []struct {
		name, operation, body string
		args                  []string
		valid                 bool
	}{
		{"creation requires user", "credentials-create", `{"credential":{"description":"fixture"}}`, nil, false},
		{"MFA requires user", "mfa-create", `{"virtual_mfa_device":{"name":"fixture"}}`, nil, false},
		{"MFA requires name", "mfa-create", `{"virtual_mfa_device":{"user_id":"user-1"}}`, nil, false},
		{"protection requires method", "login-protection-update", `{"login_protect":{"enabled":false}}`, []string{"user-1"}, false},
		{"false is a supplied setting", "login-protection-update", `{"login_protect":{"enabled":false,"verification_method":"vmfa"}}`, []string{"user-1"}, true},
		{"password requires original", "users-change-password", `{"user":{"password":"secret-sentinel"}}`, []string{"user-1"}, false},
		{"ACL requires both lists", "security-set-api-acl-policy", `{"api_acl_policy":{"allow_ip_ranges":[]}}`, []string{"domain-1"}, false},
		{"operation protection required", "security-set-protect-policy", `{"protect_policy":{"admin_check":"off"}}`, []string{"domain-1"}, false},
		{"bare policy rejected", "security-set-password-policy", `{"minimum_password_length":12}`, []string{"domain-1"}, false},
		{"extra envelope rejected", "credentials-update", `{"credential":{"status":"inactive"},"secret":"secret-sentinel"}`, []string{"key-1"}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateMutationInput(test.operation, test.args, []byte(test.body))
			if (err == nil) != test.valid {
				t.Errorf("input validation = %v, want valid=%t", err, test.valid)
			}
			if err != nil && strings.Contains(err.Error(), "secret-sentinel") {
				t.Error("input validation leaked credential content")
			}
		})
	}
}

func TestSecurityMutationBodyValidation(t *testing.T) {
	tests := []struct {
		name, operation, body string
		valid                 bool
	}{
		{"create credential", "credentials-create", `{"user_id":"user-1","description":""}`, true},
		{"credential user ID injection", "credentials-create", `{"user_id":"user?other=1"}`, false},
		{"deactivate credential", "credentials-update", `{"status":"inactive"}`, true},
		{"credential string status", "credentials-update", `{"status":false}`, false},
		{"credential unsupported status", "credentials-update", `{"status":"disabled"}`, false},
		{"credential secret field", "credentials-update", `{"secret":"secret-sentinel"}`, false},
		{"empty update", "credentials-update", `{}`, false},
		{"create MFA", "mfa-create", `{"name":"My MFA device","user_id":"user-1"}`, true},
		{"empty MFA name", "mfa-create", `{"name":"","user_id":"user-1"}`, false},
		{"long MFA name", "mfa-create", `{"name":"` + strings.Repeat("a", 65) + `","user_id":"user-1"}`, false},
		{"disable login protection", "login-protection-update", `{"enabled":false,"verification_method":"vmfa"}`, true},
		{"string login enabled", "login-protection-update", `{"enabled":"false","verification_method":"vmfa"}`, false},
		{"unsupported login method", "login-protection-update", `{"enabled":true,"verification_method":"totp"}`, false},
		{"change password", "users-change-password", `{"password":"new-secret-sentinel","original_password":"old-secret-sentinel"}`, true},
		{"non-string password", "users-change-password", `{"password":{"secret-sentinel":true},"original_password":"old-secret-sentinel"}`, false},
		{"empty password", "users-change-password", `{"password":"","original_password":"old-secret-sentinel"}`, false},
		{"password limits", "security-set-password-policy", `{"minimum_password_length":32,"minimum_password_age":0,"password_not_username_or_invert":false}`, true},
		{"password below limit", "security-set-password-policy", `{"minimum_password_length":5}`, false},
		{"password fractional limit", "security-set-password-policy", `{"minimum_password_length":8.5}`, false},
		{"password string limit", "security-set-password-policy", `{"minimum_password_length":"8"}`, false},
		{"password read-only field", "security-set-password-policy", `{"password_requirements":"server-derived text"}`, false},
		{"login limits", "security-set-login-policy", `{"session_timeout":1440,"account_validity_period":0,"show_recent_login_info":false}`, true},
		{"login timeout below range", "security-set-login-policy", `{"session_timeout":1}`, false},
		{"lockout out of range", "security-set-login-policy", `{"lockout_duration":31}`, false},
		{"operation protection", "security-set-protect-policy", `{"operation_protection":false,"allow_user":{"manage_accesskey":false}}`, true},
		{"designated verifier", "security-set-protect-policy", `{"operation_protection":true,"admin_check":"on","scene":"email","email":"verify@example.com"}`, true},
		{"missing verifier scene", "security-set-protect-policy", `{"operation_protection":true,"admin_check":"on"}`, false},
		{"missing verifier address", "security-set-protect-policy", `{"operation_protection":true,"admin_check":"on","scene":"mobile"}`, false},
		{"string user permission", "security-set-protect-policy", `{"operation_protection":true,"allow_user":{"manage_password":"true"}}`, false},
		{"IPv4 ACL", "security-set-api-acl-policy", `{"allow_address_netmasks":[{"address_netmask":"192.0.2.1/24"}],"allow_ip_ranges":[{"ip_range":"198.51.100.1-198.51.100.10","description":"office"}]}`, true},
		{"explicit empty ACL", "security-set-console-acl-policy", `{"allow_address_netmasks":[],"allow_ip_ranges":[]}`, true},
		{"null ACL", "security-set-api-acl-policy", `{"allow_address_netmasks":null,"allow_ip_ranges":[]}`, false},
		{"IPv6 unsupported by API", "security-set-api-acl-policy", `{"allow_address_netmasks":[{"address_netmask":"2001:db8::/64"}],"allow_ip_ranges":[]}`, false},
		{"reversed IP range", "security-set-console-acl-policy", `{"allow_address_netmasks":[],"allow_ip_ranges":[{"ip_range":"198.51.100.10-198.51.100.1"}]}`, false},
		{"ACL missing address", "security-set-console-acl-policy", `{"allow_address_netmasks":[{"description":"missing address"}],"allow_ip_ranges":[]}`, false},
		{"unknown nested ACL field", "security-set-api-acl-policy", `{"allow_address_netmasks":[{"address_netmask":"192.0.2.0/24","enabled":true}],"allow_ip_ranges":[]}`, false},
	}
	specs := make(map[string]MutationSpec)
	for _, spec := range securityMutationSpecs() {
		specs[spec.Name] = spec
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var body Record
			if err := decode([]byte(test.body), &body); err != nil {
				t.Fatalf("invalid test fixture: %v", err)
			}
			validate := specs[test.operation].ValidateBody
			if validate == nil {
				t.Fatalf("%s lacks body validation", test.operation)
			}
			err := validate(body)
			if (err == nil) != test.valid {
				t.Errorf("validation = %v, want valid=%t", err, test.valid)
			}
			if err != nil && strings.Contains(err.Error(), "secret-sentinel") {
				t.Error("validation error leaked credential content")
			}
		})
	}
}
