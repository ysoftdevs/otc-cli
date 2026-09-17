package iam

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"unicode/utf8"
)

// Security writes follow the OTC IAM API reference, not generic Keystone APIs:
// https://docs.otc.t-systems.com/identity-access-management/iam-api-ref.pdf
// Access keys: printed pages 49-59; password changes: 113-115;
// security policies: 255-285; login protection and MFA: 295-303.
func securityMutationSpecs() []MutationSpec {
	specs := []MutationSpec{
		{
			Name: "credentials-create", CommandPath: []string{"credentials"}, Use: "create",
			Short: "Create a permanent access key for an IAM user", Method: http.MethodPost, Version: "v3.0",
			Path: []string{"OS-CREDENTIAL", "credentials"}, BodyKey: "credential", RequiredFields: []string{"user_id"},
			ResponseKey: "credential", SensitiveResponse: true, Create: true, SuccessCodes: []int{http.StatusCreated},
			ValidateBody: validateCredentialCreate,
			Risk:         "Creates a permanent credential. The secret key is returned only on creation and must be saved securely.",
		},
		{
			Name: "credentials-update", CommandPath: []string{"credentials"}, Use: "update ACCESS_KEY",
			Short: "Change a permanent access key's status or description", Method: http.MethodPut, Version: "v3.0",
			Path: []string{"OS-CREDENTIAL", "credentials", "{0}"}, BodyKey: "credential",
			ReadVersion: "v3.0", ReadPath: []string{"OS-CREDENTIAL", "credentials", "{0}"}, ReadKey: "credential",
			ResponseKey: "credential", SuccessCodes: []int{http.StatusOK}, ValidateBody: validateCredentialUpdate,
			Risk: "Deactivating a key can interrupt every workload that uses it, including this CLI's own access.",
		},
		{
			Name: "credentials-delete", CommandPath: []string{"credentials"}, Use: "delete ACCESS_KEY",
			Short: "Delete a permanent access key", Method: http.MethodDelete, Version: "v3.0",
			Path:        []string{"OS-CREDENTIAL", "credentials", "{0}"},
			ReadVersion: "v3.0", ReadPath: []string{"OS-CREDENTIAL", "credentials", "{0}"}, ReadKey: "credential",
			SuccessCodes: []int{http.StatusNoContent},
			Risk:         "Permanently revokes the key and can interrupt dependent workloads. A metadata backup cannot restore the deleted secret.",
		},
		{
			Name: "mfa-create", CommandPath: []string{"mfa"}, Use: "create",
			Short: "Create a virtual MFA device for the authenticated IAM user", Method: http.MethodPost, Version: "v3.0",
			Path: []string{"OS-MFA", "virtual-mfa-devices"}, BodyKey: "virtual_mfa_device", RequiredFields: []string{"name", "user_id"},
			ResponseKey: "virtual_mfa_device", SensitiveResponse: true, Create: true, SuccessCodes: []int{http.StatusCreated},
			ValidateBody: validateMFACreate,
			Risk:         "Creates an MFA seed for the authenticated user. Keep the returned seed secret; creation does not bind the device.",
		},
		{
			Name: "login-protection-update", CommandPath: []string{"login-protection"}, Use: "update USER_ID",
			Short: "Set an IAM user's login verification configuration", Method: http.MethodPut, Version: "v3.0",
			Path: []string{"OS-USER", "users", "{0}", "login-protect"}, BodyKey: "login_protect",
			RequiredFields: []string{"enabled", "verification_method"},
			ReadVersion:    "v3.0", ReadPath: []string{"OS-USER", "users", "{0}", "login-protect"}, ReadKey: "login_protect",
			ResponseKey: "login_protect", SuccessCodes: []int{http.StatusOK}, ValidateBody: validateLoginProtection, AllowMissing: true,
			Risk: "Changes login verification. An unavailable verification method can lock the user out; disabling it weakens login protection.",
		},
		{
			Name: "users-change-password", CommandPath: []string{"users"}, Use: "change-password USER_ID",
			Short: "Change a user's password using the original password", Method: http.MethodPost, Version: "v3",
			Path: []string{"users", "{0}", "password"}, BodyKey: "user", RequiredFields: []string{"password", "original_password"},
			ReadVersion: "v3", ReadPath: []string{"users", "{0}"}, ReadKey: "user",
			SuccessCodes: []int{http.StatusNoContent}, ValidateBody: validatePasswordChange,
			Risk: "Changes a login credential. The snapshot contains user metadata only and cannot restore the old password; the account's password policy is enforced by OTC.",
		},
	}
	for _, policy := range []struct {
		name     string
		required []string
		validate func(Record) error
		risk     string
	}{
		{"password-policy", nil, validatePasswordPolicy, "Changes password requirements for the account and can prevent users from changing or renewing passwords."},
		{"login-policy", nil, validateLoginPolicy, "Changes account-wide login, inactivity and lockout rules; users can lose access."},
		{"protect-policy", []string{"operation_protection"}, validateProtectPolicy, "Changes verification for sensitive operations and users' credential-management permissions; an unavailable verifier can block administration."},
		{"api-acl-policy", []string{"allow_address_netmasks", "allow_ip_ranges"}, validateSecurityACL, "Replaces source IP restrictions for API access. An incorrect allowlist can block this CLI and other account API clients."},
		{"console-acl-policy", []string{"allow_address_netmasks", "allow_ip_ranges"}, validateSecurityACL, "Replaces source IP restrictions for console access. An incorrect allowlist can lock account users out of the console."},
	} {
		key := strings.ReplaceAll(policy.name, "-", "_")
		path := []string{"OS-SECURITYPOLICY", "domains", "{0}", policy.name}
		specs = append(specs, MutationSpec{
			Name: "security-set-" + policy.name, CommandPath: []string{"security"}, Use: "set-" + policy.name + " DOMAIN_ID",
			Short: "Update the account's " + strings.ReplaceAll(policy.name, "-", " "), Method: http.MethodPut, Version: "v3.0",
			Path: path, BodyKey: key, RequiredFields: policy.required, ReadVersion: "v3.0", ReadPath: path, ReadKey: key,
			ResponseKey: key, SuccessCodes: []int{http.StatusOK}, ValidateBody: policy.validate, Risk: policy.risk,
		})
	}
	return specs
}

type securityFieldValidator func(any) error

// Reject misspelled and response-only fields rather than allowing a successful
// API call that silently ignores part of the requested security change.
func validateSecurityFields(body Record, fields map[string]securityFieldValidator) error {
	if len(body) == 0 {
		return fmt.Errorf("security update must contain at least one field")
	}
	for field, value := range body {
		validate, ok := fields[field]
		if !ok {
			return fmt.Errorf("unsupported security request field %q", field)
		}
		if err := validate(value); err != nil {
			return fmt.Errorf("security field %s: %w", field, err)
		}
	}
	return nil
}

func validateCredentialCreate(body Record) error {
	return validateSecurityFields(body, map[string]securityFieldValidator{"user_id": securityUserID, "description": securityString})
}

func validateCredentialUpdate(body Record) error {
	return validateSecurityFields(body, map[string]securityFieldValidator{
		"status": securityEnum("active", "inactive"), "description": securityString,
	})
}

func validateMFACreate(body Record) error {
	return validateSecurityFields(body, map[string]securityFieldValidator{
		"user_id": securityUserID,
		"name": func(value any) error {
			name, ok := value.(string)
			if !ok || utf8.RuneCountInString(name) < 1 || utf8.RuneCountInString(name) > 64 {
				return fmt.Errorf("must be a string containing 1 to 64 characters")
			}
			return nil
		},
	})
}

func validateLoginProtection(body Record) error {
	return validateSecurityFields(body, map[string]securityFieldValidator{
		"enabled": securityBool, "verification_method": securityEnum("sms", "email", "vmfa"),
	})
}

func validatePasswordChange(body Record) error {
	return validateSecurityFields(body, map[string]securityFieldValidator{
		"password": securityNonEmptyString, "original_password": securityNonEmptyString,
	})
}

func validatePasswordPolicy(body Record) error {
	return validateSecurityFields(body, map[string]securityFieldValidator{
		"maximum_consecutive_identical_chars":   securityInteger(0, 32),
		"minimum_password_age":                  securityInteger(0, 1440),
		"minimum_password_length":               securityInteger(6, 32),
		"number_of_recent_passwords_disallowed": securityInteger(0, 10),
		"password_not_username_or_invert":       securityBool,
		"password_validity_period":              securityInteger(0, 180),
		"password_char_combination":             securityInteger(2, 4),
	})
}

func validateLoginPolicy(body Record) error {
	return validateSecurityFields(body, map[string]securityFieldValidator{
		"account_validity_period":    securityInteger(0, 240),
		"custom_info_for_login":      securityString,
		"lockout_duration":           securityInteger(15, 30),
		"login_failed_times":         securityInteger(3, 10),
		"period_with_login_failures": securityInteger(15, 60),
		"session_timeout":            securityInteger(15, 1440),
		"show_recent_login_info":     securityBool,
	})
}

func validateProtectPolicy(body Record) error {
	if err := validateSecurityFields(body, map[string]securityFieldValidator{
		"operation_protection": securityBool,
		"admin_check":          securityEnum("on", "off"),
		"scene":                securityEnum("", "mobile", "email"),
		"mobile":               securityString,
		"email":                securityString,
		"allow_user": func(value any) error {
			fields, ok := securityObject(value)
			if !ok {
				return fmt.Errorf("must be an object")
			}
			return validateSecurityFields(fields, map[string]securityFieldValidator{
				"manage_accesskey": securityBool, "manage_email": securityBool,
				"manage_mobile": securityBool, "manage_password": securityBool,
			})
		},
	}); err != nil {
		return err
	}
	if body["admin_check"] == "on" {
		scene, _ := body["scene"].(string)
		if scene != "mobile" && scene != "email" {
			return fmt.Errorf("admin_check=on requires a mobile or email scene")
		}
		if err := securityNonEmptyString(body[scene]); err != nil {
			return fmt.Errorf("admin_check=on requires a non-empty %s verification destination", scene)
		}
	}
	return nil
}

func validateSecurityACL(body Record) error {
	return validateSecurityFields(body, map[string]securityFieldValidator{
		"allow_address_netmasks": securityACLList("address_netmask", func(value any) error {
			text, ok := value.(string)
			prefix, err := netip.ParsePrefix(text)
			if !ok || err != nil || !prefix.Addr().Is4() {
				return fmt.Errorf("must be an IPv4 CIDR block")
			}
			return nil
		}),
		"allow_ip_ranges": securityACLList("ip_range", func(value any) error {
			text, ok := value.(string)
			startText, endText, found := strings.Cut(text, "-")
			start, startErr := netip.ParseAddr(startText)
			end, endErr := netip.ParseAddr(endText)
			if !ok || !found || startErr != nil || endErr != nil || !start.Is4() || !end.Is4() || start.Compare(end) > 0 {
				return fmt.Errorf("must be an ordered IPv4 address range")
			}
			return nil
		}),
	})
}

func securityACLList(required string, validate securityFieldValidator) securityFieldValidator {
	return func(value any) error {
		items, ok := value.([]any)
		if !ok || items == nil {
			return fmt.Errorf("must be an array of objects")
		}
		for i, item := range items {
			fields, ok := securityObject(item)
			if !ok {
				return fmt.Errorf("entry %d must be an object", i)
			}
			if _, ok := fields[required]; !ok {
				return fmt.Errorf("entry %d requires %s", i, required)
			}
			if err := validateSecurityFields(fields, map[string]securityFieldValidator{required: validate, "description": securityString}); err != nil {
				return fmt.Errorf("entry %d: %w", i, err)
			}
		}
		return nil
	}
}

func securityObject(value any) (Record, bool) {
	switch value := value.(type) {
	case Record:
		return value, value != nil
	case map[string]any:
		return Record(value), value != nil
	default:
		return nil, false
	}
}

func securityUserID(value any) error {
	id, ok := value.(string)
	if !ok {
		return fmt.Errorf("must be a user ID string")
	}
	return ValidateID("user ID", id)
}

func securityString(value any) error {
	if _, ok := value.(string); !ok {
		return fmt.Errorf("must be a string")
	}
	return nil
}

func securityNonEmptyString(value any) error {
	if text, ok := value.(string); !ok || text == "" {
		return fmt.Errorf("must be a non-empty string")
	}
	return nil
}

func securityBool(value any) error {
	if _, ok := value.(bool); !ok {
		return fmt.Errorf("must be a boolean")
	}
	return nil
}

func securityEnum(allowed ...string) securityFieldValidator {
	return func(value any) error {
		text, ok := value.(string)
		if ok {
			for _, candidate := range allowed {
				if text == candidate {
					return nil
				}
			}
		}
		return fmt.Errorf("must be one of %s", strings.Join(allowed, ", "))
	}
}

func securityInteger(min, max int64) securityFieldValidator {
	return func(value any) error {
		var number int64
		switch value := value.(type) {
		case json.Number:
			parsed, err := value.Int64()
			if err != nil {
				return fmt.Errorf("must be an integer from %d to %d", min, max)
			}
			number = parsed
		case int:
			number = int64(value)
		case int64:
			number = value
		default:
			return fmt.Errorf("must be an integer from %d to %d", min, max)
		}
		if number < min || number > max {
			return fmt.Errorf("must be an integer from %d to %d", min, max)
		}
		return nil
	}
}
