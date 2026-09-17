package iam

import (
	"fmt"
	"net/url"
)

// ListCredentials lists permanent access-key metadata. An empty userID selects
// the caller's keys; inspecting another user's keys requires IAM permission.
// The list API does not promise last_use_time; GetCredential supplies it.
func (s *Service) ListCredentials(userID string) ([]Record, error) {
	query := url.Values{}
	if userID != "" {
		if err := ValidateID("user ID", userID); err != nil {
			return nil, err
		}
		query.Set("user_id", userID)
	}
	records, err := s.listVersion("v3.0", "credentials", query, "OS-CREDENTIAL", "credentials")
	if err != nil {
		return nil, err
	}
	for i, record := range records {
		records[i] = credentialMetadata(record)
	}
	return records, nil
}

// GetCredential returns creation and last-use metadata, never the secret key.
func (s *Service) GetCredential(accessKey string) (Record, error) {
	record, err := s.getVersion("v3.0", "credential", "OS-CREDENTIAL", "credentials", accessKey)
	if err != nil {
		return nil, err
	}
	return credentialMetadata(record), nil
}

// Access-key inspection deliberately exposes only documented metadata fields.
func credentialMetadata(record Record) Record {
	return securityMetadata(record, "access", "user_id", "status", "create_time", "last_use_time", "description")
}

func securityMetadata(record Record, fields ...string) Record {
	metadata := make(Record)
	for _, field := range fields {
		if value, ok := record[field]; ok {
			metadata[field] = value
		}
	}
	return metadata
}

// ListMFADevices lists virtual MFA device assignments without device seeds.
func (s *Service) ListMFADevices() ([]Record, error) {
	records, err := s.listVersion("v3.0", "virtual_mfa_devices", nil, "OS-MFA", "virtual-mfa-devices")
	if err != nil {
		return nil, err
	}
	for i, record := range records {
		records[i] = securityMetadata(record, "user_id", "serial_number")
	}
	return records, nil
}

// GetMFADevice reads a user's virtual MFA device assignment.
func (s *Service) GetMFADevice(userID string) (Record, error) {
	record, err := s.getVersion("v3.0", "virtual_mfa_device", "OS-MFA", "users", userID, "virtual-mfa-device")
	if err != nil {
		return nil, err
	}
	return securityMetadata(record, "user_id", "serial_number"), nil
}

// ListLoginProtections includes only users whose protection was configured.
// Users absent from this list must not be reported as explicitly disabled.
func (s *Service) ListLoginProtections() ([]Record, error) {
	return s.listVersion("v3.0", "login_protects", nil, "OS-USER", "login-protects")
}

// GetLoginProtection preserves the API's not-found response for a user whose
// login protection has never been configured.
func (s *Service) GetLoginProtection(userID string) (Record, error) {
	return s.getVersion("v3.0", "login_protect", "OS-USER", "users", userID, "login-protect")
}

// GetSecurityPolicy reads one account-wide security policy. Policy names use
// the API's literal resource names, not arbitrary paths.
func (s *Service) GetSecurityPolicy(domainID, policy string) (Record, error) {
	var key string
	switch policy {
	case "password-policy":
		key = "password_policy"
	case "login-policy":
		key = "login_policy"
	case "protect-policy":
		key = "protect_policy"
	case "api-acl-policy":
		key = "api_acl_policy"
	case "console-acl-policy":
		key = "console_acl_policy"
	default:
		return nil, fmt.Errorf("unknown IAM security policy %q", policy)
	}
	return s.getVersion("v3.0", key, "OS-SECURITYPOLICY", "domains", domainID, policy)
}
