package iam

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Federation endpoints and request envelopes follow the OTC IAM API reference:
// https://docs.otc.t-systems.com/identity-access-management/iam-api-ref.pdf
// See Federated Identity Authentication Management, pages 323–382. In particular,
// OIDC uses v3.0/identity-providers, while Keystone uses v3/identity_providers.
func federationMutationSpecs() []MutationSpec {
	providerPath := []string{"OS-FEDERATION", "identity_providers", "{0}"}
	oidcPath := []string{"OS-FEDERATION", "identity-providers", "{0}", "openid-connect-config"}
	mappingPath := []string{"OS-FEDERATION", "mappings", "{0}"}
	protocolPath := []string{"OS-FEDERATION", "identity_providers", "{0}", "protocols", "{1}"}
	metadataPath := []string{"OS-FEDERATION", "identity_providers", "{0}", "protocols", "{1}", "metadata"}
	return []MutationSpec{
		{
			Name: "provider.create", CommandPath: []string{"providers"}, Use: "create PROVIDER_ID",
			Short: "Create a SAML identity provider", Method: http.MethodPut, Version: "v3", Path: providerPath,
			BodyKey: "identity_provider", ValidateBody: validateFederationProviderCreate,
			ReadVersion: "v3", ReadPath: providerPath, ReadKey: "identity_provider",
			ResponseKey: "identity_provider", SuccessCodes: []int{http.StatusCreated}, Create: true,
			Risk: "Creates an identity provider; enabling it permits federated sign-in once trust and protocol mapping are configured.",
		},
		{
			Name: "provider.update", CommandPath: []string{"providers"}, Use: "update PROVIDER_ID",
			Short: "Update SAML identity provider settings", Method: http.MethodPatch, Version: "v3", Path: providerPath,
			BodyKey: "identity_provider", ValidateBody: validateFederationProviderUpdate,
			ReadVersion: "v3", ReadPath: providerPath, ReadKey: "identity_provider",
			ResponseKey: "identity_provider", SuccessCodes: []int{http.StatusOK},
			Risk: "Enabling or disabling this provider changes sign-in availability for all of its federated users.",
		},
		{
			Name: "provider.delete", CommandPath: []string{"providers"}, Use: "delete PROVIDER_ID",
			Short: "Delete a SAML or OIDC identity provider", Method: http.MethodDelete, Version: "v3", Path: providerPath,
			ReadVersion: "v3", ReadPath: providerPath, ReadKey: "identity_provider",
			SuccessCodes: []int{http.StatusNoContent}, Preflight: preflightFederationProviderDelete,
			Risk: "Deletes this provider after protocol bindings and stored trust are absent. Its backup does not restore federated users or their identifiers.",
		},
		{
			Name: "oidc.create", CommandPath: []string{"providers", "oidc"}, Use: "create PROVIDER_ID",
			Short: "Create OIDC identity provider configuration", Method: http.MethodPost, Version: "v3.0", Path: oidcPath,
			BodyKey: "openid_connect_config", RequiredFields: []string{"access_mode", "idp_url", "client_id", "signing_key"},
			ValidateBody: validateFederationOIDCCreate, ReadVersion: "v3.0", ReadPath: oidcPath, ReadKey: "openid_connect_config",
			ResponseKey: "openid_connect_config", SuccessCodes: []int{http.StatusCreated}, Create: true,
			Risk: "Defines the issuer, client and signing keys trusted for OIDC sign-in; incorrect values can admit unintended identities or block users.",
		},
		{
			Name: "oidc.update", CommandPath: []string{"providers", "oidc"}, Use: "update PROVIDER_ID",
			Short: "Update OIDC configuration or public signing keys", Method: http.MethodPut, Version: "v3.0", Path: oidcPath,
			BodyKey: "openid_connect_config", ValidateBody: validateFederationOIDCUpdate,
			ReadVersion: "v3.0", ReadPath: oidcPath, ReadKey: "openid_connect_config",
			ResponseKey: "openid_connect_config", SuccessCodes: []int{http.StatusOK},
			Risk: "Changing the issuer, client or signing keys can interrupt or broaden access for every user of this provider. Removing old keys can break tokens issued before rotation.",
		},
		{
			Name: "mapping.create", CommandPath: []string{"mappings"}, Use: "create MAPPING_ID",
			Short: "Create a complete federation mapping", Method: http.MethodPut, Version: "v3", Path: mappingPath,
			BodyKey: "mapping", RequiredFields: []string{"rules"}, ValidateBody: validateFederationMapping,
			ReadVersion: "v3", ReadPath: mappingPath, ReadKey: "mapping",
			ResponseKey: "mapping", SuccessCodes: []int{http.StatusCreated}, Create: true,
			Risk: "Defines how claims become local users and group memberships. Once bound to a protocol, these rules grant permissions to matching federated users.",
		},
		{
			Name: "mapping.update", CommandPath: []string{"mappings"}, Use: "update MAPPING_ID",
			Short: "Replace all rules in a federation mapping", Method: http.MethodPatch, Version: "v3", Path: mappingPath,
			BodyKey: "mapping", RequiredFields: []string{"rules"}, ValidateBody: validateFederationMapping,
			ReadVersion: "v3", ReadPath: mappingPath, ReadKey: "mapping",
			ResponseKey: "mapping", SuccessCodes: []int{http.StatusOK},
			Risk: "Replaces the entire rule set for every protocol using this mapping. Omitted or overly broad rules can lock out users or increase their access.",
		},
		{
			Name: "mapping.delete", CommandPath: []string{"mappings"}, Use: "delete MAPPING_ID",
			Short: "Delete a federation mapping", Method: http.MethodDelete, Version: "v3", Path: mappingPath,
			ReadVersion: "v3", ReadPath: mappingPath, ReadKey: "mapping",
			SuccessCodes: []int{http.StatusNoContent}, Preflight: preflightFederationMappingDelete,
			Risk: "Deletes the mapping rules. Referencing protocol bindings block deletion; the mapping must exist before a protocol can use it again.",
		},
		{
			Name: "protocol.create", CommandPath: []string{"protocols"}, Use: "create PROVIDER_ID PROTOCOL_ID",
			Short: "Register a protocol and bind its mapping", Method: http.MethodPut, Version: "v3", Path: protocolPath,
			BodyKey: "protocol", RequiredFields: []string{"mapping_id"}, ValidateBody: validateFederationProtocol,
			ReadVersion: "v3", ReadPath: protocolPath, ReadKey: "protocol",
			ResponseKey: "protocol", SuccessCodes: []int{http.StatusCreated}, Create: true,
			Risk: "Binds this provider and protocol to the selected mapping; matching federated identities receive the mapped groups' permissions.",
		},
		{
			Name: "protocol.update", CommandPath: []string{"protocols"}, Use: "update PROVIDER_ID PROTOCOL_ID",
			Short: "Change a protocol's mapping binding", Method: http.MethodPatch, Version: "v3", Path: protocolPath,
			BodyKey: "protocol", RequiredFields: []string{"mapping_id"}, ValidateBody: validateFederationProtocol,
			ReadVersion: "v3", ReadPath: protocolPath, ReadKey: "protocol",
			ResponseKey: "protocol", SuccessCodes: []int{http.StatusOK},
			Risk: "Changes the mapping used by every federated user of this provider and protocol; the new rules can interrupt or broaden their access.",
		},
		{
			Name: "protocol.delete", CommandPath: []string{"protocols"}, Use: "delete PROVIDER_ID PROTOCOL_ID",
			Short: "Delete a federation protocol binding", Method: http.MethodDelete, Version: "v3", Path: protocolPath,
			ReadVersion: "v3", ReadPath: protocolPath, ReadKey: "protocol",
			SuccessCodes: []int{http.StatusNoContent},
			Risk:         "Removes this provider's protocol-to-mapping binding and interrupts federated sign-in through that protocol.",
		},
		{
			Name: "saml-metadata.import", CommandPath: []string{"protocols"}, Use: "import-metadata PROVIDER_ID PROTOCOL_ID",
			Short: "Import SAML metadata when none exists", Method: http.MethodPost, Version: "v3-ext", Path: metadataPath,
			BodyKey: "@root", RequiredFields: []string{"domain_id", "metadata"}, ValidateBody: validateFederationMetadata,
			ReadVersion: "v3-ext", ReadPath: metadataPath,
			SuccessCodes: []int{http.StatusCreated}, Create: true,
			Risk: "Establishes SAML signing trust and IdP endpoints. Incorrect metadata can block sign-in or trust an unintended identity provider.",
		},
		{
			Name: "saml-metadata.update", CommandPath: []string{"protocols"}, Use: "update-metadata PROVIDER_ID PROTOCOL_ID",
			Short: "Replace existing imported SAML metadata", Method: http.MethodPost, Version: "v3-ext", Path: metadataPath,
			BodyKey: "@root", RequiredFields: []string{"domain_id", "metadata"}, ValidateBody: validateFederationMetadata,
			ReadVersion: "v3-ext", ReadPath: metadataPath,
			SuccessCodes: []int{http.StatusCreated},
			Risk:         "Replaces SAML signing trust and IdP endpoints; incorrect certificates or entity IDs can interrupt or broaden access for all users of this provider and protocol.",
		},
	}
}

func preflightFederationMappingDelete(s *Service, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("mapping deletion requires one mapping ID")
	}
	providers, err := s.ListProviders()
	if err != nil {
		return fmt.Errorf("cannot enumerate identity providers completely; mapping deletion is blocked")
	}
	for _, provider := range providers {
		id, ok := provider["id"].(string)
		if !ok || ValidateID("provider", id) != nil {
			return fmt.Errorf("provider inventory contains an invalid ID; mapping deletion is blocked")
		}
		protocols, err := s.ListProtocols(id)
		if err != nil {
			return fmt.Errorf("cannot enumerate every provider's protocols; mapping deletion is blocked")
		}
		for _, protocol := range protocols {
			mappingID, ok := protocol["mapping_id"].(string)
			if !ok || mappingID == "" {
				return fmt.Errorf("protocol inventory lacks a mapping ID; mapping deletion is blocked")
			}
			if mappingID == args[0] {
				return fmt.Errorf("mapping is still referenced by a provider protocol; change or remove that binding before deleting the mapping")
			}
		}
	}
	return nil
}

// A provider-only snapshot cannot restore its protocol bindings or trust
// configuration. Permit deletion only after these dependencies are removed.
func preflightFederationProviderDelete(s *Service, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("provider deletion requires one provider ID")
	}
	protocols, err := s.ListProtocols(args[0])
	if err != nil {
		return fmt.Errorf("cannot establish whether the provider has protocol bindings; deletion is blocked")
	}
	if len(protocols) != 0 {
		return fmt.Errorf("provider still has protocol bindings; export and remove them before deleting the provider")
	}
	for _, check := range []struct {
		name string
		spec MutationSpec
	}{
		{"OIDC configuration", MutationSpec{ReadVersion: "v3.0", ReadPath: []string{"OS-FEDERATION", "identity-providers", "{0}", "openid-connect-config"}, ReadKey: "openid_connect_config", Create: true}},
		{"SAML metadata", MutationSpec{ReadVersion: "v3-ext", ReadPath: []string{"OS-FEDERATION", "identity_providers", "{0}", "protocols", "saml", "metadata"}, Create: true}},
	} {
		state, err := s.mutationSnapshot(check.spec, args)
		if err != nil {
			return fmt.Errorf("cannot establish absence of %s; provider deletion is blocked", check.name)
		}
		if state["present"] != false {
			return fmt.Errorf("provider still has %s; provider-only backup is insufficient for deletion", check.name)
		}
	}
	return nil
}

func validateFederationProviderCreate(body Record) error {
	if err := federationBodyFields(body, "sso_type", "description", "enabled"); err != nil {
		return err
	}
	if value, exists := body["sso_type"]; exists && value != "virtual_user_sso" && value != "iam_user_sso" {
		return fmt.Errorf("sso_type must be virtual_user_sso or iam_user_sso")
	}
	return validateFederationProviderFields(body)
}

func validateFederationProviderUpdate(body Record) error {
	if err := federationBodyFields(body, "description", "enabled"); err != nil {
		return err
	}
	if len(body) == 0 {
		return fmt.Errorf("provide description or enabled to update the provider")
	}
	return validateFederationProviderFields(body)
}

func validateFederationProviderFields(body Record) error {
	if value, exists := body["description"]; exists {
		if _, ok := value.(string); !ok {
			return fmt.Errorf("description must be a string")
		}
	}
	if value, exists := body["enabled"]; exists {
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("enabled must be a boolean")
		}
	}
	return nil
}

func validateFederationOIDCCreate(body Record) error {
	for _, field := range []string{"access_mode", "idp_url", "client_id", "signing_key"} {
		if _, ok := body[field]; !ok {
			return fmt.Errorf("%s is required", field)
		}
	}
	return validateFederationOIDCUpdate(body)
}

func validateFederationOIDCUpdate(body Record) error {
	if err := federationBodyFields(body, "access_mode", "idp_url", "client_id", "signing_key", "authorization_endpoint", "scope", "response_type", "response_mode"); err != nil {
		return err
	}
	if len(body) == 0 {
		return fmt.Errorf("provide at least one OIDC configuration field")
	}
	for field, value := range body {
		text, ok := value.(string)
		if !ok || strings.TrimSpace(text) == "" {
			return fmt.Errorf("%s must be a non-empty string", field)
		}
		switch field {
		case "access_mode":
			if text != "program" && text != "program_console" {
				return fmt.Errorf("access_mode must be program or program_console")
			}
		case "idp_url", "authorization_endpoint":
			if len(text) < 10 || len(text) > 255 {
				return fmt.Errorf("%s must contain 10 to 255 characters", field)
			}
			endpoint, err := url.Parse(text)
			if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.User != nil || endpoint.Fragment != "" || (field == "idp_url" && endpoint.RawQuery != "") {
				return fmt.Errorf("%s must be an absolute HTTPS URL without credentials or fragment; issuer queries are not allowed", field)
			}
		case "client_id":
			if len(text) < 5 || len(text) > 255 {
				return fmt.Errorf("client_id must contain 5 to 255 characters")
			}
		case "signing_key":
			if len(text) < 10 || len(text) > 30000 {
				return fmt.Errorf("signing_key must contain 10 to 30000 characters")
			}
			if _, err := parseSigningKeys(text); err != nil {
				return fmt.Errorf("signing_key must contain a supported public JWKS: %w", err)
			}
		case "scope":
			scopes := strings.Fields(text)
			if len(scopes) > 10 || !containsOIDCString(scopes, "openid") {
				return fmt.Errorf("scope must include openid and contain at most 10 space-separated values")
			}
		case "response_type":
			if text != "id_token" {
				return fmt.Errorf("response_type must be id_token")
			}
		case "response_mode":
			if text != "fragment" && text != "form_post" {
				return fmt.Errorf("response_mode must be fragment or form_post")
			}
		}
	}
	if body["access_mode"] == "program_console" {
		for _, field := range []string{"authorization_endpoint", "scope", "response_type", "response_mode"} {
			if _, exists := body[field]; !exists {
				return fmt.Errorf("%s is required when access_mode is program_console", field)
			}
		}
	}
	return nil
}

func validateFederationMapping(body Record) error {
	if err := federationBodyFields(body, "rules"); err != nil {
		return err
	}
	rules, ok := body["rules"].([]any)
	if !ok || len(rules) == 0 {
		return fmt.Errorf("rules must be a non-empty array containing the complete intended mapping")
	}
	for _, rule := range rules {
		object, ok := rule.(map[string]any)
		if !ok {
			return fmt.Errorf("each mapping rule must be an object")
		}
		for _, field := range []string{"local", "remote"} {
			entries, ok := object[field].([]any)
			if !ok || len(entries) == 0 {
				return fmt.Errorf("each mapping rule requires a non-empty %s array", field)
			}
			for _, entry := range entries {
				if item, ok := entry.(map[string]any); !ok || len(item) == 0 {
					return fmt.Errorf("mapping %s entries must be non-empty objects", field)
				}
			}
		}
	}
	return nil
}

func validateFederationProtocol(body Record) error {
	if err := federationBodyFields(body, "mapping_id"); err != nil {
		return err
	}
	id, ok := body["mapping_id"].(string)
	if !ok {
		return fmt.Errorf("mapping_id must be a string")
	}
	return ValidateID("mapping", id)
}

func validateFederationMetadata(body Record) error {
	if err := federationBodyFields(body, "domain_id", "xaccount_type", "metadata"); err != nil {
		return err
	}
	domainID, ok := body["domain_id"].(string)
	if !ok {
		return fmt.Errorf("domain_id must be a string")
	}
	if err := ValidateID("domain", domainID); err != nil {
		return err
	}
	// Unlike ordinary required strings, OTC explicitly allows the empty value.
	if _, ok := body["xaccount_type"].(string); !ok {
		return fmt.Errorf("xaccount_type must be present as a string; use an empty string for the default")
	}
	metadata, ok := body["metadata"].(string)
	if !ok || strings.TrimSpace(metadata) == "" {
		return fmt.Errorf("metadata must contain the IdP metadata XML as a string")
	}
	decoder := xml.NewDecoder(strings.NewReader(metadata))
	depth, roots := 0, 0
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("metadata must contain well-formed XML")
		}
		switch value := token.(type) {
		case xml.StartElement:
			if depth == 0 {
				roots++
			}
			depth++
			if depth > 128 {
				return fmt.Errorf("metadata XML exceeds the nesting limit")
			}
		case xml.EndElement:
			depth--
		case xml.CharData:
			if depth == 0 && strings.TrimSpace(string(value)) != "" {
				return fmt.Errorf("metadata must contain a single XML document")
			}
		case xml.Directive:
			return fmt.Errorf("metadata XML must not contain a DTD or other directives")
		}
	}
	if roots != 1 || depth != 0 {
		return fmt.Errorf("metadata must contain a single complete XML document")
	}
	return nil
}

func federationBodyFields(body Record, allowed ...string) error {
	for field := range body {
		if !containsOIDCString(allowed, field) {
			// Do not echo unknown field names, which could contain pasted secrets.
			return fmt.Errorf("request contains an unsupported federation field")
		}
	}
	return nil
}
