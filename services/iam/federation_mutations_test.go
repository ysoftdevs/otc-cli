package iam

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func TestFederationMutationInputValidation(t *testing.T) {
	publicKeys, err := json.Marshal(testJWKS(testPublicJWK))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		op   string
		body string
		want bool
	}{
		{"create provider disabled", "provider.create", `{"identity_provider":{"enabled":false}}`, true},
		{"update provider description clear", "provider.update", `{"identity_provider":{"description":""}}`, true},
		{"string boolean", "provider.update", `{"identity_provider":{"enabled":"false"}}`, false},
		{"null boolean", "provider.update", `{"identity_provider":{"enabled":null}}`, false},
		{"unknown SSO type", "provider.create", `{"identity_provider":{"sso_type":"saml"}}`, false},
		{"change SSO type", "provider.update", `{"identity_provider":{"sso_type":"iam_user_sso"}}`, false},
		{"wrong case field", "provider.update", `{"identity_provider":{"Enabled":false}}`, false},
		{"empty provider update", "provider.update", `{"identity_provider":{}}`, false},
		{"mapping complete", "mapping.update", `{"mapping":{"rules":[{"local":[{"groups":"{0}"}],"remote":[{"type":"roles"}]}]}}`, true},
		{"mapping cleared", "mapping.update", `{"mapping":{"rules":[]}}`, false},
		{"mapping null", "mapping.update", `{"mapping":{"rules":null}}`, false},
		{"mapping not array", "mapping.update", `{"mapping":{"rules":{}}}`, false},
		{"mapping missing local", "mapping.create", `{"mapping":{"rules":[{"remote":[{"type":"roles"}]}]}}`, false},
		{"mapping empty entry", "mapping.update", `{"mapping":{"rules":[{"local":[{}],"remote":[{"type":"roles"}]}]}}`, false},
		{"mapping duplicate property", "mapping.update", `{"mapping":{"rules":[{}],"rules":[]}}`, false},
		{"protocol mapping", "protocol.update", `{"protocol":{"mapping_id":"mapping-1"}}`, true},
		{"protocol path traversal", "protocol.update", `{"protocol":{"mapping_id":"../other"}}`, false},
		{"OIDC key rotation only", "oidc.update", `{"openid_connect_config":{"signing_key":` + string(publicKeys) + `}}`, true},
		{"OIDC program create", "oidc.create", `{"openid_connect_config":{"access_mode":"program","idp_url":"https://issuer.example","client_id":"client","signing_key":` + string(publicKeys) + `}}`, true},
		{"OIDC console settings", "oidc.update", `{"openid_connect_config":{"access_mode":"program_console","authorization_endpoint":"https://issuer.example/authorize","scope":"openid email profile","response_type":"id_token","response_mode":"form_post"}}`, true},
		{"OIDC console incomplete", "oidc.update", `{"openid_connect_config":{"access_mode":"program_console"}}`, false},
		{"OIDC create missing fields", "oidc.create", `{"openid_connect_config":{"signing_key":` + string(publicKeys) + `}}`, false},
		{"OIDC insecure issuer", "oidc.update", `{"openid_connect_config":{"idp_url":"http://issuer.example"}}`, false},
		{"OIDC issuer credentials", "oidc.update", `{"openid_connect_config":{"idp_url":"https://user:private-fixture@issuer.example"}}`, false},
		{"OIDC issuer query", "oidc.update", `{"openid_connect_config":{"idp_url":"https://issuer.example?secret=private-fixture"}}`, false},
		{"OIDC null issuer", "oidc.update", `{"openid_connect_config":{"idp_url":null}}`, false},
		{"OIDC empty JWKS", "oidc.update", `{"openid_connect_config":{"signing_key":"{\"keys\":[]}"}}`, false},
		{"OIDC private JWKS", "oidc.update", `{"openid_connect_config":{"signing_key":"{\"keys\":[{\"d\":\"private-fixture\"}]}"}}`, false},
		{"OIDC duplicate JWKS properties", "oidc.update", `{"openid_connect_config":{"signing_key":"{\"keys\":[{\"d\":\"private-fixture\"}],\"keys\":[]}"}}`, false},
		{"OIDC missing openid scope", "oidc.update", `{"openid_connect_config":{"scope":"email profile"}}`, false},
		{"OIDC wrong flow", "oidc.update", `{"openid_connect_config":{"response_type":"code"}}`, false},
		{"OIDC bad response mode", "oidc.update", `{"openid_connect_config":{"response_mode":"query"}}`, false},
		{"OIDC client secret field", "oidc.update", `{"openid_connect_config":{"client_secret":"private-fixture"}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := []string{"resource-1"}
			if strings.HasPrefix(tc.op, "protocol.") {
				args = append(args, "saml")
			}
			err := ValidateMutationInput(tc.op, args, json.RawMessage(tc.body))
			if (err == nil) != tc.want {
				t.Fatalf("valid = %v, want %v: %v", err == nil, tc.want, err)
			}
			if err != nil && strings.Contains(err.Error(), "private-fixture") {
				t.Fatalf("validation leaked request content: %v", err)
			}
		})
	}
}

func TestFederationMetadataInputValidation(t *testing.T) {
	for _, tc := range []struct {
		name     string
		metadata string
		want     bool
	}{
		{"document", `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://issuer.example"/>`, true},
		{"XML declaration", `<?xml version="1.0"?><EntityDescriptor/>`, true},
		{"invalid XML", `<EntityDescriptor>`, false},
		{"trailing text", `<EntityDescriptor/>trailing`, false},
		{"multiple documents", `<EntityDescriptor/><EntityDescriptor/>`, false},
		{"DTD", `<!DOCTYPE x [<!ENTITY external SYSTEM "file:///private-fixture">]><x>&external;</x>`, false},
		{"empty document", ``, false},
		{"nested document", strings.Repeat("<x>", 129) + strings.Repeat("</x>", 129), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, err := json.Marshal(Record{"domain_id": "domain-1", "xaccount_type": "", "metadata": tc.metadata})
			if err != nil {
				t.Fatal(err)
			}
			err = ValidateMutationInput("saml-metadata.import", []string{"provider-1", "saml"}, body)
			if (err == nil) != tc.want {
				t.Fatalf("valid = %v, want %v: %v", err == nil, tc.want, err)
			}
			if err != nil && strings.Contains(err.Error(), "private-fixture") {
				t.Fatal("validation leaked XML content")
			}
		})
	}
	for _, body := range []string{
		`{"domain_id":"domain-1","metadata":"<x/>"}`,
		`{"domain_id":"domain-1","xaccount_type":null,"metadata":"<x/>"}`,
		`{"domain_id":"domain-1","xaccount_type":"","data":"<x/>"}`,
		`{"metadata":{"domain_id":"domain-1","xaccount_type":"","metadata":"<x/>"}}`,
	} {
		if err := ValidateMutationInput("saml-metadata.update", []string{"provider-1", "saml"}, json.RawMessage(body)); err == nil {
			t.Fatal("malformed metadata body accepted")
		}
	}
}

func TestFederationMutationCatalogSafety(t *testing.T) {
	seen := make(map[string]bool)
	for _, spec := range federationMutationSpecs() {
		if seen[spec.Name] {
			t.Fatalf("duplicate operation %s", spec.Name)
		}
		seen[spec.Name] = true
		if strings.TrimSpace(spec.Risk) == "" || spec.Risk == "federation" || len(spec.ReadPath) == 0 || spec.ReadVersion != spec.Version {
			t.Errorf("%s lacks a descriptive risk or matching snapshot version", spec.Name)
		}
		if !reflect.DeepEqual(spec.Path, spec.ReadPath) {
			t.Errorf("%s snapshot does not address the changed resource", spec.Name)
		}
		if len(spec.SuccessCodes) != 1 {
			t.Errorf("%s must accept only its documented success status", spec.Name)
		}
		if spec.Method == http.MethodDelete && (spec.BodyKey != "" || spec.Create || spec.SuccessCodes[0] != http.StatusNoContent) {
			t.Errorf("%s has unsafe delete semantics", spec.Name)
		}
		if spec.BodyKey != "" && spec.ValidateBody == nil {
			t.Errorf("%s accepts a body without semantic validation", spec.Name)
		}
		if strings.HasPrefix(spec.Name, "saml-metadata.") && (spec.BodyKey != "@root" || spec.ReadKey != "" || spec.ResponseKey != "" || spec.SuccessCodes[0] != http.StatusCreated) {
			t.Errorf("%s does not use documented unwrapped metadata request/response", spec.Name)
		}
	}
	if seen["oidc.delete"] {
		t.Fatal("undocumented standalone OIDC config deletion must not be exposed")
	}
}

func TestFederationMetadataPlanProtectsReplacement(t *testing.T) {
	const body = `{"domain_id":"domain-1","xaccount_type":"","metadata":"<new/>"}`
	for _, exists := range []bool{false, true} {
		t.Run(fmt.Sprintf("exists=%v", exists), func(t *testing.T) {
			requests := 0
			service, _ := testService(t, func(w http.ResponseWriter, r *http.Request) {
				requests++
				if r.Method != http.MethodGet || r.URL.Path != "/v3-ext/OS-FEDERATION/identity_providers/provider-1/protocols/saml/metadata" {
					t.Errorf("preview must only GET metadata: %s %s", r.Method, r.URL.Path)
				}
				if !exists {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				fmt.Fprint(w, `{"data":"<old/>","domain_id":"domain-1","xaccount_type":""}`)
			})
			service.client.DomainID = "domain-1"
			args := []string{"provider-1", "saml"}
			_, importErr := service.PlanMutation("saml-metadata.import", args, json.RawMessage(body))
			if (importErr != nil) != exists {
				t.Errorf("import error = %v, want existing metadata to block first import", importErr)
			}
			plan, updateErr := service.PlanMutation("saml-metadata.update", args, json.RawMessage(body))
			if (updateErr == nil) != exists {
				t.Errorf("update error = %v, want missing metadata to block replacement", updateErr)
			}
			if exists && !plan.NeedsBackup {
				t.Error("replacing existing metadata must require a backup")
			}
			if requests != 2 {
				t.Errorf("snapshot request count = %d, want 2", requests)
			}
		})
	}
}

func TestFederationProviderDeletePreflight(t *testing.T) {
	for _, tc := range []struct {
		name           string
		protocolStatus int
		protocolBody   string
		oidcStatus     int
		metadataStatus int
		want           bool
	}{
		{"empty provider", 200, `{"protocols":[],"links":{"next":null}}`, 404, 404, true},
		{"protocol dependency", 200, `{"protocols":[{"id":"saml"}]}`, 404, 404, false},
		{"cannot list protocols", 403, `{}`, 404, 404, false},
		{"invalid protocol list", 200, `{}`, 404, 404, false},
		{"OIDC trust dependency", 200, `{"protocols":[]}`, 200, 404, false},
		{"cannot read OIDC trust", 200, `{"protocols":[]}`, 403, 404, false},
		{"SAML metadata dependency", 200, `{"protocols":[]}`, 404, 200, false},
		{"cannot read SAML metadata", 200, `{"protocols":[]}`, 404, 500, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			service, _ := testService(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("preflight attempted a write: %s", r.Method)
				}
				switch r.URL.Path {
				case "/v3/OS-FEDERATION/identity_providers/provider-1/protocols":
					w.WriteHeader(tc.protocolStatus)
					fmt.Fprint(w, tc.protocolBody)
				case "/v3.0/OS-FEDERATION/identity-providers/provider-1/openid-connect-config":
					w.WriteHeader(tc.oidcStatus)
					fmt.Fprint(w, `{"openid_connect_config":{"client_id":"client"}}`)
				case "/v3-ext/OS-FEDERATION/identity_providers/provider-1/protocols/saml/metadata":
					w.WriteHeader(tc.metadataStatus)
					fmt.Fprint(w, `{"data":"<xml/>"}`)
				default:
					t.Errorf("unexpected preflight request: %s", r.URL.Path)
					w.WriteHeader(http.StatusBadRequest)
				}
			})
			err := preflightFederationProviderDelete(service, []string{"provider-1"})
			if (err == nil) != tc.want {
				t.Fatalf("allowed = %v, want %v: %v", err == nil, tc.want, err)
			}
		})
	}
}

func TestFederationProviderPreflightDoesNotTrustPayloadPresence(t *testing.T) {
	for _, dependency := range []string{"openid-connect-config", "metadata"} {
		t.Run(dependency, func(t *testing.T) {
			service, _ := testService(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("preflight attempted a write: %s", r.Method)
				}
				switch {
				case strings.HasSuffix(r.URL.Path, "/protocols"):
					fmt.Fprint(w, `{"protocols":[]}`)
				case strings.HasSuffix(r.URL.Path, "/"+dependency):
					if dependency == "openid-connect-config" {
						fmt.Fprint(w, `{"openid_connect_config":{"present":false,"absent":true}}`)
					} else {
						fmt.Fprint(w, `{"present":false,"absent":true}`)
					}
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			})
			if err := preflightFederationProviderDelete(service, []string{"provider-1"}); err == nil {
				t.Fatal("HTTP 200 payload falsely bypassed dependency presence check")
			}
		})
	}
}

func TestFederationMappingDeletePreflight(t *testing.T) {
	const providersPath = "/v3/OS-FEDERATION/identity_providers"
	const protocolsPath = providersPath + "/provider-1/protocols"
	const otherProtocolsPath = providersPath + "/provider-2/protocols"
	type reply struct {
		status int
		body   string
	}
	for _, tc := range []struct {
		name    string
		replies map[string]reply
		want    bool
	}{
		{"unreferenced", map[string]reply{
			providersPath: {200, `{"identity_providers":[{"id":"provider-1"}]}`},
			protocolsPath: {200, `{"protocols":[{"id":"saml","mapping_id":"other-mapping"}]}`},
		}, true},
		{"reference on later provider page", map[string]reply{
			providersPath:                  {200, `{"identity_providers":[{"id":"provider-1"}],"links":{"next":"?marker=next"}}`},
			providersPath + "?marker=next": {200, `{"identity_providers":[{"id":"provider-2"}]}`},
			protocolsPath:                  {200, `{"protocols":[]}`},
			otherProtocolsPath:             {200, `{"protocols":[{"id":"saml","mapping_id":"mapping-1"}]}`},
		}, false},
		{"reference on later protocol page", map[string]reply{
			providersPath:                  {200, `{"identity_providers":[{"id":"provider-1"}]}`},
			protocolsPath:                  {200, `{"protocols":[{"id":"saml","mapping_id":"other"}],"links":{"next":"?marker=next"}}`},
			protocolsPath + "?marker=next": {200, `{"protocols":[{"id":"oidc","mapping_id":"mapping-1"}]}`},
		}, false},
		{"provider pagination incomplete", map[string]reply{
			providersPath:                  {200, `{"identity_providers":[{"id":"provider-1"}],"links":{"next":"?marker=next"}}`},
			providersPath + "?marker=next": {403, `{}`},
		}, false},
		{"protocol pagination incomplete", map[string]reply{
			providersPath:                  {200, `{"identity_providers":[{"id":"provider-1"}]}`},
			protocolsPath:                  {200, `{"protocols":[{"id":"saml","mapping_id":"other"}],"links":{"next":"?marker=next"}}`},
			protocolsPath + "?marker=next": {403, `{}`},
		}, false},
		{"mapping absent from protocol response", map[string]reply{
			providersPath: {200, `{"identity_providers":[{"id":"provider-1"}]}`},
			protocolsPath: {200, `{"protocols":[{"id":"saml"}]}`},
		}, false},
		{"invalid provider ID", map[string]reply{
			providersPath: {200, `{"identity_providers":[{"id":"../other"}]}`},
		}, false},
		{"no providers", map[string]reply{
			providersPath: {200, `{"identity_providers":[]}`},
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			service, _ := testService(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("preflight attempted a write: %s", r.Method)
				}
				response, exists := tc.replies[r.URL.RequestURI()]
				if !exists {
					t.Errorf("unexpected preflight request: %s", r.URL.RequestURI())
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				w.WriteHeader(response.status)
				fmt.Fprint(w, response.body)
			})
			err := preflightFederationMappingDelete(service, []string{"mapping-1"})
			if (err == nil) != tc.want {
				t.Fatalf("allowed = %v, want %v: %v", err == nil, tc.want, err)
			}
		})
	}
}
