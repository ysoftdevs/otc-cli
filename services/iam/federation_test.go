package iam

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

const testPublicJWK = `{"kid":"current","kty":"RSA","n":"AQIDBA","e":"AQAB"}`

func testJWKS(keys ...string) string { return `{"keys":[` + strings.Join(keys, ",") + `]}` }

func TestFederationConfigAndMetadataEndpoints(t *testing.T) {
	config := Record{"idp_url": "https://issuer.example", "client_id": "client", "signing_key": testJWKS(testPublicJWK), "future": map[string]any{"enabled": true}}
	saml := Record{"idp_id": "IdP", "protocol_id": "saml", "entity_id": "https://issuer.example", "data": `<EntityDescriptor entityID="test"/>`, "future": true}
	spXML := `<EntityDescriptor entityID="regional-keystone"/>`
	paths := make([]string, 0)
	service, _ := testService(t, func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.Method != http.MethodGet || r.Header.Get("X-Auth-Token") != "test-token" {
			t.Errorf("unexpected IAM request %s (token present: %t)", r.Method, r.Header.Get("X-Auth-Token") != "")
		}
		switch r.URL.Path {
		case "/v3.0/OS-FEDERATION/identity-providers/IdP/openid-connect-config":
			_ = json.NewEncoder(w).Encode(map[string]any{"openid_connect_config": config})
		case "/v3-ext/OS-FEDERATION/identity_providers/IdP/protocols/saml/metadata":
			_ = json.NewEncoder(w).Encode(saml)
		case "/v3-ext/auth/OS-FEDERATION/SSO/metadata":
			w.Header().Set("Content-Type", "application/xml")
			fmt.Fprint(w, spXML)
		default:
			t.Errorf("unexpected endpoint %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	gotConfig, err := service.GetOIDCConfig("IdP")
	if err != nil || !reflect.DeepEqual(gotConfig, config) {
		t.Fatalf("OIDC config changed: %#v, %v", gotConfig, err)
	}
	gotSAML, err := service.GetSAMLMetadata("IdP", "saml")
	if err != nil || !reflect.DeepEqual(gotSAML, saml) {
		t.Fatalf("SAML metadata changed: %#v, %v", gotSAML, err)
	}
	gotSP, err := service.GetSPMetadata()
	if err != nil || gotSP["data"] != spXML || len(paths) != 3 {
		t.Fatalf("SP metadata changed: %#v, %v", gotSP, err)
	}
	if _, err := service.GetOIDCConfig("../other"); err == nil || len(paths) != 3 {
		t.Fatal("invalid provider ID reached the network")
	}
}

type oidcRoundTripFunc func(*http.Request) (*http.Response, error)

func (f oidcRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func oidcTestClient(t *testing.T, issuer, publicKeys string) *http.Client {
	t.Helper()
	return &http.Client{Transport: oidcRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "" || r.Header.Get("X-Auth-Token") != "" || r.Header.Get("Cookie") != "" {
			t.Fatal("public OIDC request must be GET without credentials")
		}
		var body string
		switch r.URL.String() {
		case "https://issuer.example/tenant/.well-known/openid-configuration":
			data, _ := json.Marshal(map[string]any{"issuer": issuer, "jwks_uri": "https://keys.example/jwks", "id_token_signing_alg_values_supported": []string{"RS256"}})
			body = string(data)
		case "https://keys.example/jwks":
			body = publicKeys
		default:
			t.Fatalf("unexpected public request: %s", r.URL)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header), Request: r}, nil
	})}
}

func TestOIDCCheckRotationAndChangedMaterial(t *testing.T) {
	old := strings.Replace(testPublicJWK, `"current"`, `"old"`, 1)
	newKey := strings.Replace(testPublicJWK, `"current"`, `"new"`, 1)
	changed := strings.Replace(strings.Replace(testPublicJWK, `"current"`, `"changed"`, 1), "AQIDBA", "AQIDBQ", 1)
	storedChanged := strings.Replace(testPublicJWK, `"current"`, `"changed"`, 1)
	stored := strings.Replace(testPublicJWK, `"kty"`, `"alg":"RS256","kty"`, 1)
	config := Record{"idp_url": "https://issuer.example/tenant", "client_id": "client", "signing_key": testJWKS(stored, old, storedChanged)}
	rows := checkOIDCConfig(config, oidcTestClient(t, config["idp_url"].(string), testJWKS(testPublicJWK, newKey, changed)))
	statuses := map[string]string{}
	for _, row := range rows {
		if kid, ok := row["kid"].(string); ok {
			statuses[kid] = row["status"].(string)
		}
	}
	want := map[string]string{"current": "match", "new": "different", "changed": "different", "old": "info"}
	if !reflect.DeepEqual(statuses, want) {
		t.Fatalf("rotation/material comparison: %#v; rows=%v", statuses, rows)
	}
	encoded, _ := json.Marshal(rows)
	if strings.Contains(string(encoded), `"n":`) || !strings.Contains(string(encoded), "published_thumbprint") {
		t.Fatal("diagnostics should show fingerprints, not raw key material")
	}
}

func TestOIDCCheckStopsAtIssuerMismatch(t *testing.T) {
	config := Record{"idp_url": "https://issuer.example/tenant", "client_id": "client", "signing_key": testJWKS(testPublicJWK)}
	client := oidcTestClient(t, "https://wrong.example/tenant", testJWKS(testPublicJWK))
	rows := checkOIDCConfig(config, client)
	last := rows[len(rows)-1]
	if last["check"] != "discovery issuer" || last["status"] != "different" {
		t.Fatalf("issuer mismatch did not stop comparison: %v", rows)
	}
}

func TestOIDCDiscoveryUsesExactMemberNames(t *testing.T) {
	for _, tc := range []struct {
		name, body, wantCheck, wantStatus string
		wantRequests                      int
	}{
		{"wrong standard issuer cannot be overridden", `{"issuer":"https://wrong.example","Issuer":"https://issuer.example/tenant","jwks_uri":"https://keys.example/jwks","id_token_signing_alg_values_supported":["RS256"]}`, "discovery issuer", "different", 1},
		{"uppercase issuer does not supply missing standard field", `{"Issuer":"https://issuer.example/tenant","jwks_uri":"https://keys.example/jwks","id_token_signing_alg_values_supported":["RS256"]}`, "discovery issuer", "unavailable", 1},
		{"uppercase algorithms do not override empty standard array", `{"issuer":"https://issuer.example/tenant","jwks_uri":"https://keys.example/jwks","id_token_signing_alg_values_supported":[],"ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED":["RS256"]}`, "discovery algorithms", "unavailable", 1},
		{"uppercase JWKS URI does not supply missing standard field", `{"issuer":"https://issuer.example/tenant","JWKS_URI":"https://keys.example/jwks","id_token_signing_alg_values_supported":["RS256"]}`, "discovery JWKS URI", "unavailable", 1},
		{"unknown case fields do not override valid standard fields", `{"issuer":"https://issuer.example/tenant","Issuer":"https://wrong.example","jwks_uri":"https://keys.example/jwks","JWKS_URI":"https://wrong.example/jwks","id_token_signing_alg_values_supported":["RS256"],"ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED":[]}`, "signing key", "match", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requests := 0
			client := &http.Client{Transport: oidcRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				requests++
				body := tc.body
				if requests == 2 {
					if r.URL.String() != "https://keys.example/jwks" {
						t.Fatalf("request followed nonstandard JWKS_URI: %s", r.URL)
					}
					body = testJWKS(testPublicJWK)
				}
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
			})}
			config := Record{"idp_url": "https://issuer.example/tenant", "client_id": "client", "signing_key": testJWKS(testPublicJWK)}
			rows := checkOIDCConfig(config, client)
			for _, row := range rows {
				if row["check"] == tc.wantCheck && row["status"] == tc.wantStatus && requests == tc.wantRequests {
					return
				}
			}
			t.Fatalf("exact-member handling failed: requests=%d want=%d; rows=%v", requests, tc.wantRequests, rows)
		})
	}
}

func TestOIDCJWKSUsesExactKeysMember(t *testing.T) {
	otherKey := strings.Replace(testPublicJWK, `"current"`, `"other"`, 1)
	raw := `{"keys":[` + testPublicJWK + `],"Keys":[` + otherKey + `]}`
	keys, err := parseSigningKeys(raw)
	if err != nil || len(keys) != 1 || keys["current"].thumbprint == "" {
		t.Fatalf("nonstandard Keys overrode the standard keys member: keys=%v err=%v", keys, err)
	}
	config := Record{"idp_url": "https://issuer.example/tenant", "client_id": "client", "signing_key": testJWKS(testPublicJWK)}
	rows := checkOIDCConfig(config, oidcTestClient(t, config["idp_url"].(string), raw))
	matched := false
	for _, row := range rows {
		if row["kid"] == "current" && row["status"] == "match" {
			matched = true
		}
		if row["kid"] == "other" {
			t.Fatal("nonstandard Keys contributed a signing key")
		}
	}
	if !matched {
		t.Fatalf("standard keys were not compared: %v", rows)
	}
	if _, err := parseSigningKeys(`{"Keys":[` + testPublicJWK + `]}`); err == nil {
		t.Fatal("nonstandard Keys supplied a missing standard keys member")
	}
}

func TestOIDCPrivateKeySuppressionIncludesUnknownFields(t *testing.T) {
	for _, extra := range []string{
		`,"Keys":[{"d":"private-fixture"}]`,
		`,"unknown":{"nested":[{"D":"private-fixture"}]}`,
		`,"unknown":{"nested":[{"Q":"private-fixture"}]}`,
		`,"unknown":{"nested":[{"K":"private-fixture"}]}`,
		`,"unknown":"-----BEGIN PRIVATE KEY-----\nprivate-fixture\n-----END PRIVATE KEY-----"`,
	} {
		raw := `{"keys":[` + testPublicJWK + `]` + extra + `}`
		service, _ := testService(t, func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{"openid_connect_config": Record{"signing_key": raw}})
		})
		record, err := service.GetOIDCConfig("IdP")
		if record != nil || err == nil || strings.Contains(err.Error(), "private-fixture") {
			t.Fatalf("private material outside standard keys reached display: record=%v err=%v", record, err)
		}
		if keys, err := parseSigningKeys(raw); keys != nil || err == nil || strings.Contains(err.Error(), "private-fixture") {
			t.Fatalf("private material outside standard keys accepted: keys=%v err=%v", keys, err)
		}
	}
}

func TestOIDCInvalidStoredKeysNeverReportMatch(t *testing.T) {
	for _, keys := range []string{"", `{"keys":[]}`, `{"keys":[{"kid":"bad","kty":"oct","k":"private-fixture"}]}`, testJWKS(testPublicJWK, testPublicJWK)} {
		config := Record{"idp_url": "https://issuer.example/tenant", "client_id": "client", "signing_key": keys}
		rows := checkOIDCConfig(config, oidcTestClient(t, config["idp_url"].(string), testJWKS(testPublicJWK)))
		unavailable := false
		for _, row := range rows {
			if row["check"] == "stored signing keys" && row["status"] == "unavailable" {
				unavailable = true
			}
			if row["check"] == "signing key" && row["status"] == "match" {
				t.Fatal("invalid stored keys produced a match")
			}
		}
		encoded, _ := json.Marshal(rows)
		if !unavailable || strings.Contains(string(encoded), "private-fixture") {
			t.Fatalf("invalid key diagnostic wrong: %s", encoded)
		}
	}
}

func TestOIDCRejectsMalformedAndUnsupportedKeys(t *testing.T) {
	for _, key := range []string{
		`{"kid":"x","kty":"RSA","n":"not base64","e":"AQAB"}`,
		`{"kid":"x","kty":"RSA","n":"AQIDBA","e":"AQAB","alg":"HS256"}`,
		`{"kid":"x","kty":"RSA","n":"AQIDBA","e":"AQAB","alg":123}`,
		`{"kid":"x","kty":"RSA","n":"AQIDBA","e":"AQAB","d":"do-not-print"}`,
		`{"kid":"x","kty":"RSA","n":"AQIDBA","e":"AQAB","key_ops":["encrypt"]}`,
		`{"kid":"x","kty":"EC","crv":"unknown","x":"AQIDBA","y":"AQIDBA"}`,
		`{"kid":"x","kty":"future","n":"AQIDBA","e":"AQAB"}`,
		`{"kty":"RSA","n":"AQIDBA","e":"AQAB"}`,
	} {
		if _, err := parseSigningKeys(testJWKS(key)); err == nil || strings.Contains(err.Error(), "do-not-print") {
			t.Fatalf("key accepted or private material exposed: %v", err)
		}
	}
	// An encryption key alongside a signing key should not create a missing-kid
	// or missing-signing-key warning. Its private material is still forbidden.
	keys, err := parseSigningKeys(testJWKS(testPublicJWK, `{"use":"enc","kty":"RSA"}`))
	if err != nil || len(keys) != 1 {
		t.Fatalf("encryption key was not excluded: %v, %v", keys, err)
	}
}

func TestOIDCCheckMissingPublicEvidenceAndAlgorithmMismatch(t *testing.T) {
	for _, tc := range []struct {
		name, stored, published, check, status string
	}{
		{"empty published JWKS", testJWKS(testPublicJWK), `{"keys":[]}`, "public signing keys", "unavailable"},
		{"algorithm not advertised", testJWKS(strings.Replace(testPublicJWK, `"kty"`, `"alg":"RS512","kty"`, 1)), testJWKS(testPublicJWK), "signing key", "different"},
		{"published algorithm not advertised", testJWKS(testPublicJWK), testJWKS(strings.Replace(testPublicJWK, `"kty"`, `"alg":"RS512","kty"`, 1)), "signing key", "different"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := Record{"idp_url": "https://issuer.example/tenant", "client_id": "client", "signing_key": tc.stored}
			rows := checkOIDCConfig(config, oidcTestClient(t, config["idp_url"].(string), tc.published))
			for _, row := range rows {
				if row["check"] == tc.check && row["status"] == tc.status {
					return
				}
			}
			t.Fatalf("expected %s=%s: %v", tc.check, tc.status, rows)
		})
	}
}

func TestOIDCRejectsMissingOrInvalidDiscoveryAlgorithms(t *testing.T) {
	for _, field := range []string{"", `,"id_token_signing_alg_values_supported":null`, `,"id_token_signing_alg_values_supported":[]`, `,"id_token_signing_alg_values_supported":[""]`, `,"id_token_signing_alg_values_supported":["ES256"]`, `,"id_token_signing_alg_values_supported":["RS256",null]`} {
		config := Record{"idp_url": "https://issuer.example/tenant", "client_id": "client", "signing_key": testJWKS(testPublicJWK)}
		requests := 0
		client := &http.Client{Transport: oidcRoundTripFunc(func(r *http.Request) (*http.Response, error) {
			requests++
			if requests > 1 {
				t.Fatal("invalid discovery algorithms must stop before fetching JWKS")
			}
			body := `{"issuer":"https://issuer.example/tenant","jwks_uri":"https://keys.example/jwks"` + field + `}`
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header), Request: r}, nil
		})}
		rows := checkOIDCConfig(config, client)
		last := rows[len(rows)-1]
		if last["check"] != "discovery algorithms" || last["status"] != "unavailable" || requests != 1 {
			t.Fatalf("missing algorithm evidence was accepted for %s: %v", field, rows)
		}
	}
}

func TestOIDCRejectsAmbiguousOrDeepJWKSBeforeDisplayAndComparison(t *testing.T) {
	for _, raw := range []string{
		`{"keys":[{"d":"private-fixture"}],"keys":[]}`,
		`{"keys":[{"d":"private-fixture"}],"keys":[` + testPublicJWK + `]}`,
		`{"keys":[` + strings.Replace(testPublicJWK, `"current"`, `"old","kid":"current"`, 1) + `]}`,
		`{"keys":[],"\u006beys":[` + testPublicJWK + `]}`,
		`{"keys":[` + testPublicJWK + `],"extra":` + strings.Repeat("[", 129) + "null" + strings.Repeat("]", 129) + `}`,
	} {
		service, _ := testService(t, func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{"openid_connect_config": Record{"signing_key": raw}})
		})
		record, err := service.GetOIDCConfig("IdP")
		if err == nil || record != nil || strings.Contains(err.Error(), "private-fixture") {
			t.Fatalf("ambiguous/deep JWKS returned for display, or error leaked material: record=%v err=%v", record, err)
		}
		if keys, err := parseSigningKeys(raw); err == nil || keys != nil || strings.Contains(err.Error(), "private-fixture") {
			t.Fatalf("ambiguous/deep JWKS accepted for comparison: keys=%v err=%v", keys, err)
		}
	}
}

func TestOIDCPublicFetchSuppressesMalformedRedirectLocation(t *testing.T) {
	const secret = "private-query-fixture"
	client := &http.Client{Transport: oidcRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusFound, Header: http.Header{
			"Location": {"https://user:" + secret + "@issuer.example/%zz?token=" + secret},
		}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
	})}
	var result Record
	err := fetchOIDCPublicJSON(client, "https://issuer.example/jwks", &result)
	if err == nil || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "Location") || strings.Contains(err.Error(), "https://") {
		t.Fatalf("malformed redirect error exposed response data: %v", err)
	}
	if err.Error() != "public OIDC metadata request failed (network, TLS or redirect policy)" {
		t.Fatalf("unexpected safe HTTP error: %v", err)
	}
}

func TestOIDCPublicFetchRejectsDuplicateJSONMembers(t *testing.T) {
	client := &http.Client{Transport: oidcRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header),
			Body: io.NopCloser(strings.NewReader(`{"issuer":"private-fixture","issuer":"https://issuer.example"}`)), Request: r}, nil
	})}
	var result Record
	if err := fetchOIDCPublicJSON(client, "https://issuer.example/discovery", &result); err == nil || strings.Contains(err.Error(), "private-fixture") {
		t.Fatalf("ambiguous metadata accepted or values leaked: %v", err)
	}
}

func TestOIDCPublicAddressPolicy(t *testing.T) {
	for _, address := range []string{
		"0.0.0.1", "10.1.2.3", "100.64.0.1", "100.100.100.100", "100.127.255.255", "127.0.0.1", "169.254.169.254",
		"172.16.0.1", "192.0.0.9", "192.0.2.10", "192.31.196.1", "192.52.193.1", "192.88.99.1", "192.168.1.1",
		"192.175.48.1", "198.18.0.1", "198.19.255.255", "198.51.100.10", "203.0.113.10", "224.0.0.1", "240.0.0.1", "255.255.255.255",
		"::", "::1", "::127.0.0.1", "::ffff:127.0.0.1", "::ffff:100.100.100.100", "::ffff:192.0.2.10", "::ffff:0:127.0.0.1",
		"64:ff9b::127.0.0.1", "64:ff9b:1::a00:1", "100::1", "100:0:0:1::1",
		"2001::1", "2001:2::1", "2001:db8::1", "2002:7f00:1::", "2620:4f:8000::1", "3fff::1", "5f00::1", "fc00::1", "fe80::1", "ff02::1",
	} {
		if publicOIDCIP(net.ParseIP(address)) {
			t.Errorf("special-purpose address accepted: %s", address)
		}
		if _, err := publicOIDCURL("https://" + net.JoinHostPort(address, "443") + "/jwks"); err == nil {
			t.Errorf("special-purpose literal URL accepted: %s", address)
		}
	}
	for _, address := range []string{"1.1.1.1", "8.8.8.8", "100.63.255.255", "100.128.0.1", "20.190.128.1", "::ffff:8.8.8.8", "2001:4860:4860::8888", "2606:4700:4700::1111"} {
		if !publicOIDCIP(net.ParseIP(address)) {
			t.Errorf("ordinary public address rejected: %s", address)
		}
	}
	if _, err := publicOIDCURL("https://[2001:4860::1%25en0]/jwks"); err == nil {
		t.Fatal("scoped IPv6 literal accepted")
	}
}

func TestOIDCShowPreservesUnsupportedButPublicKeyFields(t *testing.T) {
	want := Record{"signing_key": `{"keys":[{"kid":"future-key","kty":"future-type","future_public_parameter":"public"}]}`}
	service, _ := testService(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"openid_connect_config": want})
	})
	got, err := service.GetOIDCConfig("IdP")
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("raw public configuration changed: %v, %v", got, err)
	}
}

func TestOIDCPublicFetchBoundariesAndErrors(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		want       string
	}{
		{"HTTP error", `private-body-do-not-print`, 403, "HTTP 403"},
		{"invalid JSON", `private-body-do-not-print`, 200, "not valid JSON"},
		{"too large", strings.Repeat("x", oidcResponseLimit+1), 200, "1 MiB"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{Transport: oidcRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
			})}
			var target Record
			err := fetchOIDCPublicJSON(client, "https://issuer.example/jwks", &target)
			if err == nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), "private-body") {
				t.Fatalf("wrong bounded/safe error: %v", err)
			}
		})
	}
	for _, rawURL := range []string{"http://issuer.example", "https://user:password@issuer.example", "https://127.0.0.1/jwks", "https://[::1]/jwks", "https://169.254.169.254/latest", "https://10.0.0.1", "https://issuer.example/#token"} {
		if _, err := publicOIDCURL(rawURL); err == nil {
			t.Errorf("unsafe URL accepted: %s", rawURL)
		}
	}
	client := newOIDCPublicClient()
	defer client.CloseIdleConnections()
	if client.Timeout != 10*time.Second || client.Transport.(*http.Transport).Proxy != nil {
		t.Fatal("public HTTP client must be bounded and independent of environment proxies")
	}
	downgrade, _ := url.Parse("http://issuer.example/jwks")
	if err := client.CheckRedirect(&http.Request{URL: downgrade}, nil); err == nil {
		t.Fatal("HTTPS redirect downgrade accepted")
	}
	for _, address := range []string{"127.0.0.1", "10.0.0.1", "::1", "fe80::1", "169.254.169.254", "224.0.0.1"} {
		if publicOIDCIP(net.ParseIP(address)) {
			t.Errorf("non-public address accepted: %s", address)
		}
	}
}

func TestOIDCShowSuppressesPrivateMaterial(t *testing.T) {
	service, _ := testService(t, func(w http.ResponseWriter, r *http.Request) {
		config := Record{"idp_url": "https://issuer.example", "signing_key": testJWKS(`{"kid":"x","kty":"RSA","d":"private-fixture"}`)}
		_ = json.NewEncoder(w).Encode(map[string]any{"openid_connect_config": config})
	})
	config, err := service.GetOIDCConfig("IdP")
	if config != nil || err == nil || strings.Contains(err.Error(), "private-fixture") {
		t.Fatalf("private config must not be returned: %v %v", config, err)
	}
}
