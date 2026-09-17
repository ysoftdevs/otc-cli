package iam

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMutationSigningKeyRedactionPreservesPublicJWKS(t *testing.T) {
	// Keep the original JSON string, including optional public extension fields,
	// rather than projecting only the fields understood by this CLI.
	public := `{"keys":[{"kid":"current","kty":"RSA","n":"AQIDBA","e":"AQAB","issuer":"https://issuer.example","future_public":{"counter":9007199254740993}}]}`
	if got := redactMutationSigningKey(public); got != public {
		t.Fatalf("public JWKS was changed: %v", got)
	}
	for _, field := range []string{"signing_key", "SIGNING_KEY"} {
		input := Record{"openid_connect_config": map[string]any{field: public}}
		encoded, err := json.Marshal(redactMutation(input))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(encoded), "9007199254740993") || strings.Contains(string(encoded), "redacted") {
			t.Fatalf("public JWKS lost in mutation preview: %s", encoded)
		}
	}
}

func TestMutationSigningKeyRedactionSuppressesUnsafeValues(t *testing.T) {
	doubleEncoded, err := json.Marshal(testJWKS(testPublicJWK))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		value any
	}{
		{"private RSA", `{"keys":[{"kid":"current","kty":"RSA","n":"AQIDBA","e":"AQAB","d":"private-fixture"}]}`},
		{"private extension", `{"keys":[` + testPublicJWK + `],"unknown":{"D":"private-fixture"}}`},
		{"symmetric key", `{"keys":[{"kid":"current","kty":"oct","k":"private-fixture"}]}`},
		{"duplicate keys", `{"keys":[{"d":"private-fixture"}],"keys":[` + testPublicJWK + `]}`},
		{"duplicate key member", `{"keys":[{"kid":"current","kty":"RSA","d":"private-fixture","d":"","n":"AQIDBA","e":"AQAB"}]}`},
		{"private case alternative", `{"keys":[` + testPublicJWK + `],"Keys":[{"d":"private-fixture"}]}`},
		{"private PEM extension", `{"keys":[` + testPublicJWK + `],"unknown":"-----BEGIN PRIVATE KEY-----\nprivate-fixture\n-----END PRIVATE KEY-----"}`},
		{"malformed JSON", `{"keys":[private-fixture`},
		{"JSON string inside JSON string", string(doubleEncoded)},
		{"empty key set", `{"keys":[]}`},
		{"non-string key", `{"keys":[{"kid":"current","kty":"RSA","n":123,"e":"AQAB"}]}`},
		{"wrong-case required member", `{"Keys":[` + testPublicJWK + `]}`},
		{"null", nil},
		{"object instead of string", map[string]any{"keys": []any{map[string]any{"d": "private-fixture"}}}},
		{"response too large", strings.Repeat("private-fixture", oidcResponseLimit)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := redactMutationSigningKey(tc.value)
			if got != "<redacted: invalid or private signing_key>" {
				t.Fatal("unsafe signing_key was not fully suppressed")
			}
			encoded, err := json.Marshal(redactMutation(Record{"SIGNING_KEY": tc.value}))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(encoded), "private-fixture") || !strings.Contains(string(encoded), "redacted") {
				t.Fatal("unsafe signing_key escaped mutation preview redaction")
			}
		})
	}
}
