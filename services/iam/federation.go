package iam

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"
)

const oidcResponseLimit = 1 << 20

// GetOIDCConfig returns the stored configuration, including its public JWKS.
// No token or client secret is part of this documented OTC response.
func (s *Service) GetOIDCConfig(providerID string) (Record, error) {
	config, err := s.getOIDCConfig(providerID)
	if err != nil {
		return nil, err
	}
	// Preserve unknown public key attributes for inspection. Only malformed JSON
	// and private material must be suppressed; key usability is checked below.
	if err := validatePublicKeyDisplay(config["signing_key"]); err != nil {
		return nil, fmt.Errorf("stored signing_key cannot be displayed safely: %w; use providers oidc check", err)
	}
	return config, nil
}

func (s *Service) getOIDCConfig(providerID string) (Record, error) {
	return s.getVersion("v3.0", "openid_connect_config", "OS-FEDERATION", "identity-providers", providerID, "openid-connect-config")
}

// GetSAMLMetadata returns the imported IdP metadata and its API attributes. This
// endpoint uses v3-ext and an unwrapped object, unlike protocol binding reads.
func (s *Service) GetSAMLMetadata(providerID, protocolID string) (Record, error) {
	endpoint, err := s.versionEndpoint("v3-ext", "OS-FEDERATION", "identity_providers", providerID, "protocols", protocolID, "metadata")
	if err != nil {
		return nil, err
	}
	var result Record
	if err := s.read(endpoint, &result); err != nil {
		return nil, err
	}
	if data, ok := result["data"].(string); !ok || data == "" {
		return nil, fmt.Errorf("IAM SAML metadata response must contain a non-empty data string")
	}
	return result, nil
}

// GetSPMetadata reads the regional Keystone service-provider metadata XML.
func (s *Service) GetSPMetadata() (Record, error) {
	data, err := s.readTextVersion("v3-ext", "auth", "OS-FEDERATION", "SSO", "metadata")
	if err != nil {
		return nil, err
	}
	return Record{"data": data}, nil
}

// CheckOIDCConfig compares stored OTC signing keys with the issuer's current
// public discovery/JWKS documents. It neither validates a login nor updates IAM.
// A missing public key is different from an old key retained in OTC for overlap.
func (s *Service) CheckOIDCConfig(providerID string) ([]Record, error) {
	config, err := s.getOIDCConfig(providerID)
	if err != nil {
		return nil, err
	}
	client := newOIDCPublicClient()
	defer client.CloseIdleConnections()
	return checkOIDCConfig(config, client), nil
}

func checkOIDCConfig(config Record, client *http.Client) []Record {
	rows := make([]Record, 0)
	add := func(check, status, detail string) {
		rows = append(rows, Record{"check": check, "status": status, "detail": detail})
	}
	issuer, _ := config["idp_url"].(string)
	issuerURL, err := publicOIDCURL(issuer)
	if err != nil || issuerURL.RawQuery != "" {
		add("issuer", "unavailable", "Stored idp_url must be an absolute public HTTPS issuer URL without query or fragment")
		return rows
	}
	add("configured issuer", "info", issuer)
	if id, ok := config["client_id"].(string); ok && id != "" {
		add("client ID", "info", id+" (stored value; token audience and application configuration were not checked)")
	} else {
		add("client ID", "different", "Stored configuration has no client_id")
	}
	stored, storedErr := parseSigningKeys(config["signing_key"])
	if storedErr != nil {
		add("stored signing keys", "unavailable", storedErr.Error())
	} else {
		add("stored signing keys", "info", fmt.Sprintf("%d signing key(s)", len(stored)))
	}
	discoveryURL := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	// OIDC member names are case-sensitive. Struct decoding would let an
	// unrelated "Issuer" or "JWKS_URI" override the standard lowercase member.
	var discovery map[string]json.RawMessage
	if err := fetchOIDCPublicJSON(client, discoveryURL, &discovery); err != nil {
		add("discovery", "unavailable", err.Error())
		return rows
	}
	var discoveredIssuer string
	if err := json.Unmarshal(discovery["issuer"], &discoveredIssuer); err != nil || discoveredIssuer == "" {
		add("discovery issuer", "unavailable", "Discovery requires an exact issuer member containing a non-empty string")
		return rows
	}
	if discoveredIssuer != issuer {
		add("discovery issuer", "different", "Discovery issuer does not exactly match stored idp_url; its JWKS was not trusted or fetched")
		return rows
	}
	add("discovery issuer", "match", "Discovery issuer exactly matches stored idp_url")
	// OIDC Discovery section 3 requires this list and inclusion of RS256.
	// Without it there is no trustworthy advertised signing-algorithm evidence.
	var algorithms []string
	if err := json.Unmarshal(discovery["id_token_signing_alg_values_supported"], &algorithms); err != nil || len(algorithms) == 0 || !containsOIDCString(algorithms, "RS256") || containsOIDCString(algorithms, "") {
		add("discovery algorithms", "unavailable", "Discovery requires a non-empty id_token_signing_alg_values_supported array including RS256, without blank entries")
		return rows
	}
	var jwksURI string
	if err := json.Unmarshal(discovery["jwks_uri"], &jwksURI); err != nil || jwksURI == "" {
		add("discovery JWKS URI", "unavailable", "Discovery requires an exact jwks_uri member containing a non-empty string")
		return rows
	}
	var jwks json.RawMessage
	if err := fetchOIDCPublicJSON(client, jwksURI, &jwks); err != nil {
		add("public signing keys", "unavailable", err.Error())
		return rows
	}
	current, err := parseSigningKeys(string(jwks))
	if err != nil {
		add("public signing keys", "unavailable", err.Error())
		return rows
	}
	add("public signing keys", "info", fmt.Sprintf("%d signing key(s) published by the issuer", len(current)))
	if storedErr != nil {
		return rows
	}
	for _, kid := range sortedSigningKeyIDs(current) {
		published := current[kid]
		saved, exists := stored[kid]
		row := Record{"check": "signing key", "kid": kid, "published_thumbprint": published.thumbprint}
		switch {
		case published.alg != "" && !containsOIDCString(algorithms, published.alg):
			row["status"], row["detail"] = "different", "Published key alg is not advertised for ID token signing by discovery"
		case !exists:
			row["status"], row["detail"] = "different", "Published signing key is missing from OTC"
		case saved.thumbprint != published.thumbprint:
			row["status"], row["detail"] = "different", "Same kid has different public key material in OTC"
			row["stored_thumbprint"] = saved.thumbprint
		case saved.alg != "" && published.alg != "" && saved.alg != published.alg:
			row["status"], row["detail"] = "different", "Public key material matches, but explicit alg restrictions differ"
		case saved.alg != "" && !containsOIDCString(algorithms, saved.alg):
			row["status"], row["detail"] = "different", "Stored alg is not advertised for ID token signing by discovery"
		case saved.issuer != "" && published.issuer != "" && saved.issuer != published.issuer:
			row["status"], row["detail"] = "different", "Public key material matches, but key-level issuer metadata differs"
		default:
			row["status"], row["detail"] = "match", "kid and public key material match"
		}
		rows = append(rows, row)
	}
	for _, kid := range sortedSigningKeyIDs(stored) {
		if _, exists := current[kid]; !exists {
			rows = append(rows, Record{"check": "stored-only key", "status": "info", "kid": kid,
				"stored_thumbprint": stored[kid].thumbprint,
				"detail":            "Key remains in OTC but is not currently published; may be retained for rotation overlap"})
		}
	}
	add("coverage", "info", "Configuration/key comparison only; no token signature, audience, claims mapping, provider enablement or login was tested")
	return rows
}

type signingKey struct {
	thumbprint string
	alg        string
	issuer     string
}

func validatePublicKeyDisplay(value any) error {
	if value == nil || value == "" {
		return nil
	}
	raw, ok := value.(string)
	if !ok || len(raw) > oidcResponseLimit {
		return fmt.Errorf("signing_key must be a bounded JSON string")
	}
	if err := validateJSONDocument([]byte(raw)); err != nil {
		return fmt.Errorf("signing_key must contain unambiguous valid JSON: %w", err)
	}
	var document any
	if json.Unmarshal([]byte(raw), &document) != nil {
		return fmt.Errorf("signing_key is not valid JSON")
	}
	var hasPrivateField func(any) bool
	hasPrivateField = func(value any) bool {
		switch item := value.(type) {
		case map[string]any:
			for field, value := range item {
				if containsOIDCString([]string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"}, strings.ToLower(field)) || hasPrivateField(value) {
					return true
				}
			}
		case []any:
			for _, value := range item {
				if hasPrivateField(value) {
					return true
				}
			}
		case string:
			// Unknown extension values may contain PEM material rather than JWK
			// members. Do not echo recognizable private-key PEM blocks either.
			upper := strings.ToUpper(item)
			return strings.Contains(upper, "-----BEGIN ") && strings.Contains(upper, "PRIVATE KEY-----")
		}
		return false
	}
	if hasPrivateField(document) {
		return fmt.Errorf("JWKS contains private or symmetric key material; values suppressed")
	}
	return nil
}

func parseSigningKeys(value any) (map[string]signingKey, error) {
	raw, ok := value.(string)
	if !ok || raw == "" {
		return nil, fmt.Errorf("signing_key must contain a non-empty JWKS JSON string")
	}
	if len(raw) > oidcResponseLimit {
		return nil, fmt.Errorf("JWKS exceeds the response limit")
	}
	if err := validatePublicKeyDisplay(raw); err != nil {
		return nil, fmt.Errorf("JWKS cannot be inspected: %w", err)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &document); err != nil {
		return nil, fmt.Errorf("JWKS must be a JSON object")
	}
	var rawKeys []map[string]json.RawMessage
	if err := json.Unmarshal(document["keys"], &rawKeys); err != nil || len(rawKeys) == 0 {
		return nil, fmt.Errorf("JWKS must contain a non-empty keys array")
	}
	keys := make(map[string]signingKey)
	for _, rawKey := range rawKeys {
		for _, field := range []string{"kid", "kty", "alg", "issuer", "use", "e", "n", "crv", "x", "y"} {
			if raw, exists := rawKey[field]; exists {
				var value string
				if string(raw) == "null" || json.Unmarshal(raw, &value) != nil {
					return nil, fmt.Errorf("JWKS contains a non-string key attribute")
				}
			}
		}
		stringField := func(name string) string {
			var value string
			_ = json.Unmarshal(rawKey[name], &value)
			return value
		}
		use := stringField("use")
		if use == "enc" {
			continue // Encryption-only keys are not relevant to ID token signatures.
		}
		if use != "" && use != "sig" {
			return nil, fmt.Errorf("signing key has an unsupported use attribute")
		}
		if rawOps, exists := rawKey["key_ops"]; exists {
			var ops []string
			if json.Unmarshal(rawOps, &ops) != nil {
				return nil, fmt.Errorf("JWKS contains invalid key_ops")
			}
			verify := false
			for _, op := range ops {
				verify = verify || op == "verify"
			}
			if !verify {
				continue
			}
		}
		kid, kty := stringField("kid"), stringField("kty")
		if kid == "" {
			return nil, fmt.Errorf("signing key has no non-empty kid; comparison is unavailable")
		}
		if _, exists := keys[kid]; exists {
			return nil, fmt.Errorf("JWKS contains duplicate signing key IDs; comparison is ambiguous")
		}
		material := map[string]string{"kty": kty}
		var fields []string
		switch kty {
		case "RSA":
			fields = []string{"e", "n"}
		case "EC":
			fields = []string{"crv", "x", "y"}
		case "OKP":
			fields = []string{"crv", "x"}
		default:
			return nil, fmt.Errorf("JWKS contains an unsupported signing key type")
		}
		for _, field := range fields {
			value := stringField(field)
			if value == "" {
				return nil, fmt.Errorf("signing key lacks required public key material")
			}
			if field != "crv" {
				if decoded, err := base64.RawURLEncoding.DecodeString(value); err != nil || len(decoded) == 0 {
					return nil, fmt.Errorf("signing key contains invalid base64url public key material")
				}
			}
			material[field] = value
		}
		if err := validateSigningAlgorithm(kty, stringField("alg"), stringField("crv")); err != nil {
			return nil, err
		}
		// JSON sorts map keys lexically, as required by RFC 7638 thumbprints.
		canonical, _ := json.Marshal(material)
		digest := sha256.Sum256(canonical)
		keys[kid] = signingKey{thumbprint: base64.RawURLEncoding.EncodeToString(digest[:]), alg: stringField("alg"), issuer: stringField("issuer")}
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("JWKS contains no usable signing keys")
	}
	return keys, nil
}

func validateSigningAlgorithm(kty, alg, curve string) error {
	var supported []string
	switch kty {
	case "RSA":
		supported = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"}
	case "EC":
		switch curve {
		case "P-256":
			supported = []string{"ES256"}
		case "P-384":
			supported = []string{"ES384"}
		case "P-521":
			supported = []string{"ES512"}
		default:
			return fmt.Errorf("signing key uses an unsupported elliptic curve")
		}
	case "OKP":
		if curve != "Ed25519" && curve != "Ed448" {
			return fmt.Errorf("signing key uses an unsupported curve")
		}
		supported = []string{"EdDSA"}
	}
	// alg is optional in a JWK. Entra's public JWKS normally omits it.
	if alg != "" && !containsOIDCString(supported, alg) {
		return fmt.Errorf("signing key uses an unsupported or incompatible algorithm")
	}
	return nil
}

func containsOIDCString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func sortedSigningKeyIDs(keys map[string]signingKey) []string {
	ids := make([]string, 0, len(keys))
	for id := range keys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func publicOIDCURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" || strings.Contains(u.Hostname(), "%") {
		return nil, fmt.Errorf("public OIDC metadata requires an absolute HTTPS URL without credentials or fragment")
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil && !publicOIDCIP(ip) {
		return nil, fmt.Errorf("public OIDC metadata cannot use a private or local address")
	}
	return u, nil
}

func publicOIDCIP(ip net.IP) bool {
	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	address = address.Unmap()
	if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() {
		return false
	}
	// Only native globally allocated IPv6 is eligible. This also excludes
	// translation prefixes that could encode a private IPv4 destination.
	if address.Is6() && !oidcNativeIPv6.Contains(address) {
		return false
	}
	for _, prefix := range oidcSpecialPurposePrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

var oidcNativeIPv6 = netip.MustParsePrefix("2000::/3")

// Deliberately exclude all IANA special-purpose destinations, including
// globally routed protocol anycasts: none is an ordinary public OIDC host.
// https://www.iana.org/assignments/iana-ipv4-special-registry/
// https://www.iana.org/assignments/iana-ipv6-special-registry/
var oidcSpecialPurposePrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.31.196.0/24"),
	netip.MustParsePrefix("192.52.193.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.175.48.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("2620:4f:8000::/48"),
	netip.MustParsePrefix("3fff::/20"),
}

// This client is intentionally independent of the authenticated OTC client and
// environment proxies. DNS is checked at dial time to avoid resolving a public
// name once and subsequently connecting to a private address after rebinding.
func newOIDCPublicClient() *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("invalid public OIDC address")
		}
		addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil || len(addresses) == 0 {
			return nil, fmt.Errorf("public OIDC host could not be resolved")
		}
		for _, address := range addresses {
			if !publicOIDCIP(address.IP) {
				return nil, fmt.Errorf("public OIDC host resolves to a private or local address")
			}
		}
		for _, address := range addresses {
			connection, err := dialer.DialContext(ctx, network, net.JoinHostPort(address.IP.String(), port))
			if err == nil {
				return connection, nil
			}
		}
		return nil, fmt.Errorf("could not connect to public OIDC host")
	}
	return &http.Client{Transport: transport, Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("too many public OIDC redirects")
			}
			_, err := publicOIDCURL(req.URL.String())
			return err
		}}
}

func fetchOIDCPublicJSON(client *http.Client, rawURL string, target any) error {
	u, err := publicOIDCURL(rawURL)
	if err != nil {
		return err
	}
	request, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return fmt.Errorf("could not construct public OIDC metadata request")
	}
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		// Even the inner error of url.Error can embed a malformed Location with
		// credentials or query values. Classify without rendering any raw error.
		var networkError net.Error
		if errors.As(err, &networkError) && networkError.Timeout() {
			return fmt.Errorf("public OIDC metadata request timed out")
		}
		return fmt.Errorf("public OIDC metadata request failed (network, TLS or redirect policy)")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("public OIDC metadata returned HTTP %d", response.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, oidcResponseLimit+1))
	if err != nil {
		return fmt.Errorf("could not read public OIDC metadata response")
	}
	if len(raw) > oidcResponseLimit {
		return fmt.Errorf("public OIDC metadata exceeds 1 MiB response limit")
	}
	if err := validateJSONDocument(raw); err != nil {
		return fmt.Errorf("public OIDC metadata is not valid JSON or contains ambiguous members")
	}
	if err := json.Unmarshal(raw, target); err != nil {
		return fmt.Errorf("public OIDC metadata is not valid JSON")
	}
	return nil
}
