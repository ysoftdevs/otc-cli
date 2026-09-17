// Package iam inspects OTC IAM and applies explicitly reviewed management plans.
package iam

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	golangsdk "github.com/opentelekomcloud/gophertelekomcloud"
	"github.com/ysoftdevs/otc-cli/client"
	"github.com/ysoftdevs/otc-cli/config"
)

// Record preserves the API fields, including complete policy documents and
// federation rules, which the SDK's generic role models otherwise discard.
type Record map[string]any

// Service uses the credentials and IAM endpoint selected by the common client.
type Service struct {
	client       *golangsdk.ServiceClient
	base         *url.URL
	projectToken string
}

// New creates an IAM service. Bearer tokens are scoped to their account for
// global IAM access; signed AK/SK authentication needs no token exchange.
func New(commonConfig *config.CommonConfig) (*Service, error) {
	opts, err := client.GetAuthOpts(commonConfig)
	if err != nil {
		return nil, err
	}
	return newAuthenticatedService(opts)
}

func newService(identity *golangsdk.ServiceClient) (*Service, error) {
	base, err := url.Parse(identity.ServiceURL())
	if err != nil {
		return nil, fmt.Errorf("parse IAM endpoint: %w", err)
	}
	if (base.Scheme != "https" && base.Scheme != "http") || base.Host == "" ||
		base.User != nil || base.RawQuery != "" || base.Fragment != "" ||
		!strings.HasSuffix(base.Path, "/v3/") {
		return nil, fmt.Errorf("IAM endpoint must be an absolute HTTP(S) URL ending in /v3/")
	}
	service := &Service{client: identity, base: base}
	if identity.HTTPClient.Timeout == 0 {
		identity.HTTPClient.Timeout = 30 * time.Second
	}
	// The SDK otherwise retries rate limits up to twenty times with one-minute
	// sleeps. A CLI command must return a useful error instead of hanging.
	identity.MaxBackoffRetries = new(int)
	transport := identity.HTTPClient.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	identity.HTTPClient.Transport = iamResponseTransport{base: transport, validate: service.validateURL}
	// A redirect must not forward an IAM token to another host or service. The
	// provider belongs to this service, so this does not alter other CLI clients.
	identity.HTTPClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return fmt.Errorf("too many IAM redirects")
		}
		return service.validateURL(req.URL)
	}
	return service, nil
}

// ValidateID accepts a literal API identifier, never a path or URL fragment.
func ValidateID(label, id string) error {
	if id == "" || id == "." || strings.Contains(id, "..") ||
		strings.ContainsAny(id, "/\\?#%") || strings.TrimSpace(id) != id ||
		strings.ContainsFunc(id, unicode.IsControl) {
		return fmt.Errorf("%s must be a non-empty literal ID without path or URL characters", label)
	}
	return nil
}

// Scope identifies one explicit grant scope. AllProjects means an inherited
// grant under DomainID; it is distinct from a domain's global-service grant.
type Scope struct {
	DomainID    string
	ProjectID   string
	AllProjects bool
}

func (scope Scope) Validate() error {
	if (scope.DomainID == "") == (scope.ProjectID == "") {
		return fmt.Errorf("specify exactly one of domain ID or project ID")
	}
	if scope.AllProjects && scope.DomainID == "" {
		return fmt.Errorf("all-projects scope requires a domain ID")
	}
	if scope.DomainID != "" {
		return ValidateID("domain ID", scope.DomainID)
	}
	return ValidateID("project ID", scope.ProjectID)
}

func (s *Service) ListUsers(domainID, name string) ([]Record, error) {
	return s.listFiltered("users", domainID, name)
}

func (s *Service) GetUser(id string) (Record, error) {
	return s.get("user", "users", id)
}

func (s *Service) ListUserGroups(id string) ([]Record, error) {
	return s.listIDs("groups", "users", id, "groups")
}

func (s *Service) ListGroups(domainID, name string) ([]Record, error) {
	return s.listFiltered("groups", domainID, name)
}

func (s *Service) GetGroup(id string) (Record, error) {
	return s.get("group", "groups", id)
}

func (s *Service) ListGroupUsers(id string) ([]Record, error) {
	return s.listIDs("users", "groups", id, "users")
}

func (s *Service) ListGroupRoles(groupID string, scope Scope) ([]Record, error) {
	if err := scope.Validate(); err != nil {
		return nil, err
	}
	if scope.AllProjects {
		return s.listIDs("roles", "OS-INHERIT", "domains", scope.DomainID, "groups", groupID, "roles", "inherited_to_projects")
	}
	if scope.DomainID != "" {
		return s.listIDs("roles", "domains", scope.DomainID, "groups", groupID, "roles")
	}
	return s.listIDs("roles", "projects", scope.ProjectID, "groups", groupID, "roles")
}

// ListRoles lists system roles/policies by default. A domain ID selects that
// account's custom policies instead; the OTC API treats these as separate lists.
func (s *Service) ListRoles(domainID, name string) ([]Record, error) {
	return s.listFiltered("roles", domainID, name)
}

func (s *Service) GetRole(id string) (Record, error) {
	return s.get("role", "roles", id)
}

func (s *Service) ListProviders() ([]Record, error) {
	return s.listIDs("identity_providers", "OS-FEDERATION", "identity_providers")
}

func (s *Service) GetProvider(id string) (Record, error) {
	return s.get("identity_provider", "OS-FEDERATION", "identity_providers", id)
}

func (s *Service) ListProtocols(providerID string) ([]Record, error) {
	return s.listIDs("protocols", "OS-FEDERATION", "identity_providers", providerID, "protocols")
}

func (s *Service) GetProtocol(providerID, protocolID string) (Record, error) {
	return s.get("protocol", "OS-FEDERATION", "identity_providers", providerID, "protocols", protocolID)
}

func (s *Service) ListMappings() ([]Record, error) {
	return s.listIDs("mappings", "OS-FEDERATION", "mappings")
}

func (s *Service) GetMapping(id string) (Record, error) {
	return s.get("mapping", "OS-FEDERATION", "mappings", id)
}

func (s *Service) endpoint(parts ...string) (*url.URL, error) {
	escaped := make([]string, len(parts))
	for i, part := range parts {
		if err := ValidateID("resource ID", part); err != nil {
			return nil, err
		}
		escaped[i] = url.PathEscape(part)
	}
	return url.Parse(s.client.ServiceURL(escaped...))
}

func (s *Service) listFiltered(resource, domainID, name string) ([]Record, error) {
	endpoint, err := s.endpoint(resource)
	if err != nil {
		return nil, err
	}
	query := url.Values{}
	if domainID != "" {
		if err := ValidateID("domain ID", domainID); err != nil {
			return nil, err
		}
		query.Set("domain_id", domainID)
	}
	if name != "" {
		query.Set("name", name)
	}
	endpoint.RawQuery = query.Encode()
	return s.list(resource, endpoint)
}

func (s *Service) listIDs(key string, parts ...string) ([]Record, error) {
	endpoint, err := s.endpoint(parts...)
	if err != nil {
		return nil, err
	}
	return s.list(key, endpoint)
}

func (s *Service) get(key string, parts ...string) (Record, error) {
	endpoint, err := s.endpoint(parts...)
	if err != nil {
		return nil, err
	}
	var envelope map[string]json.RawMessage
	if err := s.read(endpoint, &envelope); err != nil {
		return nil, err
	}
	var record Record
	if err := decode(envelope[key], &record); err != nil || record == nil {
		return nil, fmt.Errorf("IAM response from %s must contain a %s object", endpoint.Path, key)
	}
	return record, nil
}

func (s *Service) list(key string, endpoint *url.URL) ([]Record, error) {
	records := make([]Record, 0)
	seen := make(map[string]bool)
	for pageNumber := 0; ; pageNumber++ {
		if pageNumber >= 10000 {
			return nil, fmt.Errorf("IAM pagination exceeded 10000 pages")
		}
		endpoint.RawQuery = endpoint.Query().Encode()
		if seen[endpoint.String()] {
			return nil, fmt.Errorf("IAM pagination contains a repeated page")
		}
		seen[endpoint.String()] = true
		var envelope map[string]json.RawMessage
		if err := s.read(endpoint, &envelope); err != nil {
			return nil, err
		}
		var page []Record
		if err := decode(envelope[key], &page); err != nil || page == nil {
			return nil, fmt.Errorf("IAM response from %s must contain a %s array", endpoint.Path, key)
		}
		for _, record := range page {
			if record == nil {
				return nil, fmt.Errorf("IAM %s array contains a null record", key)
			}
		}
		records = append(records, page...)
		var links struct {
			Next       *string `json:"next"`
			NextMarker *string `json:"next_marker"`
		}
		if raw, ok := envelope["links"]; ok {
			if err := json.Unmarshal(raw, &links); err != nil {
				return nil, fmt.Errorf("decode IAM pagination: %w", err)
			}
		}
		if (links.Next == nil || *links.Next == "") && links.NextMarker != nil && *links.NextMarker != "" {
			next := *endpoint
			query := next.Query()
			query.Set("marker", *links.NextMarker)
			next.RawQuery = query.Encode()
			endpoint = &next
			continue
		}
		if links.Next == nil || *links.Next == "" {
			return records, nil
		}
		reference, err := url.Parse(*links.Next)
		if err != nil {
			return nil, fmt.Errorf("invalid IAM pagination link: %w", err)
		}
		endpoint = endpoint.ResolveReference(reference)
		if err := s.validateURL(endpoint); err != nil {
			return nil, err
		}
	}
}

func decode(raw json.RawMessage, target any) error {
	if err := validateJSONDocument(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("IAM response must contain exactly one JSON value")
	}
	return nil
}

func (s *Service) read(endpoint *url.URL, target any) error {
	return s.readWithHeaders(endpoint, target, nil)
}

func (s *Service) readWithHeaders(endpoint *url.URL, target any, headers map[string]string) error {
	if err := s.validateURL(endpoint); err != nil {
		return err
	}
	response, err := s.client.Get(endpoint.String(), nil, &golangsdk.RequestOpts{
		OkCodes: []int{http.StatusOK}, RetryCount: new(int), MoreHeaders: headers,
	})
	if err != nil {
		return fmt.Errorf("read IAM %s: %w", endpoint.Path, err)
	}
	defer response.Body.Close()
	const maxBytes = 16 << 20
	data, err := io.ReadAll(io.LimitReader(response.Body, maxBytes+1))
	if err != nil {
		return fmt.Errorf("read IAM %s: %w", endpoint.Path, err)
	}
	if len(data) > maxBytes {
		return fmt.Errorf("IAM response exceeds %d bytes", maxBytes)
	}
	if err := decode(data, target); err != nil {
		return fmt.Errorf("decode IAM %s: %w", endpoint.Path, err)
	}
	return nil
}

func (s *Service) validateURL(endpoint *url.URL) error {
	if !strings.EqualFold(endpoint.Scheme, s.base.Scheme) || !strings.EqualFold(endpoint.Host, s.base.Host) ||
		endpoint.User != nil || endpoint.Fragment != "" || endpoint.Opaque != "" ||
		!s.allowedAPIPath(endpoint.Path) || strings.ContainsAny(endpoint.Path, "\\%") ||
		strings.ContainsFunc(endpoint.Path, unicode.IsControl) {
		return fmt.Errorf("IAM pagination or redirect must stay on the configured IAM API endpoint")
	}
	for _, part := range strings.Split(endpoint.Path, "/") {
		if part == "." || part == ".." {
			return fmt.Errorf("IAM pagination or redirect contains path traversal")
		}
	}
	return nil
}
