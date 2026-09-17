package iam

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	golangsdk "github.com/opentelekomcloud/gophertelekomcloud"
)

// Bound reads inside the SDK as well: its error handling and token exchange
// otherwise consume response bodies without a limit. The extra byte allows
// our JSON reader to distinguish a complete response from an oversized one.
type iamResponseTransport struct {
	base     http.RoundTripper
	validate func(*url.URL) error
}

func (t iamResponseTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if t.validate != nil {
		if err := t.validate(request.URL); err != nil {
			return nil, err
		}
	}
	response, err := t.base.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	response.Body = struct {
		io.Reader
		io.Closer
	}{io.LimitReader(response.Body, (16<<20)+1), response.Body}
	return response, nil
}

// OTC's extension APIs use v3.0 and v3-ext alongside Keystone v3 on the
// configured IAM host. These are explicit API roots, never an arbitrary URL.
func (s *Service) allowedAPIPath(path string) bool {
	prefix := strings.TrimSuffix(s.base.Path, "v3/")
	for _, version := range []string{"v3", "v3.0", "v3-ext"} {
		if strings.HasPrefix(path, prefix+version+"/") || path == prefix+version {
			return true
		}
	}
	return false
}

func (s *Service) versionEndpoint(version string, parts ...string) (*url.URL, error) {
	if version != "v3" && version != "v3.0" && version != "v3-ext" {
		return nil, fmt.Errorf("unsupported IAM API version %q", version)
	}
	endpoint := *s.base
	endpoint.Path = strings.TrimSuffix(s.base.Path, "v3/") + version
	for _, part := range parts {
		if err := ValidateID("resource ID", part); err != nil {
			return nil, err
		}
		endpoint.Path += "/" + part
	}
	endpoint.RawPath = ""
	return &endpoint, nil
}

func (s *Service) getVersion(version, key string, parts ...string) (Record, error) {
	endpoint, err := s.versionEndpoint(version, parts...)
	if err != nil {
		return nil, err
	}
	var envelope map[string]json.RawMessage
	if err := s.read(endpoint, &envelope); err != nil {
		return nil, err
	}
	if envelope == nil {
		return nil, fmt.Errorf("IAM response from %s must contain an object", endpoint.Path)
	}
	var record Record
	if key == "" {
		record = make(Record, len(envelope))
		for field, raw := range envelope {
			var value any
			if err := decode(raw, &value); err != nil {
				return nil, fmt.Errorf("decode IAM %s: %w", field, err)
			}
			record[field] = value
		}
		return record, nil
	}
	if err := decode(envelope[key], &record); err != nil || record == nil {
		return nil, fmt.Errorf("IAM response from %s must contain a %s object", endpoint.Path, key)
	}
	return record, nil
}

func (s *Service) listVersion(version, key string, query url.Values, parts ...string) ([]Record, error) {
	endpoint, err := s.versionEndpoint(version, parts...)
	if err != nil {
		return nil, err
	}
	endpoint.RawQuery = query.Encode()
	return s.list(key, endpoint)
}

// The service catalog describes regional endpoints and requires the original
// project token. Use a separate provider so account-scoped IAM calls retain
// their token even when this helper fails or the project token expires.
func (s *Service) listProjectCatalog() ([]Record, error) {
	if s.client.AKSKOptions().AccessKey != "" {
		return s.listVersion("v3", "catalog", nil, "auth", "catalog")
	}
	if s.projectToken == "" {
		return nil, fmt.Errorf("service catalog requires a project-scoped login; select a cloud profile with a project and log in")
	}
	provider := &golangsdk.ProviderClient{
		TokenID:           s.projectToken,
		HTTPClient:        s.client.HTTPClient,
		UserAgent:         s.client.UserAgent,
		MaxBackoffRetries: new(int),
	}
	projectService := &Service{
		client: &golangsdk.ServiceClient{ProviderClient: provider, Endpoint: s.client.Endpoint},
		base:   s.base,
	}
	return projectService.listVersion("v3", "catalog", nil, "auth", "catalog")
}

// SP metadata is XML rather than a JSON envelope. Only documented IAM roots
// are accepted; authentication and redirect checks match other IAM requests.
func (s *Service) readTextVersion(version string, parts ...string) (string, error) {
	endpoint, err := s.versionEndpoint(version, parts...)
	if err != nil {
		return "", err
	}
	if err := s.validateURL(endpoint); err != nil {
		return "", err
	}
	response, err := s.client.Get(endpoint.String(), nil, &golangsdk.RequestOpts{
		OkCodes: []int{http.StatusOK}, MoreHeaders: map[string]string{"Accept": "application/xml, text/xml"}, RetryCount: new(int),
	})
	if err != nil {
		return "", fmt.Errorf("read IAM %s: %w", endpoint.Path, err)
	}
	defer response.Body.Close()
	const maxBytes = 2 << 20
	data, err := io.ReadAll(io.LimitReader(response.Body, maxBytes+1))
	if err != nil {
		return "", fmt.Errorf("read IAM metadata: %w", err)
	}
	if len(data) > maxBytes {
		return "", fmt.Errorf("IAM metadata exceeds %d bytes", maxBytes)
	}
	return string(data), nil
}
