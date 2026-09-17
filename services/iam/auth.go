package iam

import (
	"encoding/json"
	"fmt"
	"net/http"

	golangsdk "github.com/opentelekomcloud/gophertelekomcloud"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/identity/v3/tokens"
)

// Install the IAM transport guards before the first authentication request.
// The common authenticated-client helper authenticates before callers can
// configure redirects, which would expose custom token headers to redirects.
func newAuthenticatedService(opts golangsdk.AuthOptionsProvider) (*Service, error) {
	provider, err := openstack.NewClient(opts.GetIdentityEndpoint())
	if err != nil {
		return nil, fmt.Errorf("create IAM provider: %w", err)
	}
	identity, err := openstack.NewIdentityV3(provider, golangsdk.EndpointOpts{})
	if err != nil {
		return nil, fmt.Errorf("create IAM client: %w", err)
	}
	service, err := newService(identity)
	if err != nil {
		return nil, err
	}
	if tokenOptions, ok := opts.(golangsdk.AuthOptions); ok && tokenOptions.TokenID != "" &&
		tokenOptions.AgencyName == "" && tokenOptions.AgencyDomainName == "" {
		// ensureDomainToken already validates cached tokens. Avoid an identical
		// SDK read before it, and retain control over retries and response limits.
		provider.SetToken(tokenOptions.TokenID)
	} else if err := openstack.Authenticate(provider, opts); err != nil {
		// SDK errors can include a server-echoed password or token. Keep the
		// authentication boundary free of raw response bodies and headers.
		return nil, fmt.Errorf("IAM authentication failed; verify the configured endpoint, authentication method and credentials")
	}
	if err := service.ensureDomainToken(); err != nil {
		return nil, err
	}
	return service, nil
}

// ensureDomainToken keeps IAM authentication separate from the project token
// cached for regional services. The provider belongs to this IAM invocation;
// nothing here writes clouds.yaml or changes the user's grants.
func (s *Service) ensureDomainToken() error {
	provider := s.client.ProviderClient
	if provider.AKSKOptions().AccessKey != "" {
		return nil
	}
	original := provider.Token()
	if original == "" {
		return fmt.Errorf("IAM requires an authenticated token or AK/SK credentials")
	}

	// Expired credentials must not silently restore the old project scope.
	provider.ReauthFunc = nil
	tokenURL, err := s.versionEndpoint("v3", "auth", "tokens")
	if err != nil {
		return err
	}
	var current tokens.GetResult
	var tokenBody json.RawMessage
	current.Err = s.readWithHeaders(tokenURL, &tokenBody, map[string]string{"X-Subject-Token": original})
	if current.Err != nil {
		return fmt.Errorf("IAM token inspection failed; verify token validity and account access")
	}
	current.Body = tokenBody
	domain, err := current.ExtractDomain()
	if err != nil {
		return fmt.Errorf("inspect IAM token account scope: %w", err)
	}
	project, err := current.ExtractProject()
	if err != nil {
		return fmt.Errorf("inspect IAM token project scope: %w", err)
	}
	if domain != nil && domain.ID != "" {
		if project != nil {
			return fmt.Errorf("IAM token contains both account and project scopes")
		}
		provider.DomainID = domain.ID
		return nil
	}
	if project == nil || project.ID == "" || project.Domain.ID == "" {
		return fmt.Errorf("cannot determine IAM account from token scope; log in with an account or project scope")
	}
	// A federated user's home domain need not be the account owning the project.
	accountID := project.Domain.ID
	authOptions := &tokens.AuthOptions{
		TokenID: original,
		Scope:   tokens.Scope{DomainID: accountID},
	}
	scope, err := authOptions.ToTokenV3ScopeMap()
	if err != nil {
		return fmt.Errorf("build IAM token scope: %w", err)
	}
	body, err := authOptions.ToTokenV3CreateMap(scope)
	if err != nil {
		return fmt.Errorf("build IAM token exchange: %w", err)
	}
	var issued tokens.CreateResult
	response, err := s.client.Post(tokenURL.String(), body, &issued.Body, &golangsdk.RequestOpts{
		OkCodes: []int{http.StatusCreated}, RetryCount: new(int),
	})
	if err != nil {
		return fmt.Errorf("IAM account token exchange failed; verify that this identity can access the account")
	}
	issued.Err = err
	if response != nil {
		issued.Header = response.Header
	}
	issuedToken, err := issued.ExtractToken()
	if err != nil {
		return fmt.Errorf("obtain IAM token for account %q: %w", accountID, err)
	}
	if issuedToken == nil || issuedToken.ID == "" {
		return fmt.Errorf("IAM account token response is missing X-Subject-Token")
	}
	issuedDomain, err := issued.ExtractDomain()
	if err != nil {
		return fmt.Errorf("read issued IAM token account scope: %w", err)
	}
	issuedProject, err := issued.ExtractProject()
	if err != nil {
		return fmt.Errorf("read issued IAM token project scope: %w", err)
	}
	if issuedDomain == nil || issuedDomain.ID != accountID || issuedProject != nil {
		return fmt.Errorf("IAM token response does not have the requested account scope %q", accountID)
	}
	provider.SetToken(issuedToken.ID)
	s.projectToken = original
	provider.DomainID = accountID
	provider.ProjectID = ""
	// Do not let SDK reauthentication silently restore the original project scope.
	provider.ReauthFunc = nil
	return nil
}
