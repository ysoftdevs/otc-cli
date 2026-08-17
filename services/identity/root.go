package identity

import (
	"fmt"
	"strings"

	"github.com/ysoftdevs/otc-cli/client"
	"github.com/ysoftdevs/otc-cli/config"

	golangsdk "github.com/opentelekomcloud/gophertelekomcloud"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/identity/v3/domains"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/identity/v3/tokens"
)

type CallerIdentity struct {
	DomainID    string
	DomainName  string
	ProjectID   string
	ProjectName string
	UserID      string
	UserName    string
	AccessKey   string
	Roles       string
}

// WhoAmI returns the domain, project, user and roles that the currently
// configured credentials (clouds.yaml, AK/SK env vars, etc.) authenticate as.
func WhoAmI(commonConfig *config.CommonConfig) (*CallerIdentity, error) {
	opts, err := client.GetAuthOpts(commonConfig)
	if err != nil {
		return nil, err
	}

	pc, err := client.GetAuthenticatedClient(opts)
	if err != nil {
		return nil, err
	}

	// AK/SK auth never issues a bearer token (no POST /v3/auth/tokens ever
	// happens), so pc.Token() is empty and GET /v3/auth/tokens always fails
	// with a misleading 404 regardless of the credential's IAM permissions.
	if pc.AKSKAuthOptions.AccessKey != "" {
		return whoAmIFromAKSK(pc)
	}

	return whoAmIFromToken(pc)
}

// whoAmIFromAKSK reports identity for AK/SK-authenticated clients using only
// state already resolved during authentication, plus the self-service
// GET /v3/auth/domains call (lists domains the caller has access to), which
// requires no IAM permission beyond being an authenticated user. There is no
// reverse AK -> IAM user/username lookup available without extra
// (iam:credentials:get / iam:users:get) permissions, so User/Roles stay empty.
func whoAmIFromAKSK(pc *golangsdk.ProviderClient) (*CallerIdentity, error) {
	info := &CallerIdentity{
		DomainID:    pc.AKSKAuthOptions.DomainID,
		ProjectID:   pc.AKSKAuthOptions.ProjectId,
		ProjectName: pc.AKSKAuthOptions.ProjectName,
		AccessKey:   pc.AKSKAuthOptions.AccessKey,
	}

	if info.DomainID == "" {
		if domainID, domainName, err := lookupOwnDomain(pc); err == nil {
			info.DomainID = domainID
			info.DomainName = domainName
		}
	}

	return info, nil
}

func lookupOwnDomain(pc *golangsdk.ProviderClient) (string, string, error) {
	identityClient, err := openstack.NewIdentityV3(pc, golangsdk.EndpointOpts{})
	if err != nil {
		return "", "", err
	}
	identityClient.Endpoint += "auth/"

	pages, err := domains.List(identityClient, domains.ListOpts{}).AllPages()
	if err != nil {
		return "", "", fmt.Errorf("failed to list accessible domains: %w", err)
	}
	all, err := domains.ExtractDomains(pages)
	if err != nil {
		return "", "", fmt.Errorf("failed to extract domains: %w", err)
	}
	if len(all) != 1 {
		return "", "", fmt.Errorf("expected exactly one accessible domain, got %d", len(all))
	}
	return all[0].ID, all[0].Name, nil
}

func whoAmIFromToken(pc *golangsdk.ProviderClient) (*CallerIdentity, error) {
	identityClient, err := openstack.NewIdentityV3(pc, golangsdk.EndpointOpts{})
	if err != nil {
		return nil, fmt.Errorf("failed to create identity client: %w", err)
	}

	result := tokens.Get(identityClient, pc.Token())

	user, err := result.ExtractUser()
	if err != nil {
		return nil, fmt.Errorf("failed to extract user from token: %w", err)
	}
	project, err := result.ExtractProject()
	if err != nil {
		return nil, fmt.Errorf("failed to extract project from token: %w", err)
	}
	domain, err := result.ExtractDomain()
	if err != nil {
		return nil, fmt.Errorf("failed to extract domain from token: %w", err)
	}
	roles, err := result.ExtractRoles()
	if err != nil {
		return nil, fmt.Errorf("failed to extract roles from token: %w", err)
	}

	info := &CallerIdentity{}
	if user != nil {
		info.UserID = user.ID
		info.UserName = user.Name
	}
	if project != nil {
		info.ProjectID = project.ID
		info.ProjectName = project.Name
		// Project-scoped tokens carry the domain via the project.
		info.DomainID = project.Domain.ID
		info.DomainName = project.Domain.Name
	}
	if domain != nil {
		info.DomainID = domain.ID
		info.DomainName = domain.Name
	}

	roleNames := make([]string, 0, len(roles))
	for _, r := range roles {
		roleNames = append(roleNames, r.Name)
	}
	info.Roles = strings.Join(roleNames, ", ")

	return info, nil
}
