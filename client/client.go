package client

import (
	"fmt"

	golangsdk "github.com/opentelekomcloud/gophertelekomcloud"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack"
)

func GetAuthOpts() (golangsdk.AuthOptionsProvider, error) {
	env := openstack.NewEnv("OTC_")
	cloud, err := env.Cloud("otc-prod")

	if err != nil {
		return nil, fmt.Errorf("failed to get cloud from environment: %w", err)
	}

	opts, err := openstack.AuthOptionsFromInfo(&cloud.AuthInfo, cloud.AuthType)
	if err != nil {
		return nil, fmt.Errorf("failed to convert AuthInfo to AuthOptsBuilder with Env vars: %s", err)
	}

	if akskOpts, ok := opts.(golangsdk.AKSKAuthOptions); ok {
		// There is a bug in AuthOptionsFromInfo where SecurityToken is not set from AuthInfo
		if akskOpts.SecurityToken == "" && cloud.AuthInfo.SecurityToken != "" {
			akskOpts.SecurityToken = cloud.AuthInfo.SecurityToken
			opts = akskOpts
		}
	}
	return opts, nil
}

func GetAuthenticatedClient(opts golangsdk.AuthOptionsProvider) (*golangsdk.ProviderClient, error) {
	client, err := openstack.AuthenticatedClient(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate client: %s", err)
	}
	return client, nil
}