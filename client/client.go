package client

import (
	"fmt"

	golangsdk "github.com/opentelekomcloud/gophertelekomcloud"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack"
)

type CommonConfig struct {
	EnvPrefix   string
	CloudName   string
	Region      string
	ProjectName string
}

func GetAuthOpts(config *CommonConfig) (golangsdk.AuthOptionsProvider, error) {
	env := openstack.NewEnv(config.EnvPrefix)

	var cloud *openstack.Cloud
	var err error

	if config.CloudName != "" {
		cloud, err = env.Cloud(config.CloudName)
	} else {
		cloud, err = env.Cloud()
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get cloud from environment: %w", err)
	}

	opts, err := openstack.AuthOptionsFromInfo(&cloud.AuthInfo, cloud.AuthType)
	if err != nil {
		return nil, fmt.Errorf("failed to convert AuthInfo to AuthOptsBuilder with Env vars: %s", err)
	}

	if akskOpts, ok := opts.(golangsdk.AKSKAuthOptions); ok {
		// There is a bug in AuthOptionsFromInfo where SecurityToken is not set from AuthInfo
		setIfEmpty(&akskOpts.SecurityToken, cloud.AuthInfo.SecurityToken)

		setIfEmpty(&akskOpts.ProjectName, config.ProjectName)
		
		return akskOpts, nil
	} else if pwOpts, ok := opts.(golangsdk.AuthOptions); ok {
		setIfEmpty(&pwOpts.TenantName, config.ProjectName)
		return pwOpts, nil
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

func setIfEmpty(value *string, newValue string) {
	if *value == "" {
		*value = newValue
	}
}