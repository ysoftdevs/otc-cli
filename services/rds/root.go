package rds

import (
	"fmt"
	"otc-cli/client"
	"otc-cli/config"

	golangsdk "github.com/opentelekomcloud/gophertelekomcloud"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/rds/v3/instances"
)

func getRdsClient(commonConfig *config.CommonConfig) (*golangsdk.ServiceClient, error) {
	opts, err := client.GetAuthOpts(commonConfig)
	if err != nil {
		return nil, err
	}

	c, err := client.GetAuthenticatedClient(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate client: %s", err)
	}

	return openstack.NewRDSV3(c, golangsdk.EndpointOpts{
		Region: commonConfig.Region,
	})
}

type ListArgs struct {
	Opts         *instances.ListOpts
	CommonConfig *config.CommonConfig
}

func List(args *ListArgs) ([]instances.InstanceResponse, error) {
	rds, err := getRdsClient(args.CommonConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}

	response, err := instances.List(rds, *args.Opts)
	if err != nil {
		return nil, fmt.Errorf("failed to list databases: %w", err)
	}

	return response.Instances, nil
}
