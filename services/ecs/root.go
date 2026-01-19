package ecs

import (
	"fmt"
	"otc-cli/client"
	"otc-cli/config"

	golangsdk "github.com/opentelekomcloud/gophertelekomcloud"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/compute/v2/extensions/startstop"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/compute/v2/servers"
)

func getComputeClouds(commonConfig *config.CommonConfig) (*golangsdk.ServiceClient, error) {
	opts, err := client.GetAuthOpts(commonConfig)
	if err != nil {
		return nil, err
	}

	client, err := client.GetAuthenticatedClient(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate client: %s", err)
	}

	return openstack.NewComputeV2(client, golangsdk.EndpointOpts{
		Region: commonConfig.Region,
	})
}

type ListArgs struct {
	Limit        int
	Filter       string
	CommonConfig *config.CommonConfig
}

func List(args ListArgs) ([]servers.Server, error) {
	compute, err := getComputeClouds(args.CommonConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Compute client: %w", err)
	}

	opts := servers.ListOpts{}
	if args.Limit > 0 {
		opts.Limit = args.Limit
	}
	if args.Filter != "" {
		opts.Name = args.Filter
	}

	serverPage := servers.List(compute, opts)
	if serverPage.Err != nil {
		return nil, fmt.Errorf("failed to list servers: %w", serverPage.Err)
	}

	allPages, err := serverPage.AllPages()
	if err != nil {
		return nil, fmt.Errorf("failed to get all pages of servers: %w", err)
	}

	serverList, err := servers.ExtractServers(allPages)
	if err != nil {
		return nil, fmt.Errorf("failed to extract servers: %w", err)
	}

	return serverList, nil
}

func getServerByName(compute *golangsdk.ServiceClient, name string) (*servers.Server, error) {
	opts := servers.ListOpts{
		Name:  name,
		Limit: 2,
	}

	serverPage := servers.List(compute, opts)
	if serverPage.Err != nil {
		return nil, fmt.Errorf("failed to list servers: %w", serverPage.Err)
	}

	allPages, err := serverPage.AllPages()
	if err != nil {
		return nil, fmt.Errorf("failed to get all pages of servers: %w", err)
	}

	serverList, err := servers.ExtractServers(allPages)
	if err != nil {
		return nil, fmt.Errorf("failed to extract servers: %w", err)
	}

	if len(serverList) != 1 {
		return nil, fmt.Errorf("expected exactly one server with name %s, but found %d", name, len(serverList))
	}

	return &serverList[0], nil
}

func StartServer(name string, commonConfig *config.CommonConfig) error {
	compute, err := getComputeClouds(commonConfig)
	if err != nil {
		return fmt.Errorf("failed to create Compute client: %w", err)
	}

	server, err := getServerByName(compute, name)
	if err != nil {
		return err
	}

	err = startstop.Start(compute, server.ID).ExtractErr()
	if err != nil {
		return fmt.Errorf("failed to start server %s: %w", name, err)
	}

	return nil
}

func StopServer(name string, commonConfig *config.CommonConfig) error {
	compute, err := getComputeClouds(commonConfig)
	if err != nil {
		return fmt.Errorf("failed to create Compute client: %w", err)
	}

	server, err := getServerByName(compute, name)
	if err != nil {
		return err
	}

	err = startstop.Stop(compute, server.ID).ExtractErr()
	if err != nil {
		return fmt.Errorf("failed to stop server %s: %w", name, err)
	}
	return nil
}
