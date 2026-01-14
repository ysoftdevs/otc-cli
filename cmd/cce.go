package cmd

import (
	"fmt"
	"os"

	"github.com/opentelekomcloud/gophertelekomcloud"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/cce/v3/clusters"
)

func runCCE(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("no CCE subcommand specified. Available: list")
	}

	subcommand := args[0]
	switch subcommand {
	case "list":
		return runCCEList()
	default:
		return fmt.Errorf("unknown CCE subcommand: %s", subcommand)
	}
}

func runCCEList() error {
	// Load clouds.yaml
	cloudsPath, err := GetCloudsYAMLPath()
	if err != nil {
		return err
	}

	clouds, err := LoadCloudsYAML(cloudsPath)
	if err != nil {
		return fmt.Errorf("failed to load clouds.yaml: %w", err)
	}

	// Get the "otc" cloud configuration
	cloudConfig, ok := clouds.Clouds["otc"]
	if !ok {
		return fmt.Errorf("cloud 'otc' not found in clouds.yaml. Please run 'login' first")
	}

	// Create authentication options
	authOpts := gophercloud.AuthOptions{
		IdentityEndpoint: cloudConfig.Auth.AuthURL,
		DomainName:       cloudConfig.Auth.DomainName,
		TokenID:          cloudConfig.Auth.Token,
	}

	// Authenticate
	provider, err := openstack.AuthenticatedClient(authOpts)
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	// Create CCE service client
	client, err := openstack.NewCCEV3(provider, gophercloud.EndpointOpts{
		Region: cloudConfig.RegionName,
	})
	if err != nil {
		return fmt.Errorf("failed to create CCE client: %w", err)
	}

	// List clusters
	allPages, err := clusters.List(client, clusters.ListOpts{}).AllPages()
	if err != nil {
		return fmt.Errorf("failed to list clusters: %w", err)
	}

	clusterList, err := clusters.ExtractClusters(allPages)
	if err != nil {
		return fmt.Errorf("failed to extract clusters: %w", err)
	}

	// Print cluster names
	if len(clusterList) == 0 {
		fmt.Fprintln(os.Stderr, "No CCE clusters found")
		return nil
	}

	for _, cluster := range clusterList {
		fmt.Println(cluster.Metadata.Name)
	}

	return nil
}
