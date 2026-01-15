package cmd

import (
	"fmt"
	"os"
	"otc-cli/client"

	golangsdk "github.com/opentelekomcloud/gophertelekomcloud"
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
		return runCCEList(args[1:])
	default:
		return fmt.Errorf("unknown CCE subcommand: %s", subcommand)
	}
}

func getCCEClouds(projectName string) (*golangsdk.ServiceClient, error) {
	commonOpts := &client.CommonConfig{
		EnvPrefix:   "OTC_",
		CloudName:   "otc-prod",
		Region:      "eu-de",
		ProjectName: projectName,
	}

	opts, err := client.GetAuthOpts(commonOpts)
	if err != nil {
		return nil, err
	}

	if projectName != "" {
		if akOpts, ok := opts.(golangsdk.AKSKAuthOptions); ok {
			akOpts.ProjectName = projectName
			opts = akOpts
		} else if pwOpts, ok := opts.(golangsdk.AuthOptions); ok {
			pwOpts.TenantName = projectName
			opts = pwOpts
		}
	}

	client, err := client.GetAuthenticatedClient(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate client: %s", err)
	}

	return openstack.NewCCE(client, golangsdk.EndpointOpts{
		Region: commonOpts.Region,
	})
}



func runCCEList(args []string) error {
	projectName := ""
	if len(args) >= 1 {
		projectName = args[0]
	}


	cce, err := getCCEClouds(projectName)
	if err != nil {
		return fmt.Errorf("failed to create CCE client: %w", err)
	}

	clusterList, err := clusters.List(cce, clusters.ListOpts{})
	if err != nil {
		return fmt.Errorf("failed to list clusters: %w", err)
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
