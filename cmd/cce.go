package cmd

import (
	"flag"
	"fmt"
	"os"
	"otc-cli/client"

	golangsdk "github.com/opentelekomcloud/gophertelekomcloud"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/cce/v3/clusters"
)

func runCCE(commonFlags *CommonFlags, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("no CCE subcommand specified. Available: list")
	}

	subcommand := args[0]
	switch subcommand {
	case "list":
		return runCCEList(commonFlags, args[1:])
	default:
		return fmt.Errorf("unknown CCE subcommand: %s", subcommand)
	}
}

func getCCEClouds(commonConfig *client.CommonConfig) (*golangsdk.ServiceClient, error) {
	opts, err := client.GetAuthOpts(commonConfig)
	if err != nil {
		return nil, err
	}

	client, err := client.GetAuthenticatedClient(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate client: %s", err)
	}

	return openstack.NewCCE(client, golangsdk.EndpointOpts{
		Region: commonConfig.Region,
	})
}

func runCCEList(commonFlags *CommonFlags, args []string) error {
	fs := flag.NewFlagSet("cce list", flag.ContinueOnError)

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Check for positional argument for backward compatibility (project name)
	if commonFlags.Project == "" && fs.NArg() > 0 {
		commonFlags.Project = fs.Arg(0)
	}

	commonConfig := commonFlags.ToCommonConfig()
	cce, err := getCCEClouds(commonConfig)
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
