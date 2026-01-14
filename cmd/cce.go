package cmd

import (
	"fmt"
	"os"

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
		return runCCEList()
	default:
		return fmt.Errorf("unknown CCE subcommand: %s", subcommand)
	}
}

func getCCEClouds() (*golangsdk.ServiceClient, error) {
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

	client, err := openstack.AuthenticatedClient(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate client: %s", err)
	}

	return openstack.NewCCE(client, golangsdk.EndpointOpts{
		Region: "eu-de",
	})
}

func runCCEList() error {
	cce, err := getCCEClouds()
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
