package cce

import (
	"encoding/json"
	"fmt"
	"os"
	"otc-cli/client"
	"otc-cli/config"

	golangsdk "github.com/opentelekomcloud/gophertelekomcloud"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/cce/v3/clusters"
)

func getCCEClouds(commonConfig *config.CommonConfig) (*golangsdk.ServiceClient, error) {
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

func List(commonConfig *config.CommonConfig) ([]clusters.Clusters, error) {
	cce, err := getCCEClouds(commonConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create CCE client: %w", err)
	}

	clusterList, err := clusters.List(cce, clusters.ListOpts{})
	if err != nil {
		return nil, fmt.Errorf("failed to list clusters: %w", err)
	}

	return clusterList, nil
}

type ConfigArgs struct {
	CommonConfig *config.CommonConfig
	ClusterName  string
	OutputPath   string
}

func Config(args ConfigArgs) error {
	cce, err := getCCEClouds(args.CommonConfig)
	if err != nil {
		return fmt.Errorf("failed to create CCE client: %w", err)
	}

	clusterList, err := clusters.List(cce, clusters.ListOpts{Name: args.ClusterName})
	if err != nil {
		return fmt.Errorf("failed to list clusters: %w", err)
	}

	if len(clusterList) == 0 {
		return fmt.Errorf("cluster '%s' not found", args.ClusterName)
	}

	expiryOpts := clusters.ExpirationOpts{
		Duration: -1,
	}
	kubeconfig, err := clusters.GetCertWithExpiration(cce, clusterList[0].Metadata.Id, expiryOpts)
	if err != nil {
		return fmt.Errorf("unable to retrieve cluster kubeconfig: %w", err)
	}

	configJson, err := json.MarshalIndent(kubeconfig, "", "  ")
	if err != nil {
		return fmt.Errorf("unable to marshal cluster kubeconfig: %w", err)
	}

	if args.OutputPath != "" {
		if err := os.WriteFile(args.OutputPath, configJson, 0600); err != nil {
			return fmt.Errorf("unable to write kubeconfig to file: %w", err)
		}
		fmt.Printf("Kubeconfig written to %s\n", args.OutputPath)
		return nil
	} else {
		fmt.Println(string(configJson))
	}

	return nil
}
