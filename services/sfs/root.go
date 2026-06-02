package sfs

import (
	"fmt"
	"strings"

	"github.com/ysoftdevs/otc-cli/client"
	"github.com/ysoftdevs/otc-cli/config"

	golangsdk "github.com/opentelekomcloud/gophertelekomcloud"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/sfs_turbo/v1/shares"
)

type ShareInfo struct {
	ID             string
	Name           string
	Status         string
	ExportLocation string
}

func getSFSClient(commonConfig *config.CommonConfig) (*golangsdk.ServiceClient, error) {
	opts, err := client.GetAuthOpts(commonConfig)
	if err != nil {
		return nil, err
	}

	c, err := client.GetAuthenticatedClient(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate client: %w", err)
	}

	return openstack.NewSharedFileSystemTurboV1(c, golangsdk.EndpointOpts{
		Region: commonConfig.Region,
	})
}

type ListArgs struct {
	Filter       string
	CommonConfig *config.CommonConfig
}

func List(args ListArgs) ([]ShareInfo, error) {
	sfsClient, err := getSFSClient(args.CommonConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create SFS Turbo client: %w", err)
	}

	pages, err := shares.List(sfsClient, shares.ListOpts{}).AllPages()
	if err != nil {
		return nil, fmt.Errorf("failed to list SFS Turbo shares: %w", err)
	}

	allShares, err := shares.ExtractTurbos(pages)
	if err != nil {
		return nil, fmt.Errorf("failed to extract SFS Turbo shares: %w", err)
	}

	result := make([]ShareInfo, 0, len(allShares))
	for _, s := range allShares {
		if args.Filter != "" && !strings.Contains(s.Name, args.Filter) {
			continue
		}
		result = append(result, ShareInfo{
			ID:             s.ID,
			Name:           s.Name,
			Status:         s.Status,
			ExportLocation: s.ExportLocation,
		})
	}

	return result, nil
}

func ExportIP(path string) string {
	// paths are like: 192.168.x.x:/
	if idx := strings.Index(path, ":"); idx > 0 {
		return path[:idx]
	}
	return path
}
