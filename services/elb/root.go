package elb

import (
	"fmt"
	"strings"

	"github.com/ysoftdevs/otc-cli/client"
	"github.com/ysoftdevs/otc-cli/config"

	golangsdk "github.com/opentelekomcloud/gophertelekomcloud"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack"
	"github.com/opentelekomcloud/gophertelekomcloud/openstack/elb/v3/loadbalancers"
)

type LoadBalancerInfo struct {
	ID         string
	Name       string
	Status     string
	VipAddress string
	PublicIPs  []string
}

func getELBClient(commonConfig *config.CommonConfig) (*golangsdk.ServiceClient, error) {
	opts, err := client.GetAuthOpts(commonConfig)
	if err != nil {
		return nil, err
	}

	c, err := client.GetAuthenticatedClient(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate client: %w", err)
	}

	return openstack.NewELBV3(c, golangsdk.EndpointOpts{
		Region: commonConfig.Region,
	})
}

type ListArgs struct {
	Filter       string
	CommonConfig *config.CommonConfig
}

func List(args ListArgs) ([]LoadBalancerInfo, error) {
	elbClient, err := getELBClient(args.CommonConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create ELB client: %w", err)
	}

	opts := loadbalancers.ListOpts{}
	if args.Filter != "" {
		opts.Name = []string{args.Filter}
	}
	pages, err := loadbalancers.List(elbClient, opts).AllPages()
	if err != nil {
		return nil, fmt.Errorf("failed to list load balancers: %w", err)
	}

	lbs, err := loadbalancers.ExtractLoadbalancers(pages)
	if err != nil {
		return nil, fmt.Errorf("failed to extract load balancers: %w", err)
	}

	result := make([]LoadBalancerInfo, 0, len(lbs))
	for _, lb := range lbs {
		result = append(result, toInfo(lb))
	}
	return result, nil
}

func Show(name string, commonConfig *config.CommonConfig) (*LoadBalancerInfo, error) {
	elbClient, err := getELBClient(commonConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create ELB client: %w", err)
	}

	pages, err := loadbalancers.List(elbClient, loadbalancers.ListOpts{
		Name: []string{name},
	}).AllPages()
	if err != nil {
		return nil, fmt.Errorf("failed to list load balancers: %w", err)
	}

	lbs, err := loadbalancers.ExtractLoadbalancers(pages)
	if err != nil {
		return nil, fmt.Errorf("failed to extract load balancers: %w", err)
	}

	for _, lb := range lbs {
		if lb.Name == name {
			info := toInfo(lb)
			return &info, nil
		}
	}
	return nil, fmt.Errorf("load balancer %q not found", name)
}

func toInfo(lb loadbalancers.LoadBalancer) LoadBalancerInfo {
	info := LoadBalancerInfo{
		ID:         lb.ID,
		Name:       lb.Name,
		Status:     lb.OperatingStatus,
		VipAddress: lb.VipAddress,
	}
	for _, eip := range lb.Eips {
		if eip.EipAddress != "" {
			info.PublicIPs = append(info.PublicIPs, eip.EipAddress)
		}
	}
	for _, pip := range lb.PublicIps {
		if pip.PublicIpAddress != "" {
			info.PublicIPs = append(info.PublicIPs, pip.PublicIpAddress)
		}
	}
	return info
}

func PublicIPsString(info LoadBalancerInfo) string {
	return strings.Join(info.PublicIPs, ", ")
}
