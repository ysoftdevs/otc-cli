package config

import (
	"fmt"
	"os"
)

type CommonConfig struct {
	EnvPrefix   string
	CloudName   string
	Region      string
	ProjectName string

	Clouds        *CloudsYAML
	SelectedCloud *CloudConfig
}

func (base *CommonConfig) AugmentFromFiles() error {
	clouds, err := LoadCloudsYAMLFromDefaultLocation()
	if err != nil {
		return err
	}

	SetIfEmpty(&base.CloudName, base.getEnv("CLOUD"), clouds.SelectedCloud)
	base.Clouds = &clouds

	if cloud, ok := clouds.Clouds[base.CloudName]; ok {
		base.SelectedCloud = &cloud
		SetIfEmpty(&base.Region, base.getEnv("REGION"), cloud.RegionName)
		SetIfEmpty(&base.ProjectName, base.getEnv("PROJECT"), cloud.Auth.ProjectName)
	}

	return nil
}

// RequireCloudFound reports an error if a cloud name was set but could not be
// resolved against clouds.yaml. It is deliberately not enforced by
// AugmentFromFiles itself: a cloud name is commonly supplied purely to carry
// env-based auth (e.g. OTC_AK/OTC_SK) with no matching clouds.yaml entry, which
// is a supported way to authenticate. Callers that require an explicit,
// user-selected cloud to actually exist (e.g. the --cloud flag) should call
// this after AugmentFromFiles.
func (base *CommonConfig) RequireCloudFound() error {
	if base.CloudName != "" && base.SelectedCloud == nil {
		return fmt.Errorf("cloud %q was not found in clouds.yaml", base.CloudName)
	}
	return nil
}

func SetIfEmpty(value *string, newValues ...string) {
	if *value == "" {
		for _, v := range newValues {
			if v != "" {
				*value = v
				return
			}
		}
	}
}

func SetIfZero(value *int, newValue int) {
	if *value == 0 {
		*value = newValue
	}
}

func (base *CommonConfig) getEnv(key string) string {
	return os.Getenv(base.EnvPrefix + key)
}
