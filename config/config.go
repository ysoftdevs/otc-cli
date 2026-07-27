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
	} else if base.CloudName != "" {
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
