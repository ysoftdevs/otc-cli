package config

type CommonConfig struct {
	EnvPrefix   string
	CloudName   string
	Region      string
	ProjectName string

	clouds        *CloudsYAML
	selectedCloud *CloudConfig
}

func (base *CommonConfig) AugmentFromFiles() error {
	clouds, err := LoadCloudsYAMLFromDefaultLocation()
	if err != nil {
		return err
	}

	setIfEmpty(&base.CloudName, clouds.SelectedCloud)
	base.clouds = &clouds

	if cloud, ok := clouds.Clouds[base.CloudName]; ok {
		base.selectedCloud = &cloud
		setIfEmpty(&base.Region, cloud.RegionName)
		setIfEmpty(&base.ProjectName, cloud.Auth.ProjectName)
	}

	return nil
}

func setIfEmpty(value *string, newValue string) {
	if *value == "" {
		*value = newValue
	}
}
