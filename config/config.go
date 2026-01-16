package config

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

	SetIfEmpty(&base.CloudName, clouds.SelectedCloud)
	base.Clouds = &clouds

	if cloud, ok := clouds.Clouds[base.CloudName]; ok {
		base.SelectedCloud = &cloud
		SetIfEmpty(&base.Region, cloud.RegionName)
		SetIfEmpty(&base.ProjectName, cloud.Auth.ProjectName)
	}

	return nil
}

func SetIfEmpty(value *string, newValue string) {
	if *value == "" {
		*value = newValue
	}
}

func SetIfZero(value *int, newValue int) {
	if *value == 0 {
		*value = newValue
	}
}
