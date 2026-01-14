package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v2"
)

// CloudsYAML represents the root structure of clouds.yaml
type CloudsYAML struct {
	Clouds map[string]CloudConfig `yaml:"clouds"`
	Extra  map[string]interface{} `yaml:",inline"`
}

// CloudConfig represents a single cloud configuration
type CloudConfig struct {
	Auth        AuthConfig             `yaml:"auth"`
	RegionName  string                 `yaml:"region_name,omitempty"`
	Cloud       string                 `yaml:"cloud,omitempty"`
	Interface   string                 `yaml:"interface,omitempty"`
	IdentityAPI string                 `yaml:"identity_api_version,omitempty"`
	AuthType    string                 `yaml:"auth_type,omitempty"`
	Extra       map[string]interface{} `yaml:",inline"`
}

// AuthConfig represents authentication configuration
type AuthConfig struct {
	AuthURL                     string                 `yaml:"auth_url,omitempty"`
	ProjectName                 string                 `yaml:"project_name,omitempty"`
	ProjectID                   string                 `yaml:"project_id,omitempty"`
	ProjectDomainName           string                 `yaml:"project_domain_name,omitempty"`
	ProjectDomainID             string                 `yaml:"project_domain_id,omitempty"`
	Username                    string                 `yaml:"username,omitempty"`
	Password                    string                 `yaml:"password,omitempty"`
	UserDomainName              string                 `yaml:"user_domain_name,omitempty"`
	UserDomainID                string                 `yaml:"user_domain_id,omitempty"`
	DomainName                  string                 `yaml:"domain_name,omitempty"`
	DomainID                    string                 `yaml:"domain_id,omitempty"`
	Token                       string                 `yaml:"token,omitempty"`
	ApplicationCredentialID     string                 `yaml:"application_credential_id,omitempty"`
	ApplicationCredentialName   string                 `yaml:"application_credential_name,omitempty"`
	ApplicationCredentialSecret string                 `yaml:"application_credential_secret,omitempty"`
	Extra                       map[string]interface{} `yaml:",inline"`
}

// LoadCloudsYAML loads the clouds.yaml file from the specified path
func LoadCloudsYAML(path string) (*CloudsYAML, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Return empty structure if file doesn't exist
			return &CloudsYAML{
				Clouds: make(map[string]CloudConfig),
			}, nil
		}
		return nil, fmt.Errorf("failed to read clouds.yaml: %w", err)
	}

	var clouds CloudsYAML
	if err := yaml.Unmarshal(data, &clouds); err != nil {
		return nil, fmt.Errorf("failed to parse clouds.yaml: %w", err)
	}

	if clouds.Clouds == nil {
		clouds.Clouds = make(map[string]CloudConfig)
	}

	return &clouds, nil
}

// SaveCloudsYAML saves the clouds.yaml file to the specified path
func SaveCloudsYAML(path string, clouds *CloudsYAML) error {
	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	data, err := yaml.Marshal(clouds)
	if err != nil {
		return fmt.Errorf("failed to marshal clouds.yaml: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write clouds.yaml: %w", err)
	}

	return nil
}

// GetCloudsYAMLPath returns the default path to clouds.yaml
func GetCloudsYAMLPath() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}

	return filepath.Join(homeDir, ".config", "openstack", "clouds.yaml"), nil
}
