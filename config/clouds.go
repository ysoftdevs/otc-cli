package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v2"
)

// CloudsYAML represents the root structure of clouds.yaml
type CloudsYAML struct {
	SelectedCloud string                 `yaml:"selected_cloud,omitempty"`
	Clouds        map[string]CloudConfig `yaml:"clouds"`
	Extra         map[string]interface{} `yaml:",inline"`
}

// CloudConfig represents a single cloud configuration
type CloudConfig struct {
	Auth        AuthConfig             `yaml:"auth"`
	SSO         SSOConfig              `yaml:"sso,omitempty"`
	OIDC        OIDCConfig             `yaml:"oidc,omitempty"`
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
	AccessKey                   string                 `yaml:"ak,omitempty"`
	SecretKey                   string                 `yaml:"sk,omitempty"`
	SecurityToken               string                 `yaml:"security_token,omitempty"`
	ApplicationCredentialID     string                 `yaml:"application_credential_id,omitempty"`
	ApplicationCredentialName   string                 `yaml:"application_credential_name,omitempty"`
	ApplicationCredentialSecret string                 `yaml:"application_credential_secret,omitempty"`
	Extra                       map[string]interface{} `yaml:",inline"`
}

type SSOConfig struct {
	BaseURL    string                 `yaml:"base_url,omitempty"`
	Idp        string                 `yaml:"idp,omitempty"`
	Protocol   string                 `yaml:"protocol,omitempty"`
	Expiration int                    `yaml:"expiration,omitempty"`
	Extra      map[string]interface{} `yaml:",inline"`
}

type OIDCConfig struct {
	TenantID string                 `yaml:"tenant_id,omitempty"`
	ClientID string                 `yaml:"client_id,omitempty"`
	Idp      string                 `yaml:"idp,omitempty"`
	Scopes   []string               `yaml:"scopes,omitempty"`
	Extra    map[string]interface{} `yaml:",inline"`
}

func LoadCloudsYAMLFromDefaultLocation() (CloudsYAML, error) {
	cloudsPath, err := GetCloudsYAMLPath()
	if err != nil {
		return CloudsYAML{}, err
	}
	return LoadCloudsYAML(cloudsPath)
}

// LoadCloudsYAML loads the clouds.yaml file from the specified path
func LoadCloudsYAML(path string) (CloudsYAML, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Return empty structure if file doesn't exist
			return CloudsYAML{
				Clouds: make(map[string]CloudConfig),
			}, nil
		}
		return CloudsYAML{}, fmt.Errorf("failed to read clouds.yaml: %w", err)
	}

	var clouds CloudsYAML
	if err := yaml.Unmarshal(data, &clouds); err != nil {
		return CloudsYAML{}, fmt.Errorf("failed to parse clouds.yaml: %w", err)
	}

	if clouds.Clouds == nil {
		clouds.Clouds = make(map[string]CloudConfig)
	}

	return clouds, nil
}

func SaveCloudsYAMLToDefaultLocation(clouds *CloudsYAML) error {
	cloudsPath, err := GetCloudsYAMLPath()
	if err != nil {
		return err
	}
	return SaveCloudsYAML(cloudsPath, clouds)
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

	return writeFileAtomically(resolveSymlink(path), data, 0600, os.Rename)
}

// resolveSymlink follows path when it points somewhere else, so that the atomic
// rename replaces the link target rather than the link itself. A file that does
// not exist yet keeps the original path.
func resolveSymlink(path string) string {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return path
	}
	return resolved
}

func writeFileAtomically(path string, data []byte, perm os.FileMode, renameFile func(string, string) error) error {
	dir := filepath.Dir(path)
	tempFile, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("failed to create temporary file for %s: %w", path, err)
	}

	tempPath := tempFile.Name()
	closed := false
	defer func() {
		if !closed {
			_ = tempFile.Close()
		}
		_ = os.Remove(tempPath)
	}()

	if err := tempFile.Chmod(perm); err != nil {
		return fmt.Errorf("failed to set permissions on %s: %w", tempPath, err)
	}
	if _, err := tempFile.Write(data); err != nil {
		return fmt.Errorf("failed to write %s: %w", tempPath, err)
	}
	if err := tempFile.Sync(); err != nil {
		return fmt.Errorf("failed to sync %s: %w", tempPath, err)
	}
	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("failed to close %s: %w", tempPath, err)
	}
	closed = true

	if err := renameFile(tempPath, path); err != nil {
		return fmt.Errorf("failed to replace %s: %w", path, err)
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

func LoadCloudConfig(cloudName string) (CloudConfig, error) {
	clouds, err := LoadCloudsYAMLFromDefaultLocation()
	if err != nil {
		return CloudConfig{}, err
	}

	cloud, exists := clouds.Clouds[cloudName]
	if !exists {
		return CloudConfig{}, nil
	}
	return cloud, nil
}

func SaveCloudConfig(cloudName string, cloud CloudConfig) error {
	clouds, err := LoadCloudsYAMLFromDefaultLocation()
	if err != nil {
		return err
	}

	clouds.Clouds[cloudName] = cloud

	return SaveCloudsYAMLToDefaultLocation(&clouds)
}

func UpdateCloudConfig(cloudName string, updateFunc func(*CloudConfig)) error {
	clouds, err := LoadCloudsYAMLFromDefaultLocation()
	if err != nil {
		return err
	}

	cloud, exists := clouds.Clouds[cloudName]
	if !exists {
		cloud = CloudConfig{}
	}

	updateFunc(&cloud)
	clouds.Clouds[cloudName] = cloud

	return SaveCloudsYAMLToDefaultLocation(&clouds)
}
