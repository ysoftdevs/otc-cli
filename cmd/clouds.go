package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v2"
)

// STSCredentialResponse represents the response from the STS credential endpoint
type STSCredentialResponse struct {
	Data struct {
		Credential STSCredential `json:"credential"`
	} `json:"data"`
	RetInfo string `json:"retinfo"`
}

// STSCredential represents the temporary credentials
type STSCredential struct {
	Access        string `json:"access"`
	Secret        string `json:"secret"`
	ExpiresAt     string `json:"expires_at"`
	SecurityToken string `json:"securitytoken"`
}

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
	Token                       string                 `yaml:"security_token,omitempty"`
	AccessKey                   string                 `yaml:"ak,omitempty"`
	SecretKey                   string                 `yaml:"sk,omitempty"`
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

// UpdateCloudsWithSTSCredentials updates clouds.yaml with STS credentials
func UpdateCloudsWithSTSCredentials(cloudName string, credJSON string) error {
	// Parse the credential response
	var credResp STSCredentialResponse
	if err := json.Unmarshal([]byte(credJSON), &credResp); err != nil {
		return fmt.Errorf("failed to parse credential response: %w", err)
	}

	if credResp.RetInfo != "success" {
		return fmt.Errorf("credential request failed: %s", credResp.RetInfo)
	}

	// Get clouds.yaml path
	cloudsPath, err := GetCloudsYAMLPath()
	if err != nil {
		return err
	}

	// Load existing clouds.yaml
	clouds, err := LoadCloudsYAML(cloudsPath)
	if err != nil {
		return err
	}

	cred := credResp.Data.Credential

	// Create or update the cloud configuration
	clouds.Clouds[cloudName] = CloudConfig{
		Auth: AuthConfig{
			AuthURL:    "https://iam.eu-de.otc.t-systems.com/v3",
			AccessKey:  cred.Access,
			SecretKey:  cred.Secret,
			Token:      cred.SecurityToken,
			DomainName: "OTC-EU-DE-00000000001000000593",
		},
		RegionName:  "eu-de",
		Interface:   "public",
		IdentityAPI: "3",
		AuthType:    "v3token",
	}

	// Save clouds.yaml
	if err := SaveCloudsYAML(cloudsPath, clouds); err != nil {
		return err
	}

	fmt.Printf("Updated cloud configuration '%s' in %s\n", cloudName, cloudsPath)
	fmt.Printf("Credentials expire at: %s\n", cred.ExpiresAt)

	return nil
}
