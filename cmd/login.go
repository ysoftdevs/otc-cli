package cmd

import (
	"fmt"
	"otc-cli/config"
	"otc-cli/services/browser/login"

	"github.com/spf13/cobra"
)

// loginCmd represents the login command
var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate user and store credentials",
	PreRunE: func(cmd *cobra.Command, args []string) error {
		commonConfig, err := ParseGlobalFlags()
		if err != nil {
			return fmt.Errorf("error parsing global flags: %w", err)
		}
		loginArgs.CommonConfig = commonConfig
		if cloud := commonConfig.SelectedCloud; cloud != nil {
			config.SetIfEmpty(&loginArgs.AuthURL, cloud.Auth.AuthURL)
			config.SetIfEmpty(&loginArgs.DomainID, cloud.Auth.DomainID)

			config.SetIfEmpty(&loginArgs.Protocol, cloud.SSO.Protocol)
			config.SetIfEmpty(&loginArgs.Idp, cloud.SSO.Idp)
			config.SetIfEmpty(&loginArgs.BaseURL, cloud.SSO.BaseURL)
			config.SetIfZero(&loginArgs.Expiration, cloud.SSO.Expiration)

		}

		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := login.BrowserLogin(loginArgs); err != nil {
			return fmt.Errorf("error during login: %w", err)
		}
		return nil
	},
}

var loginArgs = login.LoginArgs{
	BaseURL:    "https://auth.otc.t-systems.com/authui/federation/websso",
	AuthURL:    "https://iam.eu-de.otc.t-systems.com/v3",
	Protocol:   "saml",
	Expiration: 3600,
}

func init() {
	rootCmd.AddCommand(loginCmd)

	loginCmd.Flags().StringVar(&loginArgs.BaseURL, "url", loginArgs.BaseURL, "Base URL for SSO authentication")
	loginCmd.Flags().StringVar(&loginArgs.AuthURL, "auth-url", loginArgs.AuthURL, "Authentication URL")
	loginCmd.Flags().StringVar(&loginArgs.DomainID, "domain-id", loginArgs.DomainID, "Domain ID")
	loginCmd.Flags().StringVar(&loginArgs.Idp, "idp", loginArgs.Idp, "Identity provider")
	loginCmd.Flags().StringVar(&loginArgs.Protocol, "protocol", loginArgs.Protocol, "Authentication protocol")
	loginCmd.Flags().IntVar(&loginArgs.Expiration, "expiration", loginArgs.Expiration, "Credential expiration time in seconds")
}
