package cmd

import (
	"github.com/ysoftdevs/otc-cli/formats"
	"github.com/ysoftdevs/otc-cli/services/identity"

	"github.com/spf13/cobra"
)

var whoamiCmd = &cobra.Command{
	Use:   "whoami",
	Short: "Show the OTC domain, project, user and roles for the current credentials",
	RunE: func(cmd *cobra.Command, args []string) error {
		info, err := identity.WhoAmI(commonConfig)
		if err != nil {
			return err
		}
		return formats.PrintFormatted(format, []identity.CallerIdentity{*info}, whoamiTableView())
	},
}

func init() {
	rootCmd.AddCommand(whoamiCmd)
}

func whoamiTableView() formats.View[identity.CallerIdentity] {
	return formats.View[identity.CallerIdentity]{
		Columns: []formats.Column[identity.CallerIdentity]{
			formats.Col("Domain ID", func(i identity.CallerIdentity) string {
				return i.DomainID
			}),
			formats.Col("Domain Name", func(i identity.CallerIdentity) string {
				return i.DomainName
			}),
			formats.Col("Project ID", func(i identity.CallerIdentity) string {
				return i.ProjectID
			}),
			formats.Col("Project Name", func(i identity.CallerIdentity) string {
				return i.ProjectName
			}),
			formats.Col("User ID", func(i identity.CallerIdentity) string {
				return i.UserID
			}),
			formats.Col("User Name", func(i identity.CallerIdentity) string {
				return i.UserName
			}),
			formats.Col("Access Key", func(i identity.CallerIdentity) string {
				return i.AccessKey
			}),
			formats.Col("Roles", func(i identity.CallerIdentity) string {
				return i.Roles
			}),
		},
	}
}
