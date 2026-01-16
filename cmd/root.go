package cmd

import (
	"os"
	"otc-cli/config"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "otc",
	Short: "CLI tool for Open Telekom Cloud",
	Long:  `otc is a command-line interface (CLI) tool designed to interact with Open Telekom Cloud services.`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// global flags for all commands
	rootCmd.PersistentFlags().StringP("cloud", "c", "", "Name of the cloud from clouds.yaml to use")
	rootCmd.PersistentFlags().StringP("region", "r", "", "Region to use for the cloud")
	rootCmd.PersistentFlags().StringP("project", "p", "", "Project name to use for authentication")
}

func ParseGlobalFlags() (*config.CommonConfig, error) {
	cloudName, err := rootCmd.PersistentFlags().GetString("cloud")
	if err != nil {
		return nil, err
	}
	region, err := rootCmd.PersistentFlags().GetString("region")
	if err != nil {
		return nil, err
	}
	projectName, err := rootCmd.PersistentFlags().GetString("project")
	if err != nil {
		return nil, err
	}
	config := config.CommonConfig{
		EnvPrefix:   "OTC_",
		CloudName:   cloudName,
		Region:      region,
		ProjectName: projectName,
	}

	if err := config.AugmentFromFiles(); err != nil {
		return nil, err
	}

	return &config, nil
}
