package cmd

import (
	"os"
	"otc-cli/config"

	"github.com/spf13/cobra"
)

// Version is set at build time via -ldflags
var Version = "dev"

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:     "otc",
	Short:   "CLI tool for Open Telekom Cloud",
	Long:    `otc is a command-line interface (CLI) tool designed to interact with Open Telekom Cloud services.`,
	Version: Version,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return commonConfig.AugmentFromFiles()
	},
}

var commonConfig = &config.CommonConfig{
	EnvPrefix: "OTC_",
}

var format string

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
	rootCmd.PersistentFlags().StringVarP(&commonConfig.CloudName, "cloud", "c", "", "Name of the cloud from clouds.yaml to use")
	rootCmd.PersistentFlags().StringVarP(&commonConfig.Region, "region", "r", "", "Region to use for the cloud")
	rootCmd.PersistentFlags().StringVarP(&commonConfig.ProjectName, "project", "p", "", "Project name to use for authentication")
}

func initFlagFormat(cmd *cobra.Command) {
	cmd.Flags().StringVar(&format, "format", "table", "Output format: table, json, yaml")
}
