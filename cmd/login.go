/*
Copyright © 2026 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// loginCmd represents the login command
var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate user and store credentials",
	Long: ``,
	Run: func(cmd *cobra.Command, args []string) {
		commonConfig, err := ParseGlobalFlags()
		
		if err != nil {
			fmt.Printf("Error parsing global flags: %s\n", err)
			return
		}
		if err := runLogin(commonConfig, args); err != nil {
			fmt.Printf("Error during login: %s\n", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(loginCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// loginCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// loginCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
