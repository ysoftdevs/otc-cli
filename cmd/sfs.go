package cmd

import (
	"github.com/spf13/cobra"
)

var sfsCmd = &cobra.Command{
	Use:   "sfs",
	Short: "Shared File System (SFS) management",
}

func init() {
	rootCmd.AddCommand(sfsCmd)
}
