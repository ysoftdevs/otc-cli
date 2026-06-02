package cmd

import (
	"github.com/ysoftdevs/otc-cli/formats"
	"github.com/ysoftdevs/otc-cli/services/sfs"

	"github.com/spf13/cobra"
)

var sfsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List SFS Turbo shares",
	RunE: func(cmd *cobra.Command, args []string) error {
		shares, err := sfs.List(sfsListArgs)
		if err != nil {
			return err
		}
		return formats.PrintFormatted(format, shares, sfsTableView())
	},
}

var sfsListArgs = sfs.ListArgs{
	CommonConfig: commonConfig,
}

func init() {
	sfsCmd.AddCommand(sfsListCmd)
	sfsListCmd.Flags().StringVar(&sfsListArgs.Filter, "filter", "", "Filter shares by name (substring match)")
	initFlagFormat(sfsListCmd)
}

func sfsTableView() formats.View[sfs.ShareInfo] {
	return formats.View[sfs.ShareInfo]{
		Columns: []formats.Column[sfs.ShareInfo]{
			formats.Col("ID", func(s sfs.ShareInfo) string {
				return s.ID
			}),
			formats.Col("Name", func(s sfs.ShareInfo) string {
				return s.Name
			}),
			formats.Col("Status", func(s sfs.ShareInfo) string {
				return s.Status
			}),
			formats.Col("Export IP", func(s sfs.ShareInfo) string {
				return sfs.ExportIP(s.ExportLocation)
			}),
			formats.Col("Export Path", func(s sfs.ShareInfo) string {
				return s.ExportLocation
			}),
		},
	}
}
