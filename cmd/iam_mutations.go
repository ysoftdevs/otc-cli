package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/ysoftdevs/otc-cli/formats"
	"github.com/ysoftdevs/otc-cli/services/iam"
)

type iamMutationAPI interface {
	PlanMutation(string, []string, json.RawMessage) (iam.MutationPlan, error)
	ApplyMutation(iam.MutationPlan, iam.MutationApplyOptions) (iam.Record, error)
}

var _ iamMutationAPI = (*iam.Service)(nil)

func addIAMMutationCommands(root *cobra.Command, connect iamFactory) {
	for _, spec := range iam.MutationSpecs() {
		group := root
		for _, name := range spec.CommandPath {
			var next *cobra.Command
			for _, child := range group.Commands() {
				if child.Name() == name {
					next = child
					break
				}
			}
			if next == nil {
				next = &cobra.Command{Use: name, Short: "Manage IAM " + name}
				group.AddCommand(next)
			}
			group = next
		}
		group.AddCommand(iamMutationCommand(connect, spec))
	}
}

func iamMutationCommand(connect iamFactory, spec iam.MutationSpec) *cobra.Command {
	var input string
	var apply bool
	var options iam.MutationApplyOptions
	command := &cobra.Command{
		Use: spec.Use, Short: spec.Short + " (preview by default)",
		Long: spec.Short + `.

Without --apply, read current state and print a redacted plan. Requests use the
documented JSON envelope in --file; use --file - to read standard input.
With --apply, --confirm must equal the plan's confirmation path. Existing state
also requires --expected-hash from the reviewed plan and --backup to a new file.
Secret-producing operations require --output to a new private file.

Backups and responses use mode 0600 and never overwrite a file. A backup is
evidence of the original state, not a complete rollback of credentials or related
objects. OTC has no atomic compare-and-swap here: another administrator can
change the resource between the state check and the write. Failed or uncertain
writes are never retried automatically; inspect the resource before retrying.
` + spec.Risk,
		Args: cobra.ExactArgs(len(strings.Fields(spec.Use)) - 1),
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, arg := range args {
				if err := iam.ValidateID("resource ID", arg); err != nil {
					return err
				}
			}
			if !apply && (options.ExpectedHash != "" || options.BackupPath != "" || options.OutputPath != "" || options.Confirm != "") {
				return fmt.Errorf("--expected-hash, --backup, --output and --confirm require --apply")
			}
			if apply {
				if options.Confirm == "" {
					return fmt.Errorf("review the preview first, then supply --confirm with its confirmation path")
				}
				if !spec.Create && (options.ExpectedHash == "" || options.BackupPath == "") {
					return fmt.Errorf("existing state requires --expected-hash from a reviewed preview and --backup")
				}
				if spec.SensitiveResponse && options.OutputPath == "" {
					return fmt.Errorf("this operation returns credentials; --output is required for a private file")
				}
			}
			body, err := readIAMMutationInput(cmd, input, spec.BodyKey != "")
			if err != nil {
				return err
			}
			if err := iam.ValidateMutationInput(spec.Name, args, body); err != nil {
				return err
			}
			api, err := connect()
			if err != nil {
				return err
			}
			management, ok := api.(iamMutationAPI)
			if !ok {
				return fmt.Errorf("IAM client does not support management operations")
			}
			plan, err := management.PlanMutation(spec.Name, args, body)
			if err != nil {
				return err
			}
			var result iam.Record
			if apply {
				result, err = management.ApplyMutation(plan, options)
			} else {
				// Only exported, redacted fields are printable; raw request and
				// snapshot data remain private to the IAM service.
				var encoded []byte
				encoded, err = json.Marshal(plan)
				if err == nil {
					decoder := json.NewDecoder(bytes.NewReader(encoded))
					decoder.UseNumber()
					err = decoder.Decode(&result)
				}
			}
			if err != nil {
				return err
			}
			return printIAMRecords([]iam.Record{result}, formats.View[iam.Record]{}, true)
		},
	}
	command.Flags().StringVar(&input, "file", "", "Request JSON file, or - for stdin (required for operations with a body)")
	command.Flags().BoolVar(&apply, "apply", false, "Apply the reviewed change; default only reads and previews")
	command.Flags().StringVar(&options.ExpectedHash, "expected-hash", "", "Hash of state and request from the previously reviewed preview")
	command.Flags().StringVar(&options.BackupPath, "backup", "", "New private file for current state before modification")
	command.Flags().StringVar(&options.OutputPath, "output", "", "New private file for the raw API response (required for secrets)")
	command.Flags().StringVar(&options.Confirm, "confirm", "", "Exact confirmation path from the reviewed preview")
	return command
}

func readIAMMutationInput(command *cobra.Command, path string, required bool) (json.RawMessage, error) {
	if !required {
		if path != "" {
			return nil, fmt.Errorf("this operation does not accept --file")
		}
		return nil, nil
	}
	if path == "" {
		return nil, fmt.Errorf("--file is required; use - to read request JSON from stdin")
	}
	reader := command.InOrStdin()
	if path != "-" {
		file, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("open IAM request file: %w", err)
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() {
			return nil, fmt.Errorf("IAM request file must be a regular file")
		}
		reader = file
	}
	data, err := io.ReadAll(io.LimitReader(reader, (2<<20)+1))
	if err != nil {
		return nil, fmt.Errorf("could not read IAM request JSON")
	}
	if len(data) == 0 || len(data) > 2<<20 {
		return nil, fmt.Errorf("request JSON must be non-empty and at most 2 MiB")
	}
	return data, nil
}
