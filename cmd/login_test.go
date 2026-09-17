package cmd

import (
	"io"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestLoginRejectsTrailingCommandBeforeStartingAuthentication(t *testing.T) {
	root := &cobra.Command{Use: "otc", SilenceUsage: true, SilenceErrors: true}
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.PersistentFlags().String("cloud", "", "test cloud")
	authenticationStarted := false
	command := &cobra.Command{
		Use:  loginCmd.Use,
		Args: loginCmd.Args,
		PreRunE: func(*cobra.Command, []string) error {
			authenticationStarted = true
			return nil
		},
		Run: func(*cobra.Command, []string) { authenticationStarted = true },
	}
	command.Flags().String("browser", "default", "test browser")
	root.AddCommand(command)
	root.SetArgs([]string{"login", "--cloud", "otc-dev-eu-de", "--browser", "default", "cce", "list"})
	err := root.Execute()
	if err == nil || !strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("expected a usage error for the trailing service command, got %v", err)
	}
	if authenticationStarted {
		t.Fatal("invalid command started authentication")
	}
	if err := loginCmd.ValidateArgs(nil); err != nil {
		t.Fatalf("login without positional arguments should be valid: %v", err)
	}
}
