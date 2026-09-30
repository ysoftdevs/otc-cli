package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/ysoftdevs/otc-cli/formats"
	"github.com/ysoftdevs/otc-cli/services/iam"
)

type iamSecurityAPI interface {
	ListCredentials(userID string) ([]iam.Record, error)
	GetCredential(accessKey string) (iam.Record, error)
	ListMFADevices() ([]iam.Record, error)
	GetMFADevice(userID string) (iam.Record, error)
	ListLoginProtections() ([]iam.Record, error)
	GetLoginProtection(userID string) (iam.Record, error)
	GetSecurityPolicy(domainID, policy string) (iam.Record, error)
}

var _ iamSecurityAPI = (*iam.Service)(nil)

func addIAMSecurityCommands(root *cobra.Command, connect iamFactory) {
	credentials := &cobra.Command{Use: "credentials", Short: "Inspect permanent access-key metadata"}
	var userID string
	credentialList := iamSecurityRead(connect, "list", "List your permanent access keys, or another user's with --user-id", iamCredentialsView(), false,
		func(api iamSecurityAPI, _ []string) ([]iam.Record, error) { return api.ListCredentials(userID) }, 0)
	credentialList.Long = `List permanent access-key metadata. Omit --user-id to list your own keys.
Use "credentials show ACCESS_KEY" to query a key's last-use time.`
	credentialList.Flags().StringVar(&userID, "user-id", "", "IAM user ID whose permanent access keys to inspect")
	credentialList.PreRunE = func(cmd *cobra.Command, _ []string) error {
		if cmd.Flags().Changed("user-id") {
			return iam.ValidateID("user ID", userID)
		}
		return nil
	}
	credentials.AddCommand(credentialList)
	credentials.AddCommand(iamSecurityRead(connect, "show ACCESS_KEY", "Show key metadata including creation and last-use time", formats.View[iam.Record]{}, true,
		func(api iamSecurityAPI, args []string) ([]iam.Record, error) {
			return iamSingle(api.GetCredential(args[0]))
		}, 1))

	mfa := &cobra.Command{Use: "mfa", Short: "Inspect virtual MFA device assignments"}
	mfa.AddCommand(iamSecurityRead(connect, "list", "List virtual MFA devices and their users", iamMFAView(), false,
		func(api iamSecurityAPI, _ []string) ([]iam.Record, error) { return api.ListMFADevices() }, 0))
	mfa.AddCommand(iamSecurityRead(connect, "show USER_ID", "Show a user's virtual MFA device assignment", formats.View[iam.Record]{}, true,
		func(api iamSecurityAPI, args []string) ([]iam.Record, error) {
			return iamSingle(api.GetMFADevice(args[0]))
		}, 1))

	protection := &cobra.Command{Use: "login-protection", Short: "Inspect users' login verification settings"}
	protectionList := iamSecurityRead(connect, "list", "List users whose login protection has been configured", iamLoginProtectionView(), false,
		func(api iamSecurityAPI, _ []string) ([]iam.Record, error) { return api.ListLoginProtections() }, 0)
	protectionList.Long = `List only users whose login protection has been configured.
Users absent from this list have no returned configuration; absence does not
represent an explicit disabled setting.`
	protection.AddCommand(protectionList)
	protectionShow := iamSecurityRead(connect, "show USER_ID", "Show a user's login protection configuration", formats.View[iam.Record]{}, true,
		func(api iamSecurityAPI, args []string) ([]iam.Record, error) {
			return iamSingle(api.GetLoginProtection(args[0]))
		}, 1)
	protectionShow.Long = `Show a user's login protection configuration.
The API returns a not-found error if login protection was never configured.`
	protection.AddCommand(protectionShow)

	security := &cobra.Command{Use: "security", Short: "Inspect account security policies and access restrictions"}
	for _, policy := range []struct{ name, short string }{
		{"password-policy", "Show the account's password requirements"},
		{"login-policy", "Show the account's login authentication policy"},
		{"protect-policy", "Show the account's operation protection policy"},
		{"api-acl-policy", "Show source IP restrictions for API access"},
		{"console-acl-policy", "Show source IP restrictions for console access"},
	} {
		security.AddCommand(iamSecurityRead(connect, policy.name+" DOMAIN_ID", policy.short, formats.View[iam.Record]{}, true,
			func(api iamSecurityAPI, args []string) ([]iam.Record, error) {
				return iamSingle(api.GetSecurityPolicy(args[0], policy.name))
			}, 1))
	}
	for _, group := range []*cobra.Command{credentials, mfa, protection, security} {
		group.Args = cobra.NoArgs
		group.RunE = func(cmd *cobra.Command, _ []string) error { return cmd.Help() }
		root.AddCommand(group)
	}
}

func iamSecurityRead(connect iamFactory, use, short string, view formats.View[iam.Record], detail bool,
	query func(iamSecurityAPI, []string) ([]iam.Record, error), argCount int) *cobra.Command {
	return iamRead(connect, use, short, view, detail, func(api iamAPI, args []string) ([]iam.Record, error) {
		security, ok := api.(iamSecurityAPI)
		if !ok {
			return nil, fmt.Errorf("IAM client does not support security inspection")
		}
		return query(security, args)
	}, argCount)
}

func iamCredentialsView() formats.View[iam.Record] {
	return formats.View[iam.Record]{Columns: []formats.Column[iam.Record]{
		iamColumn("Access Key", "access"), iamColumn("User ID", "user_id"), iamColumn("Status", "status"),
		iamColumn("Created", "create_time"), iamColumn("Description", "description"),
	}}
}

func iamMFAView() formats.View[iam.Record] {
	return formats.View[iam.Record]{Columns: []formats.Column[iam.Record]{
		iamColumn("User ID", "user_id"), iamColumn("Serial Number", "serial_number"),
	}}
}

func iamLoginProtectionView() formats.View[iam.Record] {
	return formats.View[iam.Record]{Columns: []formats.Column[iam.Record]{
		iamColumn("User ID", "user_id"), iamColumn("Enabled", "enabled"), iamColumn("Verification Method", "verification_method"),
	}}
}
