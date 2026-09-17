package cmd

import (
	"github.com/spf13/cobra"
	"github.com/ysoftdevs/otc-cli/formats"
	"github.com/ysoftdevs/otc-cli/services/iam"
)

// Keep command parsing independent of authentication so help and invalid input
// never need credentials or a network connection.
type iamAPI interface {
	ListUsers(domainID, name string) ([]iam.Record, error)
	GetUser(id string) (iam.Record, error)
	ListUserGroups(id string) ([]iam.Record, error)
	ListGroups(domainID, name string) ([]iam.Record, error)
	GetGroup(id string) (iam.Record, error)
	ListGroupUsers(id string) ([]iam.Record, error)
	ListGroupRoles(id string, scope iam.Scope) ([]iam.Record, error)
	ListRoles(domainID, name string) ([]iam.Record, error)
	GetRole(id string) (iam.Record, error)
	ListProviders() ([]iam.Record, error)
	GetProvider(id string) (iam.Record, error)
	ListProtocols(providerID string) ([]iam.Record, error)
	GetProtocol(providerID, protocolID string) (iam.Record, error)
	ListMappings() ([]iam.Record, error)
	GetMapping(id string) (iam.Record, error)
}

type iamFactory func() (iamAPI, error)
type iamQuery func(iamAPI, []string) ([]iam.Record, error)

func init() {
	rootCmd.AddCommand(newIAMCommand(func() (iamAPI, error) {
		return iam.New(commonConfig)
	}))
}

func newIAMCommand(connect iamFactory) *cobra.Command {
	command := &cobra.Command{
		Use:   "iam",
		Short: "Inspect and manage IAM users, permissions and federation",
		Long: `Inspect IAM configuration using the selected cloud's existing credentials.

Follow users -> groups -> assigned roles -> policy, or identity providers ->
protocols -> mappings. Management commands preview changes by default; --apply
requires explicit confirmation and, for existing state, a reviewed state hash
and private backup. The caller needs the relevant IAM permissions; cloud service
access alone may not grant them.

Group membership lists cover persistent IAM users. They do not enumerate all
federated users or calculate effective permissions. Use --format json or yaml
to inspect complete policy documents and federation rules.`,
	}

	users := &cobra.Command{Use: "users", Short: "Inspect IAM users and their group memberships"}
	users.AddCommand(iamFilteredList(connect, "List IAM users", iamUsersView(),
		func(api iamAPI, domainID, name string) ([]iam.Record, error) { return api.ListUsers(domainID, name) }))
	users.AddCommand(iamShow(connect, "show USER_ID", "Show an IAM user", func(api iamAPI, args []string) (iam.Record, error) {
		return api.GetUser(args[0])
	}))
	users.AddCommand(iamRead(connect, "groups USER_ID", "List groups containing this IAM user", iamGroupsView(), false,
		func(api iamAPI, args []string) ([]iam.Record, error) { return api.ListUserGroups(args[0]) }, 1))

	groups := &cobra.Command{Use: "groups", Short: "Inspect groups, members and scoped role assignments"}
	groups.AddCommand(iamFilteredList(connect, "List IAM groups", iamGroupsView(),
		func(api iamAPI, domainID, name string) ([]iam.Record, error) { return api.ListGroups(domainID, name) }))
	groups.AddCommand(iamShow(connect, "show GROUP_ID", "Show an IAM group", func(api iamAPI, args []string) (iam.Record, error) {
		return api.GetGroup(args[0])
	}))
	groups.AddCommand(iamRead(connect, "users GROUP_ID", "List persistent IAM users in a group", iamUsersView(), false,
		func(api iamAPI, args []string) ([]iam.Record, error) { return api.ListGroupUsers(args[0]) }, 1))
	groups.AddCommand(iamGroupRoles(connect))

	roles := &cobra.Command{Use: "roles", Short: "Inspect system roles and custom policies"}
	roleList := iamFilteredList(connect, "List system roles, or account custom policies with --domain-id", iamRolesView(),
		func(api iamAPI, domainID, name string) ([]iam.Record, error) { return api.ListRoles(domainID, name) })
	roleList.Long = `Without --domain-id, list system-defined roles and policies.
With --domain-id, list only that account's custom policies.
--name filters the API name, which can differ from display_name.
Use "roles show ROLE_ID" to inspect a full policy document.`
	roles.AddCommand(roleList)
	roles.AddCommand(iamShow(connect, "show ROLE_ID", "Show a role or custom policy, including its complete document",
		func(api iamAPI, args []string) (iam.Record, error) { return api.GetRole(args[0]) }))

	providers := &cobra.Command{Use: "providers", Short: "Inspect federation identity providers and protocol bindings"}
	providers.AddCommand(iamRead(connect, "list", "List federation identity providers", iamProvidersView(), false,
		func(api iamAPI, _ []string) ([]iam.Record, error) { return api.ListProviders() }, 0))
	providers.AddCommand(iamShow(connect, "show PROVIDER_ID", "Show an identity provider (ID can be a name)",
		func(api iamAPI, args []string) (iam.Record, error) { return api.GetProvider(args[0]) }))
	providers.AddCommand(iamRead(connect, "protocols PROVIDER_ID", "List a provider's protocols and their mapping IDs", iamProtocolsView(), false,
		func(api iamAPI, args []string) ([]iam.Record, error) { return api.ListProtocols(args[0]) }, 1))

	protocols := &cobra.Command{Use: "protocols", Short: "Inspect a federation protocol's mapping binding"}
	protocols.AddCommand(iamRead(connect, "show PROVIDER_ID PROTOCOL_ID", "Show the mapping bound to a provider protocol", formats.View[iam.Record]{}, true,
		func(api iamAPI, args []string) ([]iam.Record, error) {
			return iamSingle(api.GetProtocol(args[0], args[1]))
		}, 2))

	mappings := &cobra.Command{Use: "mappings", Short: "Inspect federation claim-to-user/group mapping rules"}
	mappings.AddCommand(iamRead(connect, "list", "List federation mappings", iamMappingsView(), false,
		func(api iamAPI, _ []string) ([]iam.Record, error) { return api.ListMappings() }, 0))
	mappings.AddCommand(iamShow(connect, "show MAPPING_ID", "Show all rules in a federation mapping",
		func(api iamAPI, args []string) (iam.Record, error) { return api.GetMapping(args[0]) }))

	command.AddCommand(users, groups, roles, providers, protocols, mappings)
	addIAMInventoryCommands(command, connect)
	addIAMSecurityCommands(command, connect)
	addIAMFederationCommands(command, connect)
	addIAMMutationCommands(command, connect)
	validateIAMCommandGroups(command)
	return command
}

// Cobra otherwise accepts an unknown word below a non-runnable command group
// by printing help and exiting successfully. Typos must fail before login.
func validateIAMCommandGroups(command *cobra.Command) {
	if command.HasSubCommands() && !command.Runnable() {
		command.Args = cobra.NoArgs
		command.RunE = func(cmd *cobra.Command, _ []string) error { return cmd.Help() }
	}
	for _, child := range command.Commands() {
		validateIAMCommandGroups(child)
	}
}

func iamRead(connect iamFactory, use, short string, view formats.View[iam.Record], detail bool, query iamQuery, argCount int) *cobra.Command {
	return &cobra.Command{
		Use: use, Short: short,
		Args: func(cmd *cobra.Command, args []string) error {
			if err := cobra.ExactArgs(argCount)(cmd, args); err != nil {
				return err
			}
			for _, id := range args {
				if err := iam.ValidateID("resource ID", id); err != nil {
					return err
				}
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			api, err := connect()
			if err != nil {
				return err
			}
			rows, err := query(api, args)
			if err != nil {
				return err
			}
			return printIAMRecords(rows, view, detail)
		},
	}
}

func iamShow(connect iamFactory, use, short string, query func(iamAPI, []string) (iam.Record, error)) *cobra.Command {
	return iamRead(connect, use, short, formats.View[iam.Record]{}, true,
		func(api iamAPI, args []string) ([]iam.Record, error) { return iamSingle(query(api, args)) }, 1)
}

func iamSingle(record iam.Record, err error) ([]iam.Record, error) {
	if err != nil {
		return nil, err
	}
	return []iam.Record{record}, nil
}

func iamFilteredList(connect iamFactory, short string, view formats.View[iam.Record], query func(iamAPI, string, string) ([]iam.Record, error)) *cobra.Command {
	var domainID, name string
	command := iamRead(connect, "list", short, view, false, func(api iamAPI, _ []string) ([]iam.Record, error) {
		return query(api, domainID, name)
	}, 0)
	command.Flags().StringVar(&domainID, "domain-id", "", "Account/domain ID to filter by")
	command.Flags().StringVar(&name, "name", "", "Exact API name to filter by")
	command.PreRunE = func(cmd *cobra.Command, _ []string) error {
		if cmd.Flags().Changed("domain-id") {
			return iam.ValidateID("domain ID", domainID)
		}
		return nil
	}
	return command
}

func iamGroupRoles(connect iamFactory) *cobra.Command {
	var scope iam.Scope
	command := iamRead(connect, "roles GROUP_ID", "List a group's roles in one explicit scope", iamRolesView(), false,
		func(api iamAPI, args []string) ([]iam.Record, error) { return api.ListGroupRoles(args[0], scope) }, 1)
	command.Long = `List role assignments for exactly one scope:
  --domain-id ID                 Direct account/domain assignments
  --project-id ID                Direct assignments in one project
  --domain-id ID --all-projects  Assignments inherited by all projects

These are separate assignment lists, not an effective-permissions calculation.
--project-id selects an IAM scope; global --project selects the authentication
project by name.`
	command.Flags().StringVar(&scope.DomainID, "domain-id", "", "Domain ID for direct or all-project assignments")
	command.Flags().StringVar(&scope.ProjectID, "project-id", "", "Project ID for direct project assignments")
	command.Flags().BoolVar(&scope.AllProjects, "all-projects", false, "List inherited all-project assignments (requires --domain-id)")
	command.PreRunE = func(_ *cobra.Command, _ []string) error { return scope.Validate() }
	return command
}
