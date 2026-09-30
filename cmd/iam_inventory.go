package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/ysoftdevs/otc-cli/formats"
	"github.com/ysoftdevs/otc-cli/services/iam"
)

type iamInventoryAPI interface {
	ListRegions() ([]iam.Record, error)
	GetRegion(string) (iam.Record, error)
	ListProjects(iam.ProjectListOptions) ([]iam.Record, error)
	GetProject(string) (iam.Record, error)
	GetProjectStatus(string) (iam.Record, error)
	ListAccessibleProjects() ([]iam.Record, error)
	ListUserProjects(string) ([]iam.Record, error)
	ListAccessibleDomains() ([]iam.Record, error)
	ListServices(string) ([]iam.Record, error)
	GetService(string) (iam.Record, error)
	ListEndpoints(string, string) ([]iam.Record, error)
	GetEndpoint(string) (iam.Record, error)
	ListCatalog() ([]iam.Record, error)
	ListAgencies(iam.AgencyListOptions) ([]iam.Record, error)
	GetAgency(string) (iam.Record, error)
	ListAgencyRoles(string, iam.Scope) ([]iam.Record, error)
	ListAssignments(iam.AssignmentListOptions) ([]iam.Record, error)
	GetProjectQuotas(string) (iam.Record, error)
	GetDomainQuotas(string, string) (iam.Record, error)
	GetIdentityVersion() (iam.Record, error)
}

var _ iamInventoryAPI = (*iam.Service)(nil)

func addIAMInventoryCommands(root *cobra.Command, connect iamFactory) {
	regions := &cobra.Command{Use: "regions", Short: "Inspect available regions"}
	regions.AddCommand(iamInventoryRead(connect, "list", "List regions visible to the current identity", iamInventoryView("ID", "id", "Description", "description", "Type", "type"), false,
		func(api iamInventoryAPI, _ []string) ([]iam.Record, error) { return api.ListRegions() }, 0))
	regions.AddCommand(iamInventoryShow(connect, "show REGION_ID", "Show region details",
		func(api iamInventoryAPI, args []string) (iam.Record, error) { return api.GetRegion(args[0]) }, 1))

	projects := &cobra.Command{Use: "projects", Short: "Inspect projects and accessible project scopes"}
	projects.AddCommand(iamInventoryProjectList(connect))
	projects.AddCommand(iamInventoryShow(connect, "show PROJECT_ID", "Show project details",
		func(api iamInventoryAPI, args []string) (iam.Record, error) { return api.GetProject(args[0]) }, 1))
	projects.AddCommand(iamInventoryShow(connect, "status PROJECT_ID", "Show project details including suspension status",
		func(api iamInventoryAPI, args []string) (iam.Record, error) { return api.GetProjectStatus(args[0]) }, 1))
	projects.AddCommand(iamInventoryRead(connect, "accessible", "List projects accessible to the current identity", iamProjectsView(), false,
		func(api iamInventoryAPI, _ []string) ([]iam.Record, error) { return api.ListAccessibleProjects() }, 0))
	projects.AddCommand(iamInventoryShow(connect, "quotas PROJECT_ID", "Show the project's IAM quotas",
		func(api iamInventoryAPI, args []string) (iam.Record, error) { return api.GetProjectQuotas(args[0]) }, 1))

	domains := &cobra.Command{Use: "domains", Short: "Inspect accessible accounts and IAM quotas"}
	domains.AddCommand(iamInventoryRead(connect, "accessible", "List domains accessible to the current identity", iamInventoryView("ID", "id", "Name", "name", "Enabled", "enabled"), false,
		func(api iamInventoryAPI, _ []string) ([]iam.Record, error) { return api.ListAccessibleDomains() }, 0))
	var quotaType string
	quotas := iamInventoryShow(connect, "quotas DOMAIN_ID", "Show an account's IAM resource quotas",
		func(api iamInventoryAPI, args []string) (iam.Record, error) {
			return api.GetDomainQuotas(args[0], quotaType)
		}, 1)
	quotas.Flags().StringVar(&quotaType, "type", "", "Quota type: user, group, idp, agency or policy")
	quotas.PreRunE = func(cmd *cobra.Command, _ []string) error {
		return iam.ValidateDomainQuotaType(quotaType)
	}
	domains.AddCommand(quotas)

	services := &cobra.Command{Use: "services", Short: "Inspect IAM service registrations"}
	var serviceType string
	serviceList := iamInventoryRead(connect, "list", "List registered services", iamInventoryView("ID", "id", "Name", "name", "Type", "type", "Enabled", "enabled"), false,
		func(api iamInventoryAPI, _ []string) ([]iam.Record, error) { return api.ListServices(serviceType) }, 0)
	serviceList.Flags().StringVar(&serviceType, "type", "", "Service type to filter by, such as compute or network")
	services.AddCommand(serviceList)
	services.AddCommand(iamInventoryShow(connect, "show SERVICE_ID", "Show service registration details",
		func(api iamInventoryAPI, args []string) (iam.Record, error) { return api.GetService(args[0]) }, 1))

	endpoints := &cobra.Command{Use: "endpoints", Short: "Inspect service endpoint registrations"}
	var serviceID, endpointInterface string
	endpointList := iamInventoryRead(connect, "list", "List registered service endpoints", iamInventoryView("ID", "id", "Service ID", "service_id", "Region", "region", "Interface", "interface", "URL", "url"), false,
		func(api iamInventoryAPI, _ []string) ([]iam.Record, error) {
			return api.ListEndpoints(serviceID, endpointInterface)
		}, 0)
	endpointList.Flags().StringVar(&serviceID, "service-id", "", "Service ID to filter by")
	endpointList.Flags().StringVar(&endpointInterface, "interface", "", "Endpoint interface: public, internal or admin")
	endpointList.PreRunE = func(cmd *cobra.Command, _ []string) error {
		return iamInventoryValidateFlags(cmd, func() error { return iam.ValidateEndpointFilters(serviceID, endpointInterface) })
	}
	endpoints.AddCommand(endpointList)
	endpoints.AddCommand(iamInventoryShow(connect, "show ENDPOINT_ID", "Show endpoint registration details",
		func(api iamInventoryAPI, args []string) (iam.Record, error) { return api.GetEndpoint(args[0]) }, 1))

	catalog := &cobra.Command{Use: "catalog", Short: "Inspect the selected project's service catalog"}
	catalog.AddCommand(iamInventoryRead(connect, "list", "List services from the original project credentials", iamInventoryView("ID", "id", "Name", "name", "Type", "type", "Endpoints", "endpoints"), false,
		func(api iamInventoryAPI, _ []string) ([]iam.Record, error) { return api.ListCatalog() }, 0))

	agencies := &cobra.Command{Use: "agencies", Short: "Inspect delegated agencies and their scoped grants"}
	agencies.AddCommand(iamInventoryAgencyList(connect))
	agencies.AddCommand(iamInventoryShow(connect, "show AGENCY_ID", "Show an agency's trust and lifetime details",
		func(api iamInventoryAPI, args []string) (iam.Record, error) { return api.GetAgency(args[0]) }, 1))
	agencies.AddCommand(iamInventoryAgencyRoles(connect))

	assignments := &cobra.Command{Use: "assignments", Short: "Inspect an account's authorization assignment records"}
	assignments.AddCommand(iamInventoryAssignments(connect))
	versions := &cobra.Command{Use: "versions", Short: "Inspect the identity API version"}
	versions.AddCommand(iamInventoryShow(connect, "show", "Show identity API v3 version information",
		func(api iamInventoryAPI, _ []string) (iam.Record, error) { return api.GetIdentityVersion() }, 0))

	root.AddCommand(regions, projects, domains, services, endpoints, catalog, agencies, assignments, versions)
	for _, child := range root.Commands() {
		if child.Name() == "users" {
			child.AddCommand(iamInventoryRead(connect, "projects USER_ID", "List projects accessible to a persistent IAM user", iamProjectsView(), false,
				func(api iamInventoryAPI, args []string) ([]iam.Record, error) { return api.ListUserProjects(args[0]) }, 1))
			break
		}
	}
}

func iamInventoryProjectList(connect iamFactory) *cobra.Command {
	var opts iam.ProjectListOptions
	var enabled, isDomain bool
	command := iamInventoryRead(connect, "list", "List account projects with optional filters", iamProjectsView(), false,
		func(api iamInventoryAPI, _ []string) ([]iam.Record, error) { return api.ListProjects(opts) }, 0)
	command.Flags().StringVar(&opts.DomainID, "domain-id", "", "Account/domain ID to filter by")
	command.Flags().StringVar(&opts.Name, "name", "", "Exact project name to filter by")
	command.Flags().StringVar(&opts.ParentID, "parent-id", "", "Parent project ID to filter by")
	command.Flags().BoolVar(&enabled, "enabled", false, "Filter by enabled status (use =false for disabled projects)")
	command.Flags().BoolVar(&isDomain, "is-domain", false, "Filter by the API's is_domain property")
	command.PreRunE = func(cmd *cobra.Command, _ []string) error {
		opts.Enabled = iamInventoryBool(cmd, "enabled", enabled)
		opts.IsDomain = iamInventoryBool(cmd, "is-domain", isDomain)
		return iamInventoryValidateFlags(cmd, opts.Validate)
	}
	return command
}

func iamInventoryAgencyList(connect iamFactory) *cobra.Command {
	var opts iam.AgencyListOptions
	command := iamInventoryRead(connect, "list", "List agencies in one account", iamInventoryView("ID", "id", "Name", "name", "Domain ID", "domain_id", "Trust Domain ID", "trust_domain_id", "Expires", "expire_time"), false,
		func(api iamInventoryAPI, _ []string) ([]iam.Record, error) { return api.ListAgencies(opts) }, 0)
	command.Flags().StringVar(&opts.DomainID, "domain-id", "", "Required account/domain ID")
	command.Flags().StringVar(&opts.Name, "name", "", "Agency name to filter by")
	command.Flags().StringVar(&opts.TrustDomainID, "trust-domain-id", "", "Delegated account ID to filter by")
	command.PreRunE = func(cmd *cobra.Command, _ []string) error { return iamInventoryValidateFlags(cmd, opts.Validate) }
	return command
}

func iamInventoryAgencyRoles(connect iamFactory) *cobra.Command {
	var scope iam.Scope
	command := iamInventoryRead(connect, "roles AGENCY_ID", "List an agency's grants in one explicit scope", iamRolesView(), false,
		func(api iamInventoryAPI, args []string) ([]iam.Record, error) {
			return api.ListAgencyRoles(args[0], scope)
		}, 1)
	command.Long = "List direct domain grants, direct project grants, or inherited all-project grants. These are separate assignment lists; this command does not calculate effective permissions."
	command.Flags().StringVar(&scope.DomainID, "domain-id", "", "Domain ID for direct or inherited all-project grants")
	command.Flags().StringVar(&scope.ProjectID, "project-id", "", "Project ID for direct project grants")
	command.Flags().BoolVar(&scope.AllProjects, "all-projects", false, "List inherited grants for all projects (requires --domain-id)")
	command.PreRunE = func(cmd *cobra.Command, _ []string) error { return iamInventoryValidateFlags(cmd, scope.Validate) }
	return command
}

func iamInventoryAssignments(connect iamFactory) *cobra.Command {
	var opts iam.AssignmentListOptions
	var inherited, includeGroup bool
	command := iamInventoryRead(connect, "list", "List authorization records across an account", iamInventoryView("User", "user", "Group", "group", "Agency", "agency", "Role", "role", "Scope", "scope", "Inherited", "is_inherited"), false,
		func(api iamInventoryAPI, _ []string) ([]iam.Record, error) { return api.ListAssignments(opts) }, 0)
	command.Long = `List account authorization records, following every numbered page.
Choose either a subject type or one subject ID; choose either a scope type or
one scope ID. --include-group applies only to user subjects. --is-inherited
applies only to domain scope and selects grants inherited by all projects.
Assignment records describe grants; they do not evaluate policy conditions or
calculate effective access to individual resources.`
	command.Flags().StringVar(&opts.DomainID, "domain-id", "", "Required account/domain ID")
	command.Flags().StringVar(&opts.RoleID, "role-id", "", "Policy/role ID to filter by")
	command.Flags().StringVar(&opts.Subject, "subject", "", "Subject type: user, group or agency")
	command.Flags().StringVar(&opts.UserID, "user-id", "", "IAM user ID to filter by")
	command.Flags().StringVar(&opts.GroupID, "group-id", "", "Group ID to filter by")
	command.Flags().StringVar(&opts.AgencyID, "agency-id", "", "Agency ID to filter by")
	command.Flags().StringVar(&opts.Scope, "scope", "", "Scope type: project, domain or enterprise_project")
	command.Flags().StringVar(&opts.ProjectID, "project-id", "", "Authorization project ID to filter by")
	command.Flags().StringVar(&opts.ScopeDomainID, "scope-domain-id", "", "Authorization domain ID to filter by")
	command.Flags().BoolVar(&inherited, "is-inherited", false, "Filter domain grants by all-project inheritance")
	command.Flags().BoolVar(&includeGroup, "include-group", true, "Include groups' grants when querying a user")
	command.PreRunE = func(cmd *cobra.Command, _ []string) error {
		opts.IsInherited = iamInventoryBool(cmd, "is-inherited", inherited)
		opts.IncludeGroup = iamInventoryBool(cmd, "include-group", includeGroup)
		return iamInventoryValidateFlags(cmd, opts.Validate)
	}
	return command
}

func iamInventoryRead(connect iamFactory, use, short string, view formats.View[iam.Record], detail bool, query func(iamInventoryAPI, []string) ([]iam.Record, error), argCount int) *cobra.Command {
	return iamRead(connect, use, short, view, detail, func(api iamAPI, args []string) ([]iam.Record, error) {
		inventory, ok := api.(iamInventoryAPI)
		if !ok {
			return nil, fmt.Errorf("IAM client does not support inventory queries")
		}
		return query(inventory, args)
	}, argCount)
}

func iamInventoryShow(connect iamFactory, use, short string, query func(iamInventoryAPI, []string) (iam.Record, error), argCount int) *cobra.Command {
	return iamInventoryRead(connect, use, short, formats.View[iam.Record]{}, true,
		func(api iamInventoryAPI, args []string) ([]iam.Record, error) { return iamSingle(query(api, args)) }, argCount)
}

func iamInventoryView(columns ...string) formats.View[iam.Record] {
	view := formats.View[iam.Record]{}
	for i := 0; i < len(columns); i += 2 {
		view.Columns = append(view.Columns, iamColumn(columns[i], columns[i+1]))
	}
	return view
}

func iamProjectsView() formats.View[iam.Record] {
	return iamInventoryView("ID", "id", "Name", "name", "Domain ID", "domain_id", "Parent ID", "parent_id", "Enabled", "enabled")
}

func iamInventoryBool(command *cobra.Command, flag string, value bool) *bool {
	if !command.Flags().Changed(flag) {
		return nil
	}
	return &value
}

func iamInventoryValidateFlags(command *cobra.Command, validate func() error) error {
	var invalid error
	command.Flags().Visit(func(flag *pflag.Flag) {
		if invalid == nil && strings.HasSuffix(flag.Name, "-id") {
			invalid = iam.ValidateID(flag.Name, flag.Value.String())
		}
	})
	if invalid != nil {
		return invalid
	}
	return validate()
}
