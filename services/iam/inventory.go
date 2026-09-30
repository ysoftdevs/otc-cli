package iam

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
)

// Endpoints and query semantics follow the OTC IAM API reference:
// https://docs.otc.t-systems.com/identity-access-management/iam-api-ref.pdf
// In particular, assignment records use OS-PERMISSION, not the discarded
// /v3/role_assignments API, and agencies use /v3.0/OS-AGENCY.

// ProjectListOptions filters the project inventory. Empty strings and nil bool
// pointers omit their filters; non-nil bool pointers send true or false explicitly.
type ProjectListOptions struct {
	DomainID string
	Name     string
	ParentID string
	Enabled  *bool
	IsDomain *bool
}

func (o ProjectListOptions) Validate() error {
	return inventoryOptionalIDs(map[string]string{"domain ID": o.DomainID, "parent ID": o.ParentID})
}

func (s *Service) ListRegions() ([]Record, error) {
	return s.listVersion("v3", "regions", nil, "regions")
}

func (s *Service) GetRegion(id string) (Record, error) {
	return s.getVersion("v3", "region", "regions", id)
}

func (s *Service) ListProjects(o ProjectListOptions) ([]Record, error) {
	if err := o.Validate(); err != nil {
		return nil, err
	}
	q := inventoryQuery(map[string]string{"domain_id": o.DomainID, "name": o.Name, "parent_id": o.ParentID})
	inventoryQueryBool(q, "enabled", o.Enabled)
	inventoryQueryBool(q, "is_domain", o.IsDomain)
	return s.listVersion("v3", "projects", q, "projects")
}

func (s *Service) GetProject(id string) (Record, error) {
	return s.getVersion("v3", "project", "projects", id)
}

func (s *Service) GetProjectStatus(id string) (Record, error) {
	return s.getVersion("v3-ext", "project", "projects", id)
}

// The auth/projects and auth/domains APIs are also the documented replacement
// for the federation discovery endpoints, which require an unscoped token.
func (s *Service) ListAccessibleProjects() ([]Record, error) {
	return s.listVersion("v3", "projects", nil, "auth", "projects")
}

func (s *Service) ListUserProjects(userID string) ([]Record, error) {
	return s.listVersion("v3", "projects", nil, "users", userID, "projects")
}

func (s *Service) ListAccessibleDomains() ([]Record, error) {
	return s.listVersion("v3", "domains", nil, "auth", "domains")
}

func (s *Service) ListServices(serviceType string) ([]Record, error) {
	return s.listVersion("v3", "services", inventoryQuery(map[string]string{"type": serviceType}), "services")
}

func (s *Service) GetService(id string) (Record, error) {
	return s.getVersion("v3", "service", "services", id)
}

func ValidateEndpointFilters(serviceID, endpointInterface string) error {
	if err := inventoryOptionalIDs(map[string]string{"service ID": serviceID}); err != nil {
		return err
	}
	return inventoryEnum("interface", endpointInterface, "public", "internal", "admin")
}

func (s *Service) ListEndpoints(serviceID, endpointInterface string) ([]Record, error) {
	if err := ValidateEndpointFilters(serviceID, endpointInterface); err != nil {
		return nil, err
	}
	return s.listVersion("v3", "endpoints", inventoryQuery(map[string]string{
		"service_id": serviceID, "interface": endpointInterface,
	}), "endpoints")
}

func (s *Service) GetEndpoint(id string) (Record, error) {
	return s.getVersion("v3", "endpoint", "endpoints", id)
}

// ListCatalog uses the original project credentials: the catalog describes the
// selected project's services, whereas administration requests use domain scope.
func (s *Service) ListCatalog() ([]Record, error) {
	return s.listProjectCatalog()
}

// AgencyListOptions selects agencies in the required DomainID. Empty Name and
// TrustDomainID values omit those optional filters.
type AgencyListOptions struct {
	DomainID      string
	Name          string
	TrustDomainID string
}

func (o AgencyListOptions) Validate() error {
	if err := ValidateID("domain ID", o.DomainID); err != nil {
		return err
	}
	return inventoryOptionalIDs(map[string]string{"trust domain ID": o.TrustDomainID})
}

func (s *Service) ListAgencies(o AgencyListOptions) ([]Record, error) {
	if err := o.Validate(); err != nil {
		return nil, err
	}
	return s.listVersion("v3.0", "agencies", inventoryQuery(map[string]string{
		"domain_id": o.DomainID, "name": o.Name, "trust_domain_id": o.TrustDomainID,
	}), "OS-AGENCY", "agencies")
}

func (s *Service) GetAgency(id string) (Record, error) {
	return s.getVersion("v3.0", "agency", "OS-AGENCY", "agencies", id)
}

func (s *Service) ListAgencyRoles(id string, scope Scope) ([]Record, error) {
	if err := scope.Validate(); err != nil {
		return nil, err
	}
	if scope.AllProjects {
		return s.listVersion("v3.0", "roles", nil, "OS-INHERIT", "domains", scope.DomainID, "agencies", id, "roles", "inherited_to_projects")
	}
	if scope.DomainID != "" {
		return s.listVersion("v3.0", "roles", nil, "OS-AGENCY", "domains", scope.DomainID, "agencies", id, "roles")
	}
	return s.listVersion("v3.0", "roles", nil, "OS-AGENCY", "projects", scope.ProjectID, "agencies", id, "roles")
}

// AssignmentListOptions filters authorization records in the required DomainID.
// Empty strings omit optional filters. Nil bool pointers omit their filters;
// non-nil bool pointers send true or false explicitly. Validate checks permitted
// combinations of subject, scope, and boolean filters.
type AssignmentListOptions struct {
	DomainID      string
	RoleID        string
	Subject       string
	UserID        string
	GroupID       string
	AgencyID      string
	Scope         string
	ProjectID     string
	ScopeDomainID string
	IsInherited   *bool
	IncludeGroup  *bool
}

func (o AssignmentListOptions) Validate() error {
	if err := ValidateID("domain ID", o.DomainID); err != nil {
		return err
	}
	if err := inventoryOptionalIDs(map[string]string{
		"role ID": o.RoleID, "user ID": o.UserID, "group ID": o.GroupID, "agency ID": o.AgencyID,
		"project ID": o.ProjectID, "scope domain ID": o.ScopeDomainID,
	}); err != nil {
		return err
	}
	if err := inventoryEnum("subject", o.Subject, "user", "group", "agency"); err != nil {
		return err
	}
	if err := inventoryEnum("scope", o.Scope, "project", "domain", "enterprise_project"); err != nil {
		return err
	}
	if inventoryCount(o.Subject, o.UserID, o.GroupID, o.AgencyID) > 1 {
		return fmt.Errorf("use at most one of subject, user ID, group ID or agency ID")
	}
	if inventoryCount(o.Scope, o.ProjectID, o.ScopeDomainID) > 1 {
		return fmt.Errorf("use at most one of scope, project ID or scope domain ID")
	}
	if o.IsInherited != nil && o.Scope != "domain" && o.ScopeDomainID == "" {
		return fmt.Errorf("is-inherited requires --scope domain or --scope-domain-id")
	}
	if o.IncludeGroup != nil && o.Subject != "user" && o.UserID == "" {
		return fmt.Errorf("include-group requires --subject user or --user-id")
	}
	return nil
}

// ListAssignments follows the OS-PERMISSION page/per_page protocol and checks
// total_num. Count changes, malformed or empty pages, and duplicate records fail
// instead of producing an apparently complete authorization inventory. A stable
// count cannot guarantee an atomic snapshot, but known page overlap is rejected.
func (s *Service) ListAssignments(o AssignmentListOptions) ([]Record, error) {
	if err := o.Validate(); err != nil {
		return nil, err
	}
	q := inventoryQuery(map[string]string{
		"domain_id": o.DomainID, "role_id": o.RoleID, "subject": o.Subject,
		"subject.user_id": o.UserID, "subject.group_id": o.GroupID, "subject.agency_id": o.AgencyID,
		"scope": o.Scope, "scope.project_id": o.ProjectID, "scope.domain_id": o.ScopeDomainID,
	})
	// OTC's table spells the enterprise-project ID filter in the plural, while
	// its prose uses the singular. Until verified, expose only the unambiguous
	// scope=enterprise_project filter; a misspelled ID filter could be ignored.
	inventoryQueryBool(q, "is_inherited", o.IsInherited)
	inventoryQueryBool(q, "include_group", o.IncludeGroup)
	q.Set("per_page", "50")
	records := make([]Record, 0)
	total := int64(-1)
	seenRecords := make(map[string]bool)
	for page := 1; page <= 10000; page++ {
		endpoint, err := s.versionEndpoint("v3.0", "OS-PERMISSION", "role-assignments")
		if err != nil {
			return nil, err
		}
		q.Set("page", strconv.Itoa(page))
		endpoint.RawQuery = q.Encode()
		var envelope struct {
			Assignments json.RawMessage `json:"role_assignments"`
			Total       *json.Number    `json:"total_num"`
		}
		if err := s.read(endpoint, &envelope); err != nil {
			return nil, err
		}
		var batch []Record
		if err := decode(envelope.Assignments, &batch); err != nil || batch == nil {
			return nil, fmt.Errorf("IAM assignment response must contain a role_assignments array")
		}
		for _, record := range batch {
			if record == nil {
				return nil, fmt.Errorf("IAM assignment response contains a null record")
			}
		}
		if envelope.Total == nil {
			return nil, fmt.Errorf("IAM assignment response is missing total_num")
		}
		count, err := envelope.Total.Int64()
		if err != nil || count < 0 {
			return nil, fmt.Errorf("IAM assignment response has an invalid total_num")
		}
		if total >= 0 && total != count {
			return nil, fmt.Errorf("IAM assignment count changed during pagination; repeat the query")
		}
		total = count
		for _, record := range batch {
			// Marshal sorts object keys, so different JSON property order cannot
			// disguise the same assignment appearing again during pagination.
			fingerprint, err := json.Marshal(record)
			if err != nil {
				return nil, fmt.Errorf("encode IAM assignment record: %w", err)
			}
			if seenRecords[string(fingerprint)] {
				return nil, fmt.Errorf("IAM assignment pagination repeated a record; repeat the query")
			}
			seenRecords[string(fingerprint)] = true
		}
		records = append(records, batch...)
		if int64(len(records)) > total {
			return nil, fmt.Errorf("IAM assignment response exceeds total_num")
		}
		if int64(len(records)) == total {
			return records, nil
		}
		if len(batch) == 0 {
			return nil, fmt.Errorf("IAM assignment pagination ended before total_num was reached")
		}
	}
	return nil, fmt.Errorf("IAM assignment pagination exceeded 10000 pages")
}

func (s *Service) GetProjectQuotas(id string) (Record, error) {
	return s.getVersion("v3.0", "quotas", "OS-QUOTA", "projects", id)
}

func ValidateDomainQuotaType(quotaType string) error {
	return inventoryEnum("quota type", quotaType, "user", "group", "idp", "agency", "policy")
}

func (s *Service) GetDomainQuotas(id, quotaType string) (Record, error) {
	if err := ValidateDomainQuotaType(quotaType); err != nil {
		return nil, err
	}
	endpoint, err := s.versionEndpoint("v3.0", "OS-QUOTA", "domains", id)
	if err != nil {
		return nil, err
	}
	endpoint.RawQuery = inventoryQuery(map[string]string{"type": quotaType}).Encode()
	var envelope map[string]json.RawMessage
	if err := s.read(endpoint, &envelope); err != nil {
		return nil, err
	}
	var quotas Record
	if err := decode(envelope["quotas"], &quotas); err != nil || quotas == nil {
		return nil, fmt.Errorf("IAM quota response must contain a quotas object")
	}
	return quotas, nil
}

func (s *Service) GetIdentityVersion() (Record, error) {
	return s.getVersion("v3", "version")
}

func inventoryOptionalIDs(ids map[string]string) error {
	for label, id := range ids {
		if id != "" {
			if err := ValidateID(label, id); err != nil {
				return err
			}
		}
	}
	return nil
}

func inventoryEnum(label, value string, choices ...string) error {
	if value == "" {
		return nil
	}
	for _, choice := range choices {
		if value == choice {
			return nil
		}
	}
	return fmt.Errorf("invalid %s %q; allowed values: %v", label, value, choices)
}

func inventoryCount(values ...string) int {
	count := 0
	for _, value := range values {
		if value != "" {
			count++
		}
	}
	return count
}

func inventoryQuery(values map[string]string) url.Values {
	query := url.Values{}
	for key, value := range values {
		if value != "" {
			query.Set(key, value)
		}
	}
	return query
}

func inventoryQueryBool(query url.Values, key string, value *bool) {
	if value != nil {
		query.Set(key, strconv.FormatBool(*value))
	}
}
