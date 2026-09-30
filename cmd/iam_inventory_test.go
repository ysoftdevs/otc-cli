package cmd

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/ysoftdevs/otc-cli/services/iam"
)

func TestIAMInventoryCommandsReachAuthentication(t *testing.T) {
	commands := [][]string{
		{"regions", "list"}, {"regions", "show", "eu-de"},
		{"projects", "list"}, {"projects", "show", "p"}, {"projects", "status", "p"},
		{"projects", "accessible"}, {"projects", "quotas", "p"}, {"users", "projects", "u"},
		{"domains", "accessible"}, {"domains", "quotas", "d", "--type", "user"},
		{"services", "list"}, {"services", "show", "s"},
		{"endpoints", "list"}, {"endpoints", "show", "e"}, {"catalog", "list"},
		{"agencies", "list", "--domain-id", "d"}, {"agencies", "show", "a"},
		{"agencies", "roles", "a", "--domain-id", "d", "--all-projects"},
		{"assignments", "list", "--domain-id", "d"}, {"versions", "show"},
	}
	for _, args := range commands {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			sentinel := errors.New("fixture authentication error")
			calls := 0
			command := newIAMCommand(func() (iamAPI, error) {
				calls++
				return nil, sentinel
			})
			command.SetOut(io.Discard)
			command.SetErr(io.Discard)
			command.SetArgs(args)
			if err := command.Execute(); !errors.Is(err, sentinel) || calls != 1 {
				t.Fatalf("command did not reach its read implementation: calls=%d err=%v", calls, err)
			}
		})
	}
}

func TestIAMInventoryRejectsInvalidInputBeforeAuthentication(t *testing.T) {
	commands := [][]string{
		{"regions", "show", "../other"}, {"projects", "show"}, {"projects", "status", "p?x=y"},
		{"projects", "list", "--domain-id", ""}, {"projects", "list", "--parent-id", "../p"},
		{"projects", "list", "--enabled=perhaps"}, {"users", "projects", "u/v"},
		{"domains", "quotas", "d", "--type", "compute"},
		{"endpoints", "list", "--interface", "unknown"}, {"endpoints", "list", "--service-id", ""},
		{"agencies", "list"}, {"agencies", "list", "--domain-id", "d", "--trust-domain-id", "../trust"},
		{"agencies", "roles", "a"}, {"agencies", "roles", "a", "--project-id", "p", "--all-projects"},
		{"agencies", "roles", "a", "--project-id", "p", "--domain-id", "d"},
		{"assignments", "list"}, {"assignments", "list", "--domain-id", "d", "--subject", "unknown"},
		{"assignments", "list", "--domain-id", "d", "--subject", "user", "--user-id", "u"},
		{"assignments", "list", "--domain-id", "d", "--user-id", "u", "--group-id", "g"},
		{"assignments", "list", "--domain-id", "d", "--scope", "domain", "--project-id", "p"},
		{"assignments", "list", "--domain-id", "d", "--scope", "unknown"},
		{"assignments", "list", "--domain-id", "d", "--is-inherited"},
		{"assignments", "list", "--domain-id", "d", "--include-group=false"},
		{"assignments", "list", "--domain-id", "d", "--role-id", ""},
		{"assignments", "list", "--domain-id", "d", "--enterprise-project-id", "unverified-filter"},
		{"catalog", "list", "unexpected"}, {"versions", "show", "v5"},
	}
	for _, args := range commands {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			command := newIAMCommand(func() (iamAPI, error) {
				t.Fatal("invalid inventory input reached authentication")
				return nil, nil
			})
			command.SetOut(io.Discard)
			command.SetErr(io.Discard)
			command.SetArgs(args)
			if err := command.Execute(); err == nil {
				t.Fatal("invalid input was accepted")
			}
		})
	}
}

type iamInventoryFake struct {
	iamAPI
	iamInventoryAPI
	assignments func(iam.AssignmentListOptions) ([]iam.Record, error)
	projects    func(iam.ProjectListOptions) ([]iam.Record, error)
	agencyRoles func(string, iam.Scope) ([]iam.Record, error)
}

func (f iamInventoryFake) ListAssignments(opts iam.AssignmentListOptions) ([]iam.Record, error) {
	return f.assignments(opts)
}

func (f iamInventoryFake) ListProjects(opts iam.ProjectListOptions) ([]iam.Record, error) {
	return f.projects(opts)
}

func (f iamInventoryFake) ListAgencyRoles(id string, scope iam.Scope) ([]iam.Record, error) {
	return f.agencyRoles(id, scope)
}

func TestIAMInventoryAssignmentOptionsPreserveExplicitFalse(t *testing.T) {
	sentinel := errors.New("fixture result")
	tests := []struct {
		flags []string
		check func(iam.AssignmentListOptions)
	}{
		{[]string{"--user-id", "u", "--scope-domain-id", "d", "--include-group=false", "--is-inherited=false"}, func(opts iam.AssignmentListOptions) {
			if opts.UserID != "u" || opts.ScopeDomainID != "d" || opts.IncludeGroup == nil || *opts.IncludeGroup || opts.IsInherited == nil || *opts.IsInherited {
				t.Errorf("explicit false values were lost: %+v", opts)
			}
		}},
		{[]string{"--subject", "user", "--scope", "domain"}, func(opts iam.AssignmentListOptions) {
			if opts.Subject != "user" || opts.Scope != "domain" || opts.IncludeGroup != nil || opts.IsInherited != nil {
				t.Errorf("omitted filters must retain API defaults: %+v", opts)
			}
		}},
		{[]string{"--agency-id", "a", "--scope", "enterprise_project", "--role-id", "r"}, func(opts iam.AssignmentListOptions) {
			if opts.AgencyID != "a" || opts.Scope != "enterprise_project" || opts.RoleID != "r" {
				t.Errorf("assignment filters changed: %+v", opts)
			}
		}},
	}
	for _, test := range tests {
		t.Run(strings.Join(test.flags, " "), func(t *testing.T) {
			fake := iamInventoryFake{assignments: func(opts iam.AssignmentListOptions) ([]iam.Record, error) {
				if opts.DomainID != "d" {
					t.Error("account selector lost")
				}
				test.check(opts)
				return nil, sentinel
			}}
			command := newIAMCommand(func() (iamAPI, error) { return fake, nil })
			command.SetOut(io.Discard)
			command.SetErr(io.Discard)
			command.SetArgs(append([]string{"assignments", "list", "--domain-id", "d"}, test.flags...))
			if err := command.Execute(); !errors.Is(err, sentinel) {
				t.Fatalf("service result was not propagated: %v", err)
			}
		})
	}
}

func TestIAMInventoryProjectFiltersAndAgencyScopeReachService(t *testing.T) {
	sentinel := errors.New("fixture result")
	fake := iamInventoryFake{
		projects: func(opts iam.ProjectListOptions) ([]iam.Record, error) {
			if opts.DomainID != "d" || opts.Name != "name&extra=value" || opts.ParentID != "p" || opts.Enabled == nil || *opts.Enabled || opts.IsDomain == nil || *opts.IsDomain {
				t.Errorf("project filters changed: %+v", opts)
			}
			return nil, sentinel
		},
		agencyRoles: func(id string, scope iam.Scope) ([]iam.Record, error) {
			if id != "a" || scope != (iam.Scope{DomainID: "d", AllProjects: true}) {
				t.Errorf("agency assignment scope changed: id=%s scope=%+v", id, scope)
			}
			return nil, sentinel
		},
	}
	for _, args := range [][]string{
		{"projects", "list", "--domain-id", "d", "--name", "name&extra=value", "--parent-id", "p", "--enabled=false", "--is-domain=false"},
		{"agencies", "roles", "a", "--domain-id", "d", "--all-projects"},
	} {
		command := newIAMCommand(func() (iamAPI, error) { return fake, nil })
		command.SetOut(io.Discard)
		command.SetErr(io.Discard)
		command.SetArgs(args)
		if err := command.Execute(); !errors.Is(err, sentinel) {
			t.Fatalf("service result was not propagated: %v", err)
		}
	}
}

func TestIAMInventoryAssignmentOutputPreservesAuthorizationFields(t *testing.T) {
	fake := iamInventoryFake{assignments: func(iam.AssignmentListOptions) ([]iam.Record, error) {
		return []iam.Record{{"user": iam.Record{"id": "u"}, "group": iam.Record{"id": "g"}, "role": iam.Record{"id": "r"}, "scope": iam.Record{"enterprise_project": iam.Record{"id": "ep"}}, "is_inherited": false}}, nil
	}}
	previous := format
	t.Cleanup(func() { format = previous })
	format = "json"
	command := newIAMCommand(func() (iamAPI, error) { return fake, nil })
	command.SetArgs([]string{"assignments", "list", "--domain-id", "d"})
	output := captureIAMOutput(t, command.Execute)
	for _, field := range []string{`"enterprise_project"`, `"is_inherited": false`, `"group"`, `"user"`, `"role"`} {
		if !strings.Contains(output, field) {
			t.Errorf("assignment output lost %s: %s", field, output)
		}
	}
}
