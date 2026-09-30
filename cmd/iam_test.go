package cmd

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/ysoftdevs/otc-cli/formats"
	"github.com/ysoftdevs/otc-cli/services/iam"
)

func TestIAMRejectsInvalidInputBeforeAuthentication(t *testing.T) {
	cases := [][]string{
		{"users", "list", "unexpected"},
		{"users", "show"},
		{"users", "show", "../another-user"},
		{"providers", "show", "provider?query=injected"},
		{"protocols", "show", "provider"},
		{"mappings", "show", ".."},
		{"groups", "roles", "group-id"},
		{"groups", "roles", "group-id", "--domain-id", "domain", "--project-id", "project"},
		{"groups", "roles", "group-id", "--project-id", "project", "--all-projects"},
		{"groups", "roles", "group-id", "--domain-id", "../domain"},
		{"roles", "list", "--domain-id", ""},
	}
	for _, args := range cases {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			command := newIAMCommand(func() (iamAPI, error) {
				t.Fatal("invalid input reached authentication")
				return nil, nil
			})
			command.SetOut(io.Discard)
			command.SetErr(io.Discard)
			command.SetArgs(args)
			if err := command.Execute(); err == nil {
				t.Fatal("expected argument or scope error")
			}
		})
	}
}

func TestIAMHelpDoesNotAuthenticate(t *testing.T) {
	command := newIAMCommand(func() (iamAPI, error) {
		t.Fatal("help reached authentication")
		return nil, nil
	})
	command.SetOut(io.Discard)
	command.SetArgs([]string{"groups", "roles", "--help"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
}

type iamCommandFake struct {
	iamAPI
	groupRoles func(string, iam.Scope) ([]iam.Record, error)
	listRoles  func(string, string) ([]iam.Record, error)
	protocol   func(string, string) (iam.Record, error)
}

func (f iamCommandFake) ListGroupRoles(id string, scope iam.Scope) ([]iam.Record, error) {
	return f.groupRoles(id, scope)
}

func (f iamCommandFake) ListRoles(domainID, name string) ([]iam.Record, error) {
	return f.listRoles(domainID, name)
}

func (f iamCommandFake) GetProtocol(providerID, protocolID string) (iam.Record, error) {
	return f.protocol(providerID, protocolID)
}

func TestIAMGroupRoleScopeReachesService(t *testing.T) {
	cases := []struct {
		flags []string
		want  iam.Scope
	}{
		{[]string{"--domain-id", "domain"}, iam.Scope{DomainID: "domain"}},
		{[]string{"--project-id", "project"}, iam.Scope{ProjectID: "project"}},
		{[]string{"--domain-id", "domain", "--all-projects"}, iam.Scope{DomainID: "domain", AllProjects: true}},
	}
	for _, tc := range cases {
		t.Run(strings.Join(tc.flags, " "), func(t *testing.T) {
			sentinel := errors.New("fixture authorization denied")
			fake := iamCommandFake{groupRoles: func(id string, scope iam.Scope) ([]iam.Record, error) {
				if id != "group-id" || scope != tc.want {
					t.Fatalf("unexpected scope: %q %+v", id, scope)
				}
				return nil, sentinel
			}}
			command := newIAMCommand(func() (iamAPI, error) { return fake, nil })
			command.SetOut(io.Discard)
			command.SetErr(io.Discard)
			command.SetArgs(append([]string{"groups", "roles", "group-id"}, tc.flags...))
			if err := command.Execute(); !errors.Is(err, sentinel) {
				t.Fatalf("service error must reach caller, got: %v", err)
			}
		})
	}
}

func TestIAMCustomRoleFilterAndProviderBinding(t *testing.T) {
	sentinel := errors.New("fixture result")
	fake := iamCommandFake{
		listRoles: func(domainID, name string) ([]iam.Record, error) {
			if domainID != "domain" || name != "Cloud_ReadOnly" {
				t.Fatalf("filters changed: %q %q", domainID, name)
			}
			return nil, sentinel
		},
		protocol: func(providerID, protocolID string) (iam.Record, error) {
			if providerID != "Y_Soft_Entra_ID_PROD" || protocolID != "saml" {
				t.Fatalf("provider/protocol changed: %q %q", providerID, protocolID)
			}
			return nil, sentinel
		},
	}
	for _, args := range [][]string{
		{"roles", "list", "--domain-id", "domain", "--name", "Cloud_ReadOnly"},
		{"protocols", "show", "Y_Soft_Entra_ID_PROD", "saml"},
	} {
		command := newIAMCommand(func() (iamAPI, error) { return fake, nil })
		command.SetOut(io.Discard)
		command.SetErr(io.Discard)
		command.SetArgs(args)
		if err := command.Execute(); !errors.Is(err, sentinel) {
			t.Fatalf("expected fixture result for %v, got: %v", args, err)
		}
	}
}

// Regression for SDK role models that omit Extra or reduce policy statements
// to Action/Effect, losing the conditions needed to review an authorization.
func TestIAMStructuredOutputPreservesPolicyAndMapping(t *testing.T) {
	var row iam.Record
	err := json.Unmarshal([]byte(`{
		"id":"custom-policy",
		"policy":{"Version":"1.1","Statement":[{
			"Effect":"Deny","Action":["test:resources:read"],
			"Resource":["test:region:account:resource/example"],
			"Condition":{"StringEquals":{"test:owner":"fixture-owner"}}
		}]},
		"rules":[{"remote":[{"type":"roles","any_one_of":["Reader"]}],
			"local":[{"groups":"Cloud_ReadOnly"}]}]
	}`), &row)
	if err != nil {
		t.Fatal(err)
	}
	originalFormat := format
	t.Cleanup(func() { format = originalFormat })
	for _, outputFormat := range []string{"json", "yaml", "table"} {
		t.Run(outputFormat, func(t *testing.T) {
			format = outputFormat
			output := captureIAMOutput(t, func() error {
				return printIAMRecords([]iam.Record{row}, formats.View[iam.Record]{}, true)
			})
			for _, fragment := range []string{"Resource", "Condition", "fixture-owner", "any_one_of", "Cloud_ReadOnly"} {
				if !strings.Contains(output, fragment) {
					t.Fatalf("%s output dropped %q: %s", outputFormat, fragment, output)
				}
			}
			if outputFormat == "json" {
				var got []iam.Record
				if err := json.Unmarshal([]byte(output), &got); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(got, []iam.Record{row}) {
					t.Fatalf("JSON changed API fields: %#v", got)
				}
			}
		})
	}
}

func captureIAMOutput(t *testing.T, run func() error) string {
	t.Helper()
	output, err := os.CreateTemp(t.TempDir(), "output")
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stdout
	os.Stdout = output
	defer func() { os.Stdout = original; output.Close() }()
	if err := run(); err != nil {
		t.Fatal(err)
	}
	if _, err := output.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(output)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
