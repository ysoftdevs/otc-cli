package cmd

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/ysoftdevs/otc-cli/services/iam"
)

type iamFederationFake struct {
	iamAPI
	oidc     func(string) (iam.Record, error)
	check    func(string) ([]iam.Record, error)
	metadata func(string, string) (iam.Record, error)
	sp       func() (iam.Record, error)
}

func (f iamFederationFake) GetOIDCConfig(id string) (iam.Record, error) { return f.oidc(id) }
func (f iamFederationFake) CheckOIDCConfig(id string) ([]iam.Record, error) {
	return f.check(id)
}
func (f iamFederationFake) GetSAMLMetadata(provider, protocol string) (iam.Record, error) {
	return f.metadata(provider, protocol)
}
func (f iamFederationFake) GetSPMetadata() (iam.Record, error) { return f.sp() }

func TestIAMFederationInputAndHelpBeforeAuthentication(t *testing.T) {
	cases := [][]string{
		{"providers", "oidc", "show"},
		{"providers", "oidc", "show", "../IdP"},
		{"providers", "oidc", "check", "IdP?query"},
		{"protocols", "metadata", "IdP"},
		{"protocols", "metadata", "IdP", "../saml"},
		{"protocols", "sp-metadata", "unexpected"},
	}
	for _, args := range cases {
		command := newIAMCommand(func() (iamAPI, error) {
			t.Fatal("invalid input reached authentication")
			return nil, nil
		})
		command.SetArgs(args)
		command.SetOut(io.Discard)
		command.SetErr(io.Discard)
		if err := command.Execute(); err == nil {
			t.Fatalf("invalid input accepted: %v", args)
		}
	}
	command := newIAMCommand(func() (iamAPI, error) {
		t.Fatal("help reached authentication")
		return nil, nil
	})
	command.SetArgs([]string{"providers", "oidc", "check", "--help"})
	command.SetOut(io.Discard)
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
}

func TestIAMFederationCommandsPassExactArgumentsAndErrors(t *testing.T) {
	sentinel := errors.New("fixture denied")
	fake := iamFederationFake{
		oidc: func(id string) (iam.Record, error) {
			if id != "IdP" {
				t.Fatalf("wrong provider %q", id)
			}
			return nil, sentinel
		},
		check: func(id string) ([]iam.Record, error) {
			if id != "IdP" {
				t.Fatalf("wrong provider %q", id)
			}
			return nil, sentinel
		},
		metadata: func(id, protocol string) (iam.Record, error) {
			if id != "IdP" || protocol != "saml" {
				t.Fatalf("wrong binding %q/%q", id, protocol)
			}
			return nil, sentinel
		},
		sp: func() (iam.Record, error) { return nil, sentinel },
	}
	for _, args := range [][]string{
		{"providers", "oidc", "show", "IdP"},
		{"providers", "oidc", "check", "IdP"},
		{"protocols", "metadata", "IdP", "saml"},
		{"protocols", "sp-metadata"},
	} {
		command := newIAMCommand(func() (iamAPI, error) { return fake, nil })
		command.SetArgs(args)
		command.SetOut(io.Discard)
		command.SetErr(io.Discard)
		if err := command.Execute(); !errors.Is(err, sentinel) {
			t.Fatalf("service error lost for %v: %v", args, err)
		}
	}
}

func TestIAMOIDCCheckPrintsEvidenceBeforeNonzeroExit(t *testing.T) {
	originalFormat := format
	t.Cleanup(func() { format = originalFormat })
	for _, outputFormat := range []string{"table", "json", "yaml"} {
		for _, status := range []string{"match", "different", "unavailable"} {
			t.Run(outputFormat+"/"+status, func(t *testing.T) {
				format = outputFormat
				fake := iamFederationFake{check: func(string) ([]iam.Record, error) {
					return []iam.Record{{"check": "signing key", "kid": "fixture-key", "status": status, "detail": "fixture-evidence", "published_thumbprint": "fixture-fingerprint"}}, nil
				}}
				command := newIAMCommand(func() (iamAPI, error) { return fake, nil })
				command.SetArgs([]string{"providers", "oidc", "check", "IdP"})
				command.SetOut(io.Discard)
				command.SetErr(io.Discard)
				var result error
				output := captureIAMOutput(t, func() error {
					result = command.Execute()
					return nil
				})
				if (result != nil) != (status != "match") {
					t.Fatalf("incorrect exit status for %s: %v", status, result)
				}
				for _, field := range []string{"fixture-key", "fixture-evidence", status} {
					if !strings.Contains(output, field) {
						t.Fatalf("evidence %q missing from %s", field, output)
					}
				}
				if outputFormat != "table" && !strings.Contains(output, "fixture-fingerprint") {
					t.Fatal("structured output lost public fingerprint")
				}
			})
		}
	}
}
