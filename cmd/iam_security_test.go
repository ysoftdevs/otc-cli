package cmd

import (
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/ysoftdevs/otc-cli/services/iam"
)

func newIAMSecurityTestCommand(connect iamFactory) *cobra.Command {
	command := &cobra.Command{Use: "iam"}
	addIAMSecurityCommands(command, connect)
	return command
}

type iamSecurityCommandFake struct {
	iamAPI
	credentials func(string) ([]iam.Record, error)
	credential  func(string) (iam.Record, error)
	policy      func(string, string) (iam.Record, error)
	protection  func(string) (iam.Record, error)
	protections func() ([]iam.Record, error)
	mfaDevices  func() ([]iam.Record, error)
	mfaDevice   func(string) (iam.Record, error)
}

func (f iamSecurityCommandFake) ListCredentials(id string) ([]iam.Record, error) {
	return f.credentials(id)
}

func (f iamSecurityCommandFake) GetCredential(id string) (iam.Record, error) {
	return f.credential(id)
}

func (f iamSecurityCommandFake) GetSecurityPolicy(domain, policy string) (iam.Record, error) {
	return f.policy(domain, policy)
}

func (f iamSecurityCommandFake) GetLoginProtection(id string) (iam.Record, error) {
	return f.protection(id)
}

func (f iamSecurityCommandFake) ListLoginProtections() ([]iam.Record, error) {
	return f.protections()
}

func (f iamSecurityCommandFake) ListMFADevices() ([]iam.Record, error) {
	return f.mfaDevices()
}

func (f iamSecurityCommandFake) GetMFADevice(id string) (iam.Record, error) {
	return f.mfaDevice(id)
}

func TestIAMSecurityInvalidInputNeverAuthenticates(t *testing.T) {
	for _, args := range [][]string{
		{"credentials", "list", "extra"}, {"credentials", "list", "--user-id", ""},
		{"credentials", "list", "--user-id", "u?x=y"}, {"credentials", "show"},
		{"credentials", "show", "../key"}, {"mfa", "show"}, {"mfa", "show", "../user"},
		{"login-protection", "show", "user", "extra"}, {"login-protection", "list", "user"},
		{"security", "password-policy"}, {"security", "login-policy", "../domain"},
		{"security", "protect-policy", "domain", "extra"}, {"security", "unknown-policy", "domain"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			command := newIAMSecurityTestCommand(func() (iamAPI, error) {
				t.Fatal("invalid security input reached authentication")
				return nil, nil
			})
			command.SetOut(io.Discard)
			command.SetErr(io.Discard)
			command.SetArgs(args)
			if err := command.Execute(); err == nil {
				t.Fatal("invalid security input accepted")
			}
		})
	}
}

func TestIAMSecurityHelpNeverAuthenticates(t *testing.T) {
	for _, args := range [][]string{
		{"credentials", "list", "--help"}, {"mfa", "--help"},
		{"login-protection", "list", "--help"}, {"security", "api-acl-policy", "--help"},
	} {
		command := newIAMSecurityTestCommand(func() (iamAPI, error) {
			t.Fatal("security help reached authentication")
			return nil, nil
		})
		command.SetOut(io.Discard)
		command.SetArgs(args)
		if err := command.Execute(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestIAMSecurityCommandArgumentsReachService(t *testing.T) {
	sentinel := errors.New("fixture result")
	var got string
	fake := iamSecurityCommandFake{
		credentials: func(user string) ([]iam.Record, error) { got = "credentials:" + user; return nil, sentinel },
		credential:  func(key string) (iam.Record, error) { got = "credential:" + key; return nil, sentinel },
		policy: func(domain, policy string) (iam.Record, error) {
			got = "policy:" + domain + ":" + policy
			return nil, sentinel
		},
		protection:  func(user string) (iam.Record, error) { got = "protection:" + user; return nil, sentinel },
		protections: func() ([]iam.Record, error) { got = "protections"; return nil, sentinel },
		mfaDevices:  func() ([]iam.Record, error) { got = "mfa-devices"; return nil, sentinel },
		mfaDevice:   func(user string) (iam.Record, error) { got = "mfa-device:" + user; return nil, sentinel },
	}
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"credentials", "list"}, "credentials:"},
		{[]string{"credentials", "list", "--user-id", "u"}, "credentials:u"},
		{[]string{"credentials", "show", "key-1"}, "credential:key-1"},
		{[]string{"login-protection", "show", "u"}, "protection:u"},
		{[]string{"login-protection", "list"}, "protections"},
		{[]string{"mfa", "list"}, "mfa-devices"},
		{[]string{"mfa", "show", "u"}, "mfa-device:u"},
	}
	for _, policy := range []string{"password-policy", "login-policy", "protect-policy", "api-acl-policy", "console-acl-policy"} {
		cases = append(cases, struct {
			args []string
			want string
		}{[]string{"security", policy, "d"}, "policy:d:" + policy})
	}
	for _, tc := range cases {
		command := newIAMSecurityTestCommand(func() (iamAPI, error) { return fake, nil })
		command.SetOut(io.Discard)
		command.SetErr(io.Discard)
		command.SetArgs(tc.args)
		if err := command.Execute(); !errors.Is(err, sentinel) || got != tc.want {
			t.Fatalf("%v: got=%q want=%q err=%v", tc.args, got, tc.want, err)
		}
	}
}

func TestIAMSecurityCredentialStructuredOutput(t *testing.T) {
	fake := iamSecurityCommandFake{credential: func(key string) (iam.Record, error) {
		return iam.Record{"access": key, "status": "active", "last_use_time": "2026-07-04T12:13:14Z"}, nil
	}}
	originalFormat := format
	t.Cleanup(func() { format = originalFormat })
	format = "json"
	command := newIAMSecurityTestCommand(func() (iamAPI, error) { return fake, nil })
	command.SetArgs([]string{"credentials", "show", "key-1"})
	output := captureIAMOutput(t, command.Execute)
	var rows []iam.Record
	if err := json.Unmarshal([]byte(output), &rows); err != nil || len(rows) != 1 || rows[0]["last_use_time"] != "2026-07-04T12:13:14Z" {
		t.Fatalf("last-use metadata lost in output: %s err=%v", output, err)
	}
}

func TestIAMSecurityUnsupportedClientReturnsError(t *testing.T) {
	command := newIAMSecurityTestCommand(func() (iamAPI, error) { return iamCommandFake{}, nil })
	command.SetOut(io.Discard)
	command.SetErr(io.Discard)
	command.SetArgs([]string{"mfa", "list"})
	if err := command.Execute(); err == nil || !strings.Contains(err.Error(), "does not support security inspection") {
		t.Fatalf("unsupported client must fail clearly, got %v", err)
	}
}
