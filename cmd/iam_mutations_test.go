package cmd

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ysoftdevs/otc-cli/services/iam"
)

type iamMutationFake struct {
	iamAPI
	plan  func(string, []string, json.RawMessage) (iam.MutationPlan, error)
	apply func(iam.MutationPlan, iam.MutationApplyOptions) (iam.Record, error)
}

func (f iamMutationFake) PlanMutation(name string, args []string, body json.RawMessage) (iam.MutationPlan, error) {
	return f.plan(name, args, body)
}

func (f iamMutationFake) ApplyMutation(plan iam.MutationPlan, options iam.MutationApplyOptions) (iam.Record, error) {
	return f.apply(plan, options)
}

func TestIAMMutationHelpNeverAuthenticates(t *testing.T) {
	for _, spec := range iam.MutationSpecs() {
		t.Run(spec.Name, func(t *testing.T) {
			command := newIAMCommand(func() (iamAPI, error) {
				t.Fatal("management help authenticated")
				return nil, nil
			})
			var output strings.Builder
			command.SetOut(&output)
			command.SetErr(io.Discard)
			args := append(append([]string(nil), spec.CommandPath...), strings.Fields(spec.Use)[0], "--help")
			command.SetArgs(args)
			if err := command.Execute(); err != nil {
				t.Fatal(err)
			}
			for _, text := range []string{"--apply", "--confirm", "--expected-hash", "--backup", "preview"} {
				if !strings.Contains(output.String(), text) {
					t.Errorf("management help does not describe %s", text)
				}
			}
		})
	}
}

func TestIAMMutationInvalidInputNeverAuthenticates(t *testing.T) {
	for _, test := range []struct {
		name  string
		args  []string
		input string
	}{
		{"missing resource", []string{"groups", "update", "--file", "-"}, `{"group":{"description":"new"}}`},
		{"extra resource", []string{"groups", "create", "unexpected", "--file", "-"}, `{"group":{"name":"Readers"}}`},
		{"path traversal", []string{"groups", "delete", "../other"}, ""},
		{"query injection", []string{"groups", "grant-project", "g", "p?other=1", "r"}, ""},
		{"unknown flag", []string{"groups", "delete", "g", "--yes"}, ""},
		{"invalid apply boolean", []string{"groups", "delete", "g", "--apply=maybe"}, ""},
		{"hash without apply", []string{"groups", "delete", "g", "--expected-hash", "hash"}, ""},
		{"backup without apply", []string{"groups", "delete", "g", "--backup", "backup.json"}, ""},
		{"output without apply", []string{"groups", "delete", "g", "--output", "output.json"}, ""},
		{"confirm without apply", []string{"groups", "delete", "g", "--confirm", "/v3/groups/g"}, ""},
		{"apply missing confirmation", []string{"groups", "delete", "g", "--apply"}, ""},
		{"apply missing reviewed state", []string{"groups", "delete", "g", "--apply", "--confirm", "/v3/groups/g"}, ""},
		{"apply missing hash", []string{"groups", "delete", "g", "--apply", "--confirm", "/v3/groups/g", "--backup", "backup.json"}, ""},
		{"apply missing backup", []string{"groups", "delete", "g", "--apply", "--confirm", "/v3/groups/g", "--expected-hash", strings.Repeat("a", 64)}, ""},
		{"secret create missing output", []string{"credentials", "create", "--file", "-", "--apply", "--confirm", "/v3.0/OS-CREDENTIAL/credentials"}, `{"credential":{"user_id":"user"}}`},
		{"MFA create missing output", []string{"mfa", "create", "--file", "-", "--apply", "--confirm", "/v3.0/OS-MFA/virtual-mfa-devices"}, `{"virtual_mfa_device":{"name":"Phone","user_id":"user"}}`},
		{"missing file flag", []string{"groups", "create"}, ""},
		{"file on bodyless operation", []string{"groups", "delete", "g", "--file", "-"}, `{}`},
		{"empty stdin", []string{"groups", "create", "--file", "-"}, ""},
		{"invalid JSON", []string{"groups", "create", "--file", "-"}, `{"group":`},
		{"duplicate member", []string{"groups", "create", "--file", "-"}, `{"group":{"name":"first","name":"second"}}`},
		{"wrong envelope", []string{"groups", "create", "--file", "-"}, `{"user":{"name":"Reader"}}`},
		{"extra envelope", []string{"groups", "create", "--file", "-"}, `{"group":{"name":"Readers"},"other":{}}`},
		{"empty object", []string{"groups", "update", "g", "--file", "-"}, `{"group":{}}`},
		{"array envelope", []string{"groups", "create", "--file", "-"}, `[{"group":{"name":"Readers"}}]`},
		{"missing required field", []string{"users", "create", "--file", "-"}, `{"user":{"name":"Reader"}}`},
		{"invalid field type", []string{"projects", "set-status", "p", "--file", "-"}, `{"project":{"status":false}}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			command := newIAMCommand(func() (iamAPI, error) {
				t.Fatal("invalid management input authenticated")
				return nil, nil
			})
			command.SetOut(io.Discard)
			command.SetErr(io.Discard)
			command.SetIn(strings.NewReader(test.input))
			command.SetArgs(test.args)
			if err := command.Execute(); err == nil {
				t.Fatal("invalid management input was accepted")
			}
		})
	}
}

func TestIAMMutationInputFileFailuresNeverAuthenticate(t *testing.T) {
	directory := t.TempDir()
	for _, path := range []string{directory, filepath.Join(directory, "missing.json")} {
		command := newIAMCommand(func() (iamAPI, error) {
			t.Fatal("invalid request file authenticated")
			return nil, nil
		})
		command.SetOut(io.Discard)
		command.SetErr(io.Discard)
		command.SetArgs([]string{"groups", "create", "--file", path})
		if err := command.Execute(); err == nil {
			t.Fatal("invalid request file was accepted")
		}
	}
}

func TestIAMMutationRequestSizeBoundary(t *testing.T) {
	const maximum = 2 << 20
	const body = `{"group":{"name":"Readers"}}`
	for _, source := range []string{"stdin", "file"} {
		for _, oversized := range []bool{false, true} {
			name := source + "/limit"
			if oversized {
				name += "+1"
			}
			t.Run(name, func(t *testing.T) {
				size := maximum
				if oversized {
					size++
				}
				input := body + strings.Repeat(" ", size-len(body))
				calls := 0
				sentinel := errors.New("fixture authentication reached")
				command := newIAMCommand(func() (iamAPI, error) {
					calls++
					return nil, sentinel
				})
				command.SetOut(io.Discard)
				command.SetErr(io.Discard)
				path := "-"
				if source == "file" {
					path = filepath.Join(t.TempDir(), "request.json")
					if err := os.WriteFile(path, []byte(input), 0600); err != nil {
						t.Fatal(err)
					}
				} else {
					command.SetIn(strings.NewReader(input))
				}
				command.SetArgs([]string{"groups", "create", "--file", path})
				err := command.Execute()
				if oversized {
					if err == nil || !strings.Contains(err.Error(), "2 MiB") || calls != 0 {
						t.Fatalf("oversized input reached authentication: calls=%d err=%v", calls, err)
					}
				} else if !errors.Is(err, sentinel) || calls != 1 {
					t.Fatalf("exactly 2 MiB should validate: calls=%d err=%v", calls, err)
				}
			})
		}
	}
}

func TestIAMMutationPreviewNeverAppliesAndPreservesNumbers(t *testing.T) {
	originalFormat := format
	t.Cleanup(func() { format = originalFormat })
	format = "json"
	for _, flags := range [][]string{nil, {"--apply=false"}} {
		t.Run(strings.Join(flags, " "), func(t *testing.T) {
			const input = `{"group":{"description":"new"}}`
			const precise = "9007199254740993"
			plans, applies := 0, 0
			fake := iamMutationFake{
				plan: func(name string, args []string, body json.RawMessage) (iam.MutationPlan, error) {
					plans++
					if name != "group-update" || !reflect.DeepEqual(args, []string{"g"}) || string(body) != input {
						t.Fatalf("preview request changed: name=%s args=%v body=%s", name, args, body)
					}
					return iam.MutationPlan{
						Operation: name, Method: "PATCH", Path: "/v3/groups/g", StateHash: "reviewed-hash",
						Current: iam.Record{"sequence": json.Number(precise)}, Proposed: iam.Record{"sequence": json.Number(precise)},
						NeedsBackup: true, Confirmation: "/v3/groups/g", Atomic: false,
					}, nil
				},
				apply: func(iam.MutationPlan, iam.MutationApplyOptions) (iam.Record, error) {
					applies++
					return nil, errors.New("preview unexpectedly applied")
				},
			}
			command := newIAMCommand(func() (iamAPI, error) { return fake, nil })
			command.SetOut(io.Discard)
			command.SetErr(io.Discard)
			command.SetIn(strings.NewReader(input))
			command.SetArgs(append([]string{"groups", "update", "g", "--file", "-"}, flags...))
			output := captureIAMOutput(t, command.Execute)
			if plans != 1 || applies != 0 {
				t.Fatalf("preview invoked plan=%d apply=%d", plans, applies)
			}
			var rows []iam.Record
			decoder := json.NewDecoder(strings.NewReader(output))
			decoder.UseNumber()
			if err := decoder.Decode(&rows); err != nil || len(rows) != 1 {
				t.Fatalf("invalid preview JSON: %s, %v", output, err)
			}
			for _, field := range []string{"current", "proposed"} {
				object, ok := rows[0][field].(map[string]any)
				if !ok || object["sequence"] != json.Number(precise) {
					t.Errorf("%s lost integer precision: %s", field, output)
				}
			}
			if rows[0]["atomic_compare_and_swap"] != false || rows[0]["needs_backup"] != true || rows[0]["confirmation"] != "/v3/groups/g" {
				t.Errorf("preview dropped safeguards: %s", output)
			}
		})
	}
}

func TestIAMMutationApplyForwardsReviewedOptions(t *testing.T) {
	originalFormat := format
	t.Cleanup(func() { format = originalFormat })
	format = "json"
	for _, test := range []struct {
		name, operation, body, confirmation string
		args                                []string
		existing, secret                    bool
	}{
		{"existing", "group-update", `{"group":{"description":"new"}}`, "/v3/groups/g", []string{"groups", "update", "g"}, true, false},
		{"create", "group-create", `{"group":{"name":"Readers"}}`, "/v3/groups", []string{"groups", "create"}, false, false},
		{"secret create", "credentials-create", `{"credential":{"user_id":"u"}}`, "/v3.0/OS-CREDENTIAL/credentials", []string{"credentials", "create"}, false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var events []string
			want := iam.MutationApplyOptions{Confirm: test.confirmation}
			args := append(append([]string(nil), test.args...), "--file", "-", "--apply", "--confirm", want.Confirm)
			if test.existing {
				want.ExpectedHash = strings.Repeat("a", 64)
				want.BackupPath = filepath.Join(t.TempDir(), "reviewed state.json")
				args = append(args, "--expected-hash", want.ExpectedHash, "--backup", want.BackupPath)
			}
			if test.secret {
				want.OutputPath = filepath.Join(t.TempDir(), "private credentials.json")
				args = append(args, "--output", want.OutputPath)
			}
			plan := iam.MutationPlan{Operation: test.operation, StateHash: want.ExpectedHash, Confirmation: want.Confirm, NeedsBackup: test.existing, NeedsOutput: test.secret}
			fake := iamMutationFake{
				plan: func(operation string, ids []string, body json.RawMessage) (iam.MutationPlan, error) {
					events = append(events, "plan")
					if operation != test.operation || string(body) != test.body || !reflect.DeepEqual(ids, test.args[2:]) {
						t.Fatalf("apply plan received wrong validated input: %s %v %s", operation, ids, body)
					}
					return plan, nil
				},
				apply: func(got iam.MutationPlan, options iam.MutationApplyOptions) (iam.Record, error) {
					events = append(events, "apply")
					if !reflect.DeepEqual(got, plan) || options != want {
						t.Fatalf("reviewed plan/options changed: plan=%+v options=%+v want=%+v", got, options, want)
					}
					return iam.Record{"operation": test.operation, "applied": true}, nil
				},
			}
			command := newIAMCommand(func() (iamAPI, error) {
				events = append(events, "authenticate")
				return fake, nil
			})
			command.SetOut(io.Discard)
			command.SetErr(io.Discard)
			command.SetIn(strings.NewReader(test.body))
			command.SetArgs(args)
			output := captureIAMOutput(t, command.Execute)
			if !reflect.DeepEqual(events, []string{"authenticate", "plan", "apply"}) || !strings.Contains(output, `"applied": true`) {
				t.Fatalf("apply sequence/output incorrect: %v, %s", events, output)
			}
		})
	}
}

func TestIAMMutationUnsupportedClient(t *testing.T) {
	calls := 0
	command := newIAMCommand(func() (iamAPI, error) {
		calls++
		return iamCommandFake{}, nil
	})
	command.SetOut(io.Discard)
	command.SetErr(io.Discard)
	command.SetArgs([]string{"groups", "delete", "g"})
	if err := command.Execute(); err == nil || !strings.Contains(err.Error(), "does not support management") || calls != 1 {
		t.Fatalf("unsupported client was not rejected: calls=%d err=%v", calls, err)
	}
}

func TestIAMMutationErrorsStopWithoutRetry(t *testing.T) {
	for _, failure := range []string{"authenticate", "plan", "apply"} {
		t.Run(failure, func(t *testing.T) {
			sentinel := errors.New("fixture operation failed")
			var events []string
			fake := iamMutationFake{
				plan: func(string, []string, json.RawMessage) (iam.MutationPlan, error) {
					events = append(events, "plan")
					if failure == "plan" {
						return iam.MutationPlan{}, sentinel
					}
					return iam.MutationPlan{}, nil
				},
				apply: func(iam.MutationPlan, iam.MutationApplyOptions) (iam.Record, error) {
					events = append(events, "apply")
					return nil, sentinel
				},
			}
			command := newIAMCommand(func() (iamAPI, error) {
				events = append(events, "authenticate")
				if failure == "authenticate" {
					return nil, sentinel
				}
				return fake, nil
			})
			command.SetOut(io.Discard)
			command.SetErr(io.Discard)
			command.SetIn(strings.NewReader(`{"group":{"name":"Readers"}}`))
			command.SetArgs([]string{"groups", "create", "--file", "-", "--apply", "--confirm", "/v3/groups"})
			if err := command.Execute(); !errors.Is(err, sentinel) {
				t.Fatalf("error was not propagated: %v", err)
			}
			want := []string{"authenticate"}
			if failure != "authenticate" {
				want = append(want, "plan")
			}
			if failure == "apply" {
				want = append(want, "apply")
			}
			if !reflect.DeepEqual(events, want) {
				t.Fatalf("continued or retried after error: %v; want %v", events, want)
			}
		})
	}
}
