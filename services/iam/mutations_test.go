package iam

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mutationTestService(t *testing.T, handler http.HandlerFunc) *Service {
	t.Helper()
	service, _ := testService(t, handler)
	service.client.DomainID = "account-1"
	return service
}

func TestMutationPreviewReadsOnlyAndRedactsSecrets(t *testing.T) {
	requests := 0
	service := mutationTestService(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodGet || r.URL.Path != "/v3/users/u" {
			t.Errorf("preview made unexpected request %s %s", r.Method, r.URL)
		}
		fmt.Fprint(w, `{"user":{"id":"u","password":"server-secret","nested":{"access_token":"private"}}}`)
	})
	plan, err := service.PlanMutation("users-change-password", []string{"u"}, json.RawMessage(`{"user":{"password":"new-secret","original_password":"old-secret"}}`))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"server-secret", "new-secret", "old-secret", "private" + `"}`} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("preview leaked secret: %s", encoded)
		}
	}
	if requests != 1 || !plan.NeedsBackup || plan.Atomic || len(plan.StateHash) != 64 || plan.AccountID != "account-1" {
		t.Fatalf("invalid plan: %+v requests=%d", plan, requests)
	}
	policy := redactMutation(Record{"password_policy": Record{"minimum_password_length": 12}, "allow_user": Record{"manage_password": true}, "password": "hide"}).(Record)
	if policy["password_policy"].(Record)["minimum_password_length"] != 12 || policy["password"] != "<redacted>" {
		t.Fatalf("policy settings must remain reviewable: %v", policy)
	}
}

func TestMutationInvalidInputAndMissingAccountMakeNoRequests(t *testing.T) {
	service := mutationTestService(t, func(http.ResponseWriter, *http.Request) { t.Error("invalid input reached API") })
	for _, tc := range []struct {
		name string
		args []string
		body string
	}{
		{"unknown-operation", nil, ""},
		{"group-update", []string{"../g"}, `{"group":{"name":"x"}}`},
		{"group-update", []string{"g"}, `{"group":{"name":"first","name":"last"}}`},
		{"group-update", []string{"g"}, `{"group":{"name":"x"},"unexpected":{}}`},
		{"group-update", []string{"g"}, `{"group":{}}`},
		{"group-delete", []string{"g"}, `{}`},
	} {
		if _, err := service.PlanMutation(tc.name, tc.args, json.RawMessage(tc.body)); err == nil {
			t.Errorf("invalid mutation accepted: %+v", tc)
		}
	}
	service.client.DomainID = ""
	if _, err := service.PlanMutation("group-create", nil, json.RawMessage(`{"group":{"name":"x"}}`)); err == nil {
		t.Fatal("management allowed without known account")
	}
}

func TestMutationApplyBacksUpStateBeforeSingleWrite(t *testing.T) {
	dir := t.TempDir()
	backup := filepath.Join(dir, "before.json")
	reads, writes := 0, 0
	service := mutationTestService(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v3/groups/g" || r.Header.Get("X-Auth-Token") != "test-token" {
			t.Errorf("unexpected authenticated request %s", r.URL)
		}
		if r.Method == http.MethodGet {
			reads++
			fmt.Fprint(w, `{"group":{"id":"g","name":"before"}}`)
			return
		}
		writes++
		if r.Method != http.MethodPatch {
			t.Errorf("unexpected mutation %s", r.Method)
		}
		before, err := os.ReadFile(backup)
		if err != nil || !strings.Contains(string(before), `"name": "before"`) {
			t.Errorf("original state not saved before write: %s %v", before, err)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil || strings.TrimSpace(string(body)) != `{"group":{"name":"after"}}` {
			t.Errorf("request JSON changed: %s %v", body, err)
		}
		fmt.Fprint(w, `{"group":{"id":"g","name":"after"}}`)
	})
	plan, err := service.PlanMutation("group-update", []string{"g"}, json.RawMessage(`{"group":{"name":"after"}}`))
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.ApplyMutation(plan, MutationApplyOptions{ExpectedHash: plan.StateHash, Confirm: plan.Confirmation, BackupPath: backup})
	if err != nil || result["status"] != "completed" || reads != 2 || writes != 1 {
		t.Fatalf("apply: result=%v err=%v reads=%d writes=%d", result, err, reads, writes)
	}
	assertPrivateFilePermissions(t, backup)
}

func TestMutationApplyRefusesStaleUnconfirmedAndUnsafeFiles(t *testing.T) {
	for _, reason := range []string{"state-changed", "wrong-hash", "wrong-confirm", "missing-backup", "existing-backup", "symlink-backup", "existing-output", "forged-plan"} {
		t.Run(reason, func(t *testing.T) {
			changed := false
			service := mutationTestService(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Error("unsafe operation wrote to IAM")
				}
				fmt.Fprintf(w, `{"group":{"id":"g","changed":%t}}`, changed)
			})
			plan, err := service.PlanMutation("group-delete", []string{"g"}, nil)
			if err != nil {
				t.Fatal(err)
			}
			options := MutationApplyOptions{ExpectedHash: plan.StateHash, Confirm: plan.Confirmation, BackupPath: filepath.Join(t.TempDir(), "backup.json")}
			switch reason {
			case "state-changed":
				changed = true
			case "wrong-hash":
				options.ExpectedHash = "wrong"
			case "wrong-confirm":
				options.Confirm = "/v3/groups/other"
			case "missing-backup":
				options.BackupPath = ""
			case "existing-backup", "existing-output":
				if err := os.WriteFile(options.BackupPath, []byte("keep"), 0600); err != nil {
					t.Fatal(err)
				}
				if reason == "existing-output" {
					options.OutputPath = options.BackupPath
					options.BackupPath += ".new"
				}
			case "symlink-backup":
				if err := os.Symlink(filepath.Join(t.TempDir(), "target"), options.BackupPath); err != nil {
					t.Fatal(err)
				}
			case "forged-plan":
				plan = MutationPlan{Operation: "group-delete"}
			}
			if _, err := service.ApplyMutation(plan, options); err == nil {
				t.Fatal("unsafe apply accepted")
			}
		})
	}
}

func TestMutationNeverRetriesOrRedirectsWrites(t *testing.T) {
	redirected := 0
	sink := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected++ }))
	defer sink.Close()
	for _, status := range []int{307, 308, 401, 429, 500, 502, 503, 504} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			requests := 0
			service := mutationTestService(t, func(w http.ResponseWriter, r *http.Request) {
				requests++
				if r.Method != http.MethodPost {
					t.Errorf("create sent %s", r.Method)
				}
				w.Header().Set("Location", sink.URL+"/?secret=private")
				w.Header().Set("Retry-After", "0")
				w.WriteHeader(status)
				fmt.Fprint(w, `{"error":{"message":"echoed-password-should-not-leak"}}`)
			})
			service.client.ReauthFunc = func() error { t.Error("write attempted reauthentication"); return nil }
			plan, err := service.PlanMutation("group-create", nil, json.RawMessage(`{"group":{"name":"new"}}`))
			if err != nil {
				t.Fatal(err)
			}
			_, err = service.ApplyMutation(plan, MutationApplyOptions{Confirm: plan.Confirmation})
			if err == nil || strings.Contains(err.Error(), "echoed-password") || requests != 1 || redirected != 0 {
				t.Fatalf("write retried/redirected/leaked: requests=%d redirected=%d err=%v", requests, redirected, err)
			}
		})
	}
}

func TestMutationSecretResponseRequiresPrivateFile(t *testing.T) {
	writes := 0
	service := mutationTestService(t, func(w http.ResponseWriter, r *http.Request) {
		writes++
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"credential":{"access":"new-key","secret":"one-time-secret"}}`)
	})
	plan, err := service.PlanMutation("credentials-create", nil, json.RawMessage(`{"credential":{"user_id":"u"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ApplyMutation(plan, MutationApplyOptions{Confirm: plan.Confirmation}); err == nil || writes != 0 {
		t.Fatal("secret created without safe output")
	}
	output := filepath.Join(t.TempDir(), "credential.json")
	result, err := service.ApplyMutation(plan, MutationApplyOptions{Confirm: plan.Confirmation, OutputPath: output})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(result)
	if err != nil || strings.Contains(string(encoded), "one-time-secret") || writes != 1 {
		t.Fatalf("secret leaked or repeated: %s %v writes=%d", encoded, err, writes)
	}
	data, err := os.ReadFile(output)
	if err != nil || !strings.Contains(string(data), "one-time-secret") {
		t.Fatalf("secret not preserved in file: %v", err)
	}
	assertPrivateFilePermissions(t, output)
}

func TestMutationSuccessfulEmptyDeleteAndMalformedResponse(t *testing.T) {
	for _, body := range []string{"", "not-json"} {
		t.Run(body, func(t *testing.T) {
			writes := 0
			service := mutationTestService(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					fmt.Fprint(w, `{"role":{"id":"p"}}`)
					return
				}
				writes++
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, body)
			})
			plan, err := service.PlanMutation("policy-delete", []string{"p"}, nil)
			if err != nil {
				t.Fatal(err)
			}
			_, err = service.ApplyMutation(plan, MutationApplyOptions{Confirm: plan.Confirmation, ExpectedHash: plan.StateHash, BackupPath: filepath.Join(t.TempDir(), "backup")})
			if writes != 1 || (body == "" && err != nil) || (body != "" && (err == nil || !strings.Contains(err.Error(), "instead of repeating"))) {
				t.Fatalf("success response behavior: writes=%d err=%v", writes, err)
			}
		})
	}
}

func TestMutationRelationSnapshotAndCatalogInvariants(t *testing.T) {
	seenNames, seenCommands := map[string]bool{}, map[string]bool{}
	for _, spec := range MutationSpecs() {
		command := strings.Join(spec.CommandPath, " ") + " " + strings.Fields(spec.Use)[0]
		if seenNames[spec.Name] || seenCommands[command] || spec.Name == "" || len(spec.SuccessCodes) == 0 {
			t.Errorf("invalid/duplicate compiled operation: %+v", spec)
		}
		seenNames[spec.Name], seenCommands[command] = true, true
		if !spec.Create && len(spec.ReadPath) == 0 {
			t.Errorf("existing-state mutation has no inspection: %s", spec.Name)
		}
		if spec.SnapshotMethod != http.MethodHead {
			continue
		}
		args := strings.Fields(spec.Use)[1:]
		for _, code := range []int{204, 404} {
			service := mutationTestService(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodHead {
					t.Errorf("relation inspected using %s", r.Method)
				}
				w.WriteHeader(code)
			})
			plan, err := service.PlanMutation(spec.Name, args, nil)
			if err != nil || plan.Current.(Record)["present"] != (code == 204) {
				t.Fatalf("HEAD relation: %s code=%d plan=%v err=%v", spec.Name, code, plan, err)
			}
		}
	}
}

func TestMutationSnapshotPresenceCannotBeSpoofedByAPIFields(t *testing.T) {
	service := mutationTestService(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatal("unexpected write")
		}
		fmt.Fprint(w, `{"identity_provider":{"id":"existing","present":false,"absent":true}}`)
	})
	if _, err := service.PlanMutation("provider.create", []string{"existing"}, json.RawMessage(`{"identity_provider":{"description":"new"}}`)); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("200 response must never mean absent: %v", err)
	}
}

func TestMutationChangedRequestNeedsNewHash(t *testing.T) {
	service := mutationTestService(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Error("changed request was applied without review")
		}
		fmt.Fprint(w, `{"group":{"name":"old"}}`)
	})
	first, err := service.PlanMutation("group-update", []string{"g"}, json.RawMessage(`{"group":{"name":"reviewed"}}`))
	if err != nil {
		t.Fatal(err)
	}
	changed, err := service.PlanMutation("group-update", []string{"g"}, json.RawMessage(`{"group":{"name":"different"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if first.StateHash == changed.StateHash {
		t.Fatal("hash does not bind proposed request")
	}
	if _, err := service.ApplyMutation(changed, MutationApplyOptions{ExpectedHash: first.StateHash, Confirm: first.Confirmation, BackupPath: filepath.Join(t.TempDir(), "backup")}); err == nil {
		t.Fatal("previously reviewed hash accepted a changed request")
	}
}

func TestMutationSnapshotErrorsNeverEchoResponse(t *testing.T) {
	service := mutationTestService(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"error":{"message":"private-signing-material"}}`)
	})
	_, err := service.PlanMutation("group-delete", []string{"g"}, nil)
	if err == nil || strings.Contains(err.Error(), "private-signing-material") || !strings.Contains(err.Error(), "403") {
		t.Fatalf("snapshot error not safe/useful: %v", err)
	}
}
