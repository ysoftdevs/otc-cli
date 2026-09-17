package iam

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	golangsdk "github.com/opentelekomcloud/gophertelekomcloud"
)

// MutationSpec describes one documented operation. Paths and methods come from
// this compiled catalog, never from a user-supplied URL or arbitrary method.
type MutationSpec struct {
	Name              string
	CommandPath       []string
	Use               string
	Short             string
	Method            string
	Version           string
	Path              []string
	BodyKey           string
	RequiredFields    []string
	ValidateBody      func(Record) error
	Preflight         func(*Service, []string) error
	ReadVersion       string
	ReadPath          []string
	ReadKey           string
	SnapshotMethod    string
	ResponseKey       string
	SuccessCodes      []int
	SensitiveResponse bool
	Create            bool
	AllowMissing      bool
	Risk              string
}

// MutationSpecs returns the supported management operations for CLI discovery.
func MutationSpecs() []MutationSpec {
	var specs []MutationSpec
	specs = append(specs, inventoryMutationSpecs()...)
	specs = append(specs, securityMutationSpecs()...)
	specs = append(specs, federationMutationSpecs()...)
	return specs
}

func mutationSpec(name string) (MutationSpec, error) {
	for _, spec := range MutationSpecs() {
		if spec.Name == name {
			return spec, nil
		}
	}
	return MutationSpec{}, fmt.Errorf("unknown IAM management operation %q", name)
}

// ValidateMutationInput validates arguments and JSON before authentication.
// It does not contact OTC or interpret an arbitrary API request.
func ValidateMutationInput(name string, args []string, body json.RawMessage) error {
	spec, err := mutationSpec(name)
	if err != nil {
		return err
	}
	if len(args) != len(strings.Fields(spec.Use))-1 {
		return fmt.Errorf("expected arguments: %s", spec.Use)
	}
	for _, arg := range args {
		if err := ValidateID("resource ID", arg); err != nil {
			return err
		}
	}
	if spec.BodyKey == "" {
		if len(body) != 0 {
			return fmt.Errorf("this operation does not accept a JSON request body")
		}
		return nil
	}
	if len(body) == 0 || len(body) > 2<<20 {
		return fmt.Errorf("request JSON must be non-empty and at most 2 MiB")
	}
	var envelope Record
	if err := decode(body, &envelope); err != nil || envelope == nil {
		return fmt.Errorf("request must be one valid JSON object without duplicate members")
	}
	object := envelope
	if spec.BodyKey != "@root" {
		var ok bool
		object, ok = envelope[spec.BodyKey].(map[string]any)
		if !ok || len(envelope) != 1 {
			return fmt.Errorf("request must contain only a %s object", spec.BodyKey)
		}
	}
	if len(object) == 0 {
		return fmt.Errorf("request object must not be empty")
	}
	for _, field := range spec.RequiredFields {
		value, exists := object[field]
		if !exists || value == nil || value == "" {
			return fmt.Errorf("request requires field %s", field)
		}
	}
	if spec.ValidateBody != nil {
		return spec.ValidateBody(object)
	}
	return nil
}

// MutationPlan is a preview. Sensitive request values are excluded from its
// exported representation. Private fields bind application to this live plan.
type MutationPlan struct {
	Operation    string `json:"operation"`
	AccountID    string `json:"account_id"`
	Method       string `json:"method"`
	Path         string `json:"path"`
	StateHash    string `json:"state_hash"`
	Current      any    `json:"current"`
	Proposed     any    `json:"proposed"`
	Risk         string `json:"risk,omitempty"`
	NeedsBackup  bool   `json:"needs_backup"`
	NeedsOutput  bool   `json:"needs_private_output"`
	Confirmation string `json:"confirmation"`
	Atomic       bool   `json:"atomic_compare_and_swap"`
	args         []string
	body         json.RawMessage
	snapshot     json.RawMessage
}

// MutationApplyOptions makes every safeguard explicit. ExpectedHash comes from
// a previously reviewed plan; BackupPath and OutputPath must not already exist.
type MutationApplyOptions struct {
	ExpectedHash string
	BackupPath   string
	OutputPath   string
	Confirm      string
}

// PlanMutation reads current state and prepares a redacted preview. No IAM
// configuration writes are made. Token issuance during authentication is separate.
func (s *Service) PlanMutation(name string, args []string, body json.RawMessage) (MutationPlan, error) {
	if err := ValidateMutationInput(name, args, body); err != nil {
		return MutationPlan{}, err
	}
	spec, err := mutationSpec(name)
	if err != nil {
		return MutationPlan{}, err
	}
	if spec.Preflight != nil {
		if err := spec.Preflight(s, args); err != nil {
			return MutationPlan{}, err
		}
	}
	parts, err := mutationParts(spec.Path, args)
	if err != nil {
		return MutationPlan{}, err
	}
	endpoint, err := s.versionEndpoint(spec.Version, parts...)
	if err != nil {
		return MutationPlan{}, err
	}
	account := s.client.DomainID
	if account == "" {
		account = s.client.AKSKOptions().DomainID
	}
	if account == "" {
		return MutationPlan{}, fmt.Errorf("cannot establish the authenticated IAM account for a management plan")
	}
	current, err := s.mutationSnapshot(spec, args)
	if err != nil {
		return MutationPlan{}, err
	}
	if spec.Create && len(spec.ReadPath) > 0 && current["present"] != false {
		return MutationPlan{}, fmt.Errorf("resource already exists; use its update operation")
	}
	snapshot, err := json.Marshal(current)
	if err != nil {
		return MutationPlan{}, fmt.Errorf("encode IAM snapshot: %w", err)
	}
	var proposed any
	if len(body) > 0 {
		if err := decode(body, &proposed); err != nil {
			return MutationPlan{}, err
		}
	}
	// Bind both the inspected state and the proposed JSON. Editing --file
	// after review must require a new preview, even if remote state is stable.
	bound, err := json.Marshal([]any{account, endpoint.String(), spec.Name, current, proposed})
	if err != nil {
		return MutationPlan{}, fmt.Errorf("encode IAM state hash: %w", err)
	}
	digest := sha256.Sum256(bound)
	return MutationPlan{
		Operation: name, AccountID: account, Method: spec.Method, Path: endpoint.Path,
		StateHash: hex.EncodeToString(digest[:]), Current: redactMutation(current),
		Proposed: redactMutation(proposed), Risk: spec.Risk,
		NeedsBackup: !spec.Create, NeedsOutput: spec.SensitiveResponse,
		Confirmation: endpoint.Path, Atomic: false,
		args: append([]string(nil), args...), body: append(json.RawMessage(nil), body...), snapshot: snapshot,
	}, nil
}

func mutationParts(template, args []string) ([]string, error) {
	parts := make([]string, len(template))
	for i, part := range template {
		if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
			index, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(part, "{"), "}"))
			if err != nil || index < 0 || index >= len(args) {
				return nil, fmt.Errorf("invalid compiled IAM operation path")
			}
			part = args[index]
		}
		if err := ValidateID("resource ID", part); err != nil {
			return nil, err
		}
		parts[i] = part
	}
	return parts, nil
}

func (s *Service) mutationClient() *golangsdk.ServiceClient {
	provider := &golangsdk.ProviderClient{
		TokenID: s.client.Token(), AKSKAuthOptions: s.client.AKSKOptions(),
		HTTPClient: s.client.HTTPClient, UserAgent: s.client.UserAgent,
		MaxBackoffRetries: new(int), DomainID: s.client.DomainID,
	}
	provider.HTTPClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &golangsdk.ServiceClient{ProviderClient: provider, Endpoint: s.client.Endpoint}
}

func (s *Service) mutationSnapshot(spec MutationSpec, args []string) (Record, error) {
	if len(spec.ReadPath) == 0 {
		if !spec.Create {
			return nil, fmt.Errorf("operation has no documented state inspection; refusing an unreviewable write")
		}
		return Record{"new_resource": true}, nil
	}
	parts, err := mutationParts(spec.ReadPath, args)
	if err != nil {
		return nil, err
	}
	endpoint, err := s.versionEndpoint(spec.ReadVersion, parts...)
	if err != nil {
		return nil, err
	}
	method := spec.SnapshotMethod
	if method == "" {
		method = http.MethodGet
	}
	codes := []int{http.StatusOK}
	if method == http.MethodHead {
		codes = []int{http.StatusNoContent, http.StatusNotFound}
	} else if spec.Create || spec.AllowMissing {
		codes = append(codes, http.StatusNotFound)
	}
	response, err := s.mutationClient().Request(method, endpoint.String(), &golangsdk.RequestOpts{OkCodes: codes, RetryCount: new(int)})
	if err != nil {
		status := 0
		if response != nil {
			status = response.StatusCode
		}
		return nil, fmt.Errorf("cannot inspect current IAM resource (HTTP %d); no write performed", status)
	}
	defer response.Body.Close()
	if method == http.MethodHead {
		return Record{"present": response.StatusCode == http.StatusNoContent}, nil
	}
	if response.StatusCode == http.StatusNotFound {
		return Record{"present": false}, nil
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, (16<<20)+1))
	if err != nil || len(data) > 16<<20 {
		return nil, fmt.Errorf("could not read a complete bounded IAM snapshot")
	}
	var envelope Record
	if err := decode(data, &envelope); err != nil || envelope == nil {
		return nil, fmt.Errorf("current IAM state is not a valid JSON object")
	}
	if spec.ReadKey == "" {
		return Record{"present": true, "resource": envelope}, nil
	}
	record, ok := envelope[spec.ReadKey].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("current IAM state is missing its %s object", spec.ReadKey)
	}
	return Record{"present": true, "resource": record}, nil
}

// ApplyMutation re-reads the resource and rejects stale plans before any write.
// OTC does not provide atomic conditional updates for these endpoints: another
// administrator can still act between this check and the request.
func (s *Service) ApplyMutation(plan MutationPlan, options MutationApplyOptions) (Record, error) {
	if plan.snapshot == nil {
		return nil, fmt.Errorf("management operation requires a plan created by this IAM service")
	}
	fresh, err := s.PlanMutation(plan.Operation, plan.args, plan.body)
	if err != nil {
		return nil, err
	}
	if fresh.AccountID != plan.AccountID || fresh.Path != plan.Path || fresh.StateHash != plan.StateHash {
		return nil, fmt.Errorf("IAM state changed after planning; review a new plan")
	}
	spec, err := mutationSpec(plan.Operation)
	if err != nil {
		return nil, err
	}
	if !spec.Create && (options.ExpectedHash == "" || options.ExpectedHash != fresh.StateHash) {
		return nil, fmt.Errorf("--expected-hash must match the reviewed state and request for this account and resource")
	}
	if options.Confirm != fresh.Confirmation {
		return nil, fmt.Errorf("--confirm must exactly match the plan's confirmation path")
	}
	if fresh.NeedsBackup && options.BackupPath == "" {
		return nil, fmt.Errorf("--backup is required before modifying existing IAM state")
	}
	if fresh.NeedsOutput && options.OutputPath == "" {
		return nil, fmt.Errorf("this operation returns credentials; --output is required for a private file")
	}
	if options.BackupPath != "" {
		backup, err := json.MarshalIndent(Record{"account_id": fresh.AccountID, "operation": fresh.Operation,
			"path": fresh.Path, "state_hash": fresh.StateHash, "current": json.RawMessage(fresh.snapshot)}, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("encode backup: %w", err)
		}
		if err := writePrivateExclusive(options.BackupPath, backup); err != nil {
			return nil, err
		}
	}
	var output *os.File
	if options.OutputPath != "" {
		output, err = createPrivateFile(options.OutputPath)
		if err != nil {
			return nil, fmt.Errorf("reserve private response file: %w", err)
		}
		defer output.Close()
	}
	parts, err := mutationParts(spec.Path, plan.args)
	if err != nil {
		return nil, err
	}
	endpoint, err := s.versionEndpoint(spec.Version, parts...)
	if err != nil {
		return nil, err
	}
	request := &golangsdk.RequestOpts{OkCodes: spec.SuccessCodes, RetryCount: new(int)}
	if len(plan.body) > 0 {
		request.JSONBody = plan.body
	}
	response, err := s.mutationClient().Request(spec.Method, endpoint.String(), request)
	if err != nil {
		status := 0
		if response != nil {
			status = response.StatusCode
		}
		// SDK errors may embed an echoed request with passwords or MFA codes.
		// Return only the operation/status, never its response body or headers.
		return nil, fmt.Errorf("IAM %s did not return confirmed success (HTTP %d); inspect current state before retrying", spec.Name, status)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, (16<<20)+1))
	if err != nil || len(data) > 16<<20 {
		return nil, fmt.Errorf("IAM returned success but its response could not be read completely; do not repeat the write")
	}
	if output != nil {
		if _, err := output.Write(data); err != nil {
			return nil, fmt.Errorf("IAM returned success but saving the private response failed: %w; do not repeat the write", err)
		}
		if err := output.Sync(); err != nil {
			return nil, fmt.Errorf("IAM returned success but syncing the private response failed: %w; do not repeat the write", err)
		}
	}
	result := Record{"operation": spec.Name, "status": "completed", "http_status": response.StatusCode,
		"account_id": fresh.AccountID, "path": fresh.Path}
	if output != nil {
		result["response_file"] = options.OutputPath
	}
	if len(data) > 0 {
		var value Record
		if err := decode(data, &value); err != nil || value == nil {
			return nil, fmt.Errorf("IAM returned success but its response is invalid JSON; inspect current state instead of repeating the write")
		}
		if spec.ResponseKey != "" {
			if _, ok := value[spec.ResponseKey].(map[string]any); !ok {
				return nil, fmt.Errorf("IAM returned success but its response is missing %s; inspect current state instead of repeating the write", spec.ResponseKey)
			}
		}
		if !spec.SensitiveResponse {
			result["response"] = redactMutation(value)
		}
	} else if spec.ResponseKey != "" {
		return nil, fmt.Errorf("IAM returned success but an expected response is empty; inspect current state instead of repeating the write")
	}
	return result, nil
}

func writePrivateExclusive(path string, data []byte) error {
	file, err := createPrivateFile(path)
	if err != nil {
		return fmt.Errorf("create private backup without overwriting: %w", err)
	}
	defer file.Close()
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("write IAM backup: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync IAM backup: %w", err)
	}
	return nil
}

func redactMutation(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		out := make(Record, len(typed))
		for key, item := range typed {
			if strings.EqualFold(key, "signing_key") {
				out[key] = redactMutationSigningKey(item)
			} else if sensitiveMutationField(key) {
				out[key] = "<redacted>"
			} else {
				out[key] = redactMutation(item)
			}
		}
		return out
	case Record:
		return redactMutation(map[string]any(typed))
	case []any:
		out := make([]any, len(typed))
		for i, item := range typed {
			out[i] = redactMutation(item)
		}
		return out
	default:
		return typed
	}
}

func sensitiveMutationField(key string) bool {
	name := strings.ToLower(key)
	// Policy settings such as minimum_password_length and manage_password
	// are reviewable configuration, not credential values.
	switch name {
	case "password", "original_password", "old_password", "new_password", "admin_password", "password_hash", "encrypted_password":
		return true
	}
	for _, fragment := range []string{"secret", "passcode", "verification_code", "authentication_code", "auth_code", "totp", "seed"} {
		if strings.Contains(name, fragment) {
			return true
		}
	}
	return name == "token" || strings.HasSuffix(name, "_token") || name == "otp" || name == "sk" || name == "code" || name == "d" || name == "p" || name == "q" || name == "dp" || name == "dq" || name == "qi" || name == "k"
}
