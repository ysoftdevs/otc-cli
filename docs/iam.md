# IAM inspection and management

`otc iam` reads account authorization, federation, project and security
configuration using the selected cloud's existing credentials and permissions.
Inspection commands are read-only. Management commands preview a change by
default and require explicit apply flags before changing IAM resources.

## Authentication and output

IAM administration uses an account (domain) scoped bearer token. When the
selected profile contains a project token, IAM commands inspect it and exchange
it for an account token in memory. The scope comes from the project's account,
which can differ from a federated user's home account. This uses existing
permissions and does not grant additional access. The cached project token in
`clouds.yaml` remains unchanged.

`iam catalog list` uses the original project token in a separate client. A
profile containing only an account token cannot provide this project catalog.
AK/SK authentication continues to use signed requests.

All commands support `--cloud NAME` and `--format table|json|yaml`. Table output
summarizes lists and displays each field for detail commands. JSON and YAML
preserve complete returned policy documents and mapping rules, including
conditions, resources and extension fields. Detail commands such as `show`
return a one-element array in JSON/YAML. Credential and MFA results deliberately
contain only metadata; secret keys and MFA seeds are excluded.

Use `otc whoami --cloud NAME` to identify the selected account and project. IDs
come from API responses; the CLI does not resolve display names to IDs. A
provider ID can itself be a name. `--name` filters the API's exact `name`, which
can differ from a role's `display_name`. The IAM `--project-id` flag selects a
resource or grant scope; global `--project` selects the authentication project
by name. Help and invalid arguments are handled before authentication.

## Inspection command map

Prefix every command below with `otc`. Square brackets indicate optional flags;
uppercase identifiers are placeholders.

### Users, groups and policies

| Command | Output |
| --- | --- |
| `iam users list [--domain-id ID] [--name NAME]` | Persistent IAM users |
| `iam users show USER_ID` | User details |
| `iam users groups USER_ID` | Persistent group memberships |
| `iam users projects USER_ID` | Projects accessible to an IAM user |
| `iam groups list [--domain-id ID] [--name NAME]` | Groups |
| `iam groups show GROUP_ID` | Group details |
| `iam groups users GROUP_ID` | Persistent IAM members |
| `iam groups roles GROUP_ID SCOPE_FLAGS` | Grants in one explicit scope; see below |
| `iam roles list [--domain-id ID] [--name NAME]` | System permissions by default; account custom policies with `--domain-id` |
| `iam roles show ROLE_ID` | Role metadata and complete policy document |

### Federation

| Command | Output |
| --- | --- |
| `iam providers list` | Federation identity providers |
| `iam providers show PROVIDER_ID` | Provider configuration, including enabled state |
| `iam providers protocols PROVIDER_ID` | Protocol IDs and mapping IDs |
| `iam providers oidc show PROVIDER_ID` | Stored OIDC configuration and public signing keys |
| `iam providers oidc check PROVIDER_ID` | Comparison with the issuer's public discovery and JWKS |
| `iam protocols show PROVIDER_ID PROTOCOL_ID` | One protocol-to-mapping binding |
| `iam protocols metadata PROVIDER_ID PROTOCOL_ID` | Imported SAML IdP metadata and its XML `data` field |
| `iam protocols sp-metadata` | Regional Keystone service-provider metadata XML in `data` |
| `iam mappings list` | Federation mappings |
| `iam mappings show MAPPING_ID` | Complete claim conversion rules |

### Projects, service registrations and account grants

| Command | Output |
| --- | --- |
| `iam regions list` | Regions visible to the current identity |
| `iam regions show REGION_ID` | Region details |
| `iam projects list [--domain-id ID] [--name NAME] [--parent-id ID] [--enabled=BOOL] [--is-domain=BOOL]` | Projects matching the supplied filters |
| `iam projects show PROJECT_ID` | Project details |
| `iam projects status PROJECT_ID` | Project details including suspension status |
| `iam projects accessible` | Projects accessible to the current identity |
| `iam projects quotas PROJECT_ID` | IAM quotas for the project |
| `iam domains accessible` | Accounts accessible to the current identity |
| `iam domains quotas DOMAIN_ID [--type TYPE]` | IAM quotas; type is `user`, `group`, `idp`, `agency` or `policy` |
| `iam services list [--type TYPE]` | Service registrations, optionally filtered by service type |
| `iam services show SERVICE_ID` | Service registration details |
| `iam endpoints list [--service-id ID] [--interface INTERFACE]` | Endpoint registrations; interface is `public`, `internal` or `admin` |
| `iam endpoints show ENDPOINT_ID` | Endpoint registration details |
| `iam catalog list` | Service catalog for the original project credentials |
| `iam agencies list --domain-id ID [--name NAME] [--trust-domain-id ID]` | Agencies in the account |
| `iam agencies show AGENCY_ID` | Agency trust and lifetime details |
| `iam agencies roles AGENCY_ID SCOPE_FLAGS` | Agency grants in one explicit scope |
| `iam assignments list --domain-id ID [FILTERS]` | Account permission assignment records; filters below |
| `iam versions show` | Identity API v3 version information |

Omitting `--enabled` or `--is-domain` leaves that project filter unset. Use
`--enabled=false` explicitly to query disabled projects.

### Credentials and security settings

| Command | Output |
| --- | --- |
| `iam credentials list [--user-id ID]` | Permanent access-key metadata; defaults to the caller's keys |
| `iam credentials show ACCESS_KEY` | Key metadata, including `create_time` and `last_use_time` when returned |
| `iam mfa list` | Virtual MFA device assignments |
| `iam mfa show USER_ID` | One user's virtual MFA assignment |
| `iam login-protection list` | Users whose login protection was configured |
| `iam login-protection show USER_ID` | One user's login verification settings |
| `iam security password-policy DOMAIN_ID` | Password requirements |
| `iam security login-policy DOMAIN_ID` | Login authentication policy |
| `iam security protect-policy DOMAIN_ID` | Operation protection policy |
| `iam security api-acl-policy DOMAIN_ID` | Source IP restrictions for API access |
| `iam security console-acl-policy DOMAIN_ID` | Source IP restrictions for console access |

The key detail API documents `last_use_time`; the key list API does not promise
it. This timestamp concerns the permanent access key, not federation-provider
usage. Inspecting another user's keys requires the corresponding IAM permission.
See [OTC access-key response fields](https://docs.otc.t-systems.com/identity-access-management/iam-api-ref.pdf#page=58).

Login-protection lists include only configured users. An absent user is not an
explicitly disabled configuration; the detail API returns not found when the
setting was never configured.

## Review grants in an explicit scope

For `groups roles` and `agencies roles`, choose exactly one:

| Scope flags | Meaning |
| --- | --- |
| `--domain-id DOMAIN_ID` | Direct account/domain grants |
| `--project-id PROJECT_ID` | Direct grants in one project |
| `--domain-id DOMAIN_ID --all-projects` | Grants inherited by all projects |

```bash
otc iam groups list --cloud devOIDC
otc iam groups roles GROUP_ID --domain-id DOMAIN_ID --cloud devOIDC
otc iam groups roles GROUP_ID --project-id PROJECT_ID --cloud devOIDC
otc iam groups roles GROUP_ID --domain-id DOMAIN_ID --all-projects --cloud devOIDC
otc iam roles show ROLE_ID --cloud devOIDC --format json
```

`roles list` without a domain and with a domain are separate views of system
permissions and account custom policies. Run both when reviewing both kinds.

### Assignment filters

`iam assignments list` requires `--domain-id DOMAIN_ID` for the account being
queried. Optional filters are:

| Flag | Meaning and constraints |
| --- | --- |
| `--role-id ROLE_ID` | Limit records to one policy/role |
| `--subject user\|group\|agency` | Filter by subject type |
| `--user-id USER_ID`, `--group-id GROUP_ID`, `--agency-id AGENCY_ID` | Filter by one subject ID; use at most one of these or `--subject` |
| `--scope project\|domain\|enterprise_project` | Filter by scope type |
| `--project-id PROJECT_ID`, `--scope-domain-id DOMAIN_ID` | Filter by one scope ID; use at most one of these or `--scope` |
| `--is-inherited=true\|false` | Select all-project inheritance; requires `--scope domain` or `--scope-domain-id` |
| `--include-group=true\|false` | Include group grants for a user; requires `--subject user` or `--user-id` |

An omitted boolean leaves the API default in effect: inheritance defaults to
false and group inclusion to true. There is no enterprise-project ID filter in
this CLI; `--scope enterprise_project` selects that scope type.

```bash
otc iam assignments list --domain-id DOMAIN_ID --cloud devOIDC --format json
otc iam assignments list --domain-id DOMAIN_ID --user-id USER_ID --include-group=true --cloud devOIDC
otc iam assignments list --domain-id DOMAIN_ID --scope domain --is-inherited=true --cloud devOIDC
otc iam agencies list --domain-id DOMAIN_ID --cloud devOIDC
otc iam agencies roles AGENCY_ID --domain-id DOMAIN_ID --all-projects --cloud devOIDC
otc iam projects accessible --cloud devOIDC
otc iam catalog list --cloud devOIDC --format json
```

These are assignment records. The CLI does not evaluate conditions or calculate
effective access to a particular resource across all grants and resource
policies. Persistent membership lists also do not enumerate all virtual
federated users. Entra group membership and app-role assignments require
separate inspection in Entra.

## Trace federation configuration

Follow the provider's protocol response to obtain its mapping ID:

```bash
otc iam providers list --cloud devOIDC
otc iam providers show YS_OIDC_EID_DEV --cloud devOIDC
otc iam providers protocols YS_OIDC_EID_DEV --cloud devOIDC
otc iam protocols show YS_OIDC_EID_DEV oidc --cloud devOIDC
otc iam mappings show MAPPING_ID --cloud devOIDC --format yaml
otc iam providers oidc show YS_OIDC_EID_DEV --cloud devOIDC --format json
otc iam providers oidc check YS_OIDC_EID_DEV --cloud devOIDC
```

Use the actual protocol ID returned by the API, such as `oidc` or `saml`.
Provider and mapping IDs are distinct. `sso_type` describes virtual-user versus
persistent IAM-user federation; the protocol binding identifies OIDC or SAML.

### What an OIDC check proves

The check compares the stored issuer with public discovery, then compares key
IDs (`kid`), public key material and supported key metadata with the published
JWKS. It prints results and exits nonzero for differences or unavailable
evidence. A key stored only in OTC is informational because rotation can retain
older keys for overlap. Malformed keys and private or symmetric key material
are rejected without printing their values.

A match establishes agreement between these configuration documents. It does
not validate a token signature, audience, claims mapping, provider enablement,
successful login or effective permissions. The check does not update keys.

### Provider age and actual use

The documented provider read response exposes configuration and enabled state,
but no creation timestamp or last-use timestamp. An enabled provider is not
evidence of recent use; a disabled provider does not establish when it was last
used. See [OTC identity-provider response fields](https://docs.otc.t-systems.com/identity-access-management/iam-api-ref.pdf#page=323).

Creation/change history and login evidence belong to Cloud Trace Service (CTS),
which this IAM command group does not query. CTS's searchable trace history
covers the last seven days. Older evidence requires traces that were previously
transferred and retained, for example in OBS. Missing events cannot establish
that a provider was never used. See the [CTS trace and archive guide](https://docs.otc.t-systems.com/cloud-trace-service/cts-umn.pdf).

## Management commands

Management commands print a redacted preview unless `--apply` is supplied. A
preview includes the account, API path, current state, proposed request, known
risks, `state_hash` and `confirmation` path. It can make authenticated reads but
does not modify IAM configuration. Token issuance during authentication is a
separate operation.

Requests with a body require `--file request.json` or `--file -` for standard
input. Supply one JSON object with the envelope shown below; inspection output
is an array and cannot be passed directly as a mutation request. Request files
are limited to 2 MiB. Duplicate JSON members, invalid field types and unsupported
fields fail validation before authentication. Keep files containing passwords
private and avoid placing passwords in command-line arguments.

### Preview and apply an update

For example, prepare `group-update.json` with:

```json
{"group":{"description":"Reviewed description"}}
```

Then preview the exact group and request:

```bash
otc iam groups update GROUP_ID --file group-update.json --cloud devOIDC --format json
```

Review `current`, `proposed`, `account_id`, `risk`, `state_hash` and
`confirmation`. Copy the returned hash and confirmation path into the apply
command; use a backup path that does not exist:

```bash
otc iam groups update GROUP_ID --file group-update.json --cloud devOIDC \
  --apply --expected-hash HASH_FROM_PREVIEW \
  --confirm /v3/groups/GROUP_ID --backup group-before.json
```

Use the preview's exact path, including any configured endpoint prefix. The
CLI reads state again and refuses a changed hash. The hash binds the account,
endpoint, operation, current state and proposed JSON. Review a new preview after
changing the request file or when the resource has changed. Successful resource
snapshots use `{"present":true,"resource":{...}}`; an explicit API 404 uses
`{"present":false}`.

| Flag | Requirement |
| --- | --- |
| `--file PATH` | Required for commands with a JSON body; `-` reads stdin |
| `--apply` | Enables the write; omitted means preview only |
| `--confirm PATH` | Required for every apply; must exactly match the preview's confirmation path |
| `--expected-hash HASH` | Required for updates, deletes and membership/grant changes; use the reviewed state hash |
| `--backup PATH` | Required with existing-state changes; writes the current snapshot to a new private file |
| `--output PATH` | Required when creating access keys or MFA devices; saves the raw secret-bearing response to a new private file |

Apply-only flags are rejected without `--apply`. Backups and output files are
created exclusively, with mode `0600` on Unix, and never overwrite an existing
file. A required output file is reserved before sending the write. New
credentials and MFA seeds are saved there rather than printed to the terminal.

Creation operations require `--confirm` and any required `--output`, but do not
require `--expected-hash` or `--backup`. Where the new resource has a caller-chosen
ID, its preview verifies absence. For server-assigned IDs, such as new users,
keys or agencies, the preview describes a new resource without claiming to
snapshot a resource that does not yet exist.

### Account resources and authorization

Prefix these commands with `otc`; add `--file` only where a body is listed.
Each action separated by a slash below is a separate command.

| Command | Request body |
| --- | --- |
| `iam users create` | `user` object; requires `name` and `domain_id` |
| `iam users update USER_ID` | `user` object with profile or login settings |
| `iam users delete USER_ID` | None |
| `iam users change-password USER_ID` | `user` object; requires `password` and `original_password` |
| `iam groups create` | `group` object; requires `name` |
| `iam groups update GROUP_ID` | `group` object |
| `iam groups delete GROUP_ID` | None |
| `iam groups add-user/remove-user GROUP_ID USER_ID` | None |
| `iam groups grant-domain/revoke-domain GROUP_ID DOMAIN_ID ROLE_ID` | None |
| `iam groups grant-project/revoke-project GROUP_ID PROJECT_ID ROLE_ID` | None |
| `iam groups grant-inherited/revoke-inherited GROUP_ID DOMAIN_ID ROLE_ID` | None |
| `iam projects create` | `project` object; requires `name` and `parent_id` |
| `iam projects update PROJECT_ID` | `project` object with name or description |
| `iam projects set-status PROJECT_ID` | `project` object with `status`: `normal` or `suspended` |
| `iam projects delete PROJECT_ID` | None |
| `iam agencies create` | `agency` object; requires `name` and `domain_id` |
| `iam agencies update AGENCY_ID` | `agency` object with trust or description settings |
| `iam agencies delete AGENCY_ID` | None |
| `iam agencies grant-domain/revoke-domain AGENCY_ID DOMAIN_ID ROLE_ID` | None |
| `iam agencies grant-project/revoke-project AGENCY_ID PROJECT_ID ROLE_ID` | None |
| `iam agencies grant-inherited/revoke-inherited AGENCY_ID DOMAIN_ID ROLE_ID` | None |
| `iam policies create` | `role` object; requires `display_name`, `type`, `description` and `policy` |
| `iam policies update POLICY_ID` | Complete `role` object with the same required fields |
| `iam policies delete POLICY_ID` | None |

Membership and grant commands snapshot the exact relationship using its
documented HEAD endpoint. They still require a reviewed state hash and backup.
Granting inherited permissions affects all projects in the account. Changes to
a custom policy affect every assignment that references it.

### Federation management

| Command | Request body |
| --- | --- |
| `iam providers create PROVIDER_ID` | `identity_provider` object for SAML federation |
| `iam providers update PROVIDER_ID` | `identity_provider` object for SAML provider settings |
| `iam providers delete PROVIDER_ID` | None; dependency checks apply |
| `iam providers oidc create PROVIDER_ID` | `openid_connect_config` object; requires `access_mode`, `idp_url`, `client_id` and `signing_key` |
| `iam providers oidc update PROVIDER_ID` | `openid_connect_config` object with the requested changes |
| `iam mappings create/update MAPPING_ID` | `mapping` object with complete `rules` |
| `iam mappings delete MAPPING_ID` | None |
| `iam protocols create/update PROVIDER_ID PROTOCOL_ID` | `protocol` object with `mapping_id` |
| `iam protocols delete PROVIDER_ID PROTOCOL_ID` | None |
| `iam protocols import-metadata PROVIDER_ID PROTOCOL_ID` | Bare object with `domain_id`, `xaccount_type` and `metadata` XML; requires metadata to be absent |
| `iam protocols update-metadata PROVIDER_ID PROTOCOL_ID` | Bare object with `domain_id`, `xaccount_type` and replacement `metadata` XML |

Mapping updates replace the complete rule set. Preserve every rule that is
still required when preparing the request. OIDC updates can change trust and
signing keys for every client using that provider. Preview a proposed update
with:

```bash
otc iam providers oidc update YS_OIDC_EID_DEV --file oidc-update.json --cloud devOIDC --format json
```

The separate `providers oidc check` command remains a read-only public-key
comparison. It does not apply or validate a proposed update file. Provider
deletion is blocked while protocol bindings, OIDC configuration or SAML metadata
remain, or while their absence cannot be established. A provider-only snapshot
would not preserve those dependencies.

Mapping deletion is blocked while any provider protocol references it, or if
the complete provider/protocol inventory cannot be read. Metadata import and
update require `xaccount_type`; an empty string selects the documented default.

### Credential and security management

| Command | Request body |
| --- | --- |
| `iam credentials create` | `credential` object with `user_id` and optional `description`; requires private `--output` on apply |
| `iam credentials update ACCESS_KEY` | `credential` object with `status` (`active` or `inactive`) and/or `description` |
| `iam credentials delete ACCESS_KEY` | None |
| `iam mfa create` | `virtual_mfa_device` object with `name` and `user_id`; authenticated user only; requires private `--output` on apply |
| `iam login-protection update USER_ID` | `login_protect` object with boolean `enabled` and `verification_method`: `sms`, `email` or `vmfa` |
| `iam security set-password-policy DOMAIN_ID` | `password_policy` object with documented password requirements |
| `iam security set-login-policy DOMAIN_ID` | `login_policy` object with login and lockout settings |
| `iam security set-protect-policy DOMAIN_ID` | `protect_policy` object; requires boolean `operation_protection` |
| `iam security set-api-acl-policy DOMAIN_ID` | `api_acl_policy` object with both `allow_address_netmasks` and `allow_ip_ranges` arrays |
| `iam security set-console-acl-policy DOMAIN_ID` | `console_acl_policy` object with both allowlist arrays |

The CLI validates documented numeric policy ranges, boolean values, verifier
requirements, IPv4 CIDRs and ordered IPv4 ranges. Read-only fields from policy
responses are not accepted as update fields. An ACL update can lock users or
automation out; a syntactically valid list does not establish that it permits
your current source IP.

Login protection can be configured for a user whose previous setting is absent;
the preview and backup preserve that absence. MFA creation returns a seed but
does not bind it. MFA binding, unbinding and deletion are not implemented in this
batch: their body/query selectors need dedicated snapshot handling. No command
retrieves an existing access-key secret or MFA seed.

### Backup and concurrency limits

A backup records the inspected object or relationship before a change. It is
not a complete rollback: it cannot recreate a deleted resource's original ID,
secret keys, old passwords or related grants, memberships and federation
objects that were not part of that snapshot. The CLI does not automatically
restore a backup.

OTC does not provide an atomic compare-and-swap for these operations. Another
administrator can change state between the final read and the write. The
reported hash detects observed changes but cannot close that interval. On a
failed or uncertain write, inspect current state before deciding whether to
try again; an interrupted response can follow a successful change.

## Request handling and implementation

IAM transport guards are installed before authentication. Requests and
redirects stay on the configured endpoint's scheme, host and port, under its
`v3`, `v3.0` or `v3-ext` roots. A 30-second timeout applies to each IAM request;
pagination can make a command take longer. JSON responses are capped at 16 MiB
and standalone service-provider XML at 2 MiB. Malformed responses fail with an
error. Normal reads and the account-token exchange disable SDK retries. Initial
password or AK/SK authentication still uses the SDK's one retry on HTTP 502/504;
rate-limit backoff retries are disabled.

Management writes disable redirects and retries, including SDK
reauthentication. Error output suppresses API response bodies that might echo
passwords or other credential material. Writes use only the compiled operation
catalog; the CLI does not expose an arbitrary authenticated HTTP request.

OIDC public discovery uses a separate client without OTC credentials. It allows
public HTTPS destinations, rejects private/local destinations including DNS
results, and applies a 10-second request timeout and 1 MiB document limit.

List commands follow supported API pagination and fail the whole request if a
later page fails. Assignment queries follow numbered pages and verify the
reported total, rejecting changed counts, incomplete results and repeated
records. Pagination is not an atomic snapshot: concurrent changes can still
affect what the server returns. IAM permission failures remain errors; access to
ECS or CCE does not imply permission to inspect IAM resources.

The service layer is in [`services/iam`](../services/iam/). Command registration
and validation are in [`cmd/iam.go`](../cmd/iam.go) and its federation, inventory
and security files. [`cmd/iam_views.go`](../cmd/iam_views.go) controls table
presentation. Raw JSON records preserve policy and mapping fields that the
pinned SDK's narrower models would omit.

Endpoints follow the [OTC IAM API reference](https://docs.otc.t-systems.com/identity-access-management/iam-api-ref.pdf).
In particular, assignments use `/v3.0/OS-PERMISSION/role-assignments`, and
agencies, credential metadata and security settings use OTC's v3.0 extensions.

## Validation

HTTP fixtures cover endpoint paths, filters, pagination, policy preservation,
token scoping, response limits and rejection of unsafe redirects. Constructor
tests cover cached tokens, passwords and signed AK/SK requests. CLI tests cover
validation before authentication and output formatting. OIDC fixtures exercise
key comparisons and restrictions on public metadata requests.

DEV smoke verification on 2026-09-17 completed 35 checks: 34 reads across users,
groups, projects, account assignments, agencies, service catalog/registrations,
MFA, login protection and all five security policies, plus one group-update
preview without `--apply`. OIDC inspection found six
matching published keys; SAML and service-provider metadata reads also passed.
The run left `clouds.yaml` unchanged. This was a subset of the 50 inspection commands:
permanent-key listing returned no keys for the inspected user, so key-detail
and last-use output were tested with fixtures, not live credentials.

Management validation uses local HTTP fixtures and command tests. No IAM
configuration write was performed against a live account during this work.

The implementation has 50 inspection and 54 management commands. The full
`go test -race ./...` suite, `go vet ./...` and Staticcheck passed. Govulncheck
found no reachable vulnerabilities; 10 advisories remain in existing dependencies
whose affected code is not reported as called by this CLI. Dependencies were not
upgraded as part of this change.
