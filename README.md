# OTC CLI

A command-line interface (CLI) tool for Open Telekom Cloud (OTC) services.

## Features Overview

- 🔐 **Authentication**: Browser-based SSO login with credential management
- ☁️ **Multi-cloud Support**: Manage multiple cloud configurations via `clouds.yaml`
- 🖥️ **ECS Management**: List and manage Elastic Cloud Servers
- 🐳 **CCE Operations**: List clusters and manage CCE (Cloud Container Engine) configurations
- 🌍 **Multi-region**: Support for different regions and projects
- 📁 **SFS Operations**: List of Scalable file systems (the Turbo variant)
- ⚖️ **ELB Operations**: List of load balancers and their values, delete and update

## Installation

### From Source

```bash
git clone https://github.com/ysoftdevs/otc-cli.git
cd otc-cli
go build -o otc .
```

### Pre-built Binaries

Download the latest release for your platform from the [Releases](https://github.com/ysoftdevs/otc-cli/releases) page.

and add as system binary 

```bash
chmod +x ~/Downloads/otc-darwin-arm64
sudo mv ~/Downloads/otc-darwin-arm64 /usr/local/bin/otc
```

> On Mac, you may want to remove the binary from quarantine
> ```bash
> xattr -d com.apple.quarantine /usr/local/bin/otc
> ```

## Configuration

### clouds.yaml

Create a `clouds.yaml` file in your home directory (`~/.config/openstack/clouds.yaml`):

The file can contain short-lived authentication tokens after `otc login`, so it
must be readable only by the current user:

```bash
chmod 0600 ~/.config/openstack/clouds.yaml
```

On Unix, `otc login` enforces mode `0600` whenever it updates the file. Windows
does not use POSIX file modes; the file inherits the ACLs of the current user's
profile. Updates are written to a temporary file, synced, and atomically renamed
so an interrupted write does not truncate the existing configuration. If
`clouds.yaml` is a symbolic link, its target is updated without replacing the
link. On Unix, run the command above once to protect an existing file before its
next update.

```yaml
clouds:
  my-cloud:
    region: eu-de
    auth:
      auth_url: https://iam.eu-de.otc.t-systems.com/v3
      domain_id: your-domain-id
    sso:
      protocol: saml
      idp: your-idp
      base_url: https://auth.otc.t-systems.com/authui/federation/websso
      expiration: 3600
```

For Entra ID / OpenID Connect federation, add an `oidc` block. This is the
preferred login mode when the selected OTC identity provider supports
programmatic OIDC access:

```yaml
clouds:
  otc-dev-eu-de:
    region_name: eu-de
    auth:
      auth_url: https://iam.eu-de.otc.t-systems.com/v3
      project_name: eu-de_dev
      domain_id: 57a0a4501de945d98fd366ab9dcf33cb
    oidc:
      tenant_id: <entra-tenant-id>
      client_id: <entra-application-client-id>
      idp: YS_OIDC_EID_DEV
      scopes:
        - openid
        - profile
        - email
```

The `oidc` block is optional. Clouds without `oidc` continue to use the legacy
`sso` configuration.

Legacy SAML/SSO login has important limitations:

- It depends on browser automation instead of a supported CLI token exchange.
- It is sensitive to the local browser implementation and can require a specific
  browser/runtime setup.
- It relies on OTC console browser cookies to request temporary credentials.
- It is less portable across macOS/Linux environments than the OIDC flow.
- On macOS, the legacy default-browser credential extraction path supports
  Safari only and is restricted to the standard `auth.otc.t-systems.com` and
  `console.otc.t-systems.com` hosts. Custom `--url` or `sso.base_url` hosts are
  rejected. Use OIDC for a browser-independent login flow.

### Environment Variables

You can override configuration using environment variables with the `OTC_` prefix:

- `OTC_CLOUD`: Cloud name from clouds.yaml
- `OTC_REGION`: Region to use
- `OTC_PROJECT`: Project name

For non-interactive use (see [AK/SK Login](#aksk-login-cicd--automation) below), the full set of `OTC_`-prefixed variables understood by the underlying SDK includes:

- `OTC_AUTH_URL`: Identity/IAM endpoint, e.g. `https://iam.eu-de.otc.t-systems.com/v3`
- `OTC_AK` / `OTC_ACCESS_KEY`: Access Key ID
- `OTC_SK` / `OTC_SECRET_KEY`: Secret Access Key
- `OTC_SECURITY_TOKEN`: Security token (only needed for temporary, not permanent, AK/SK pairs)
- `OTC_PROJECT_NAME` / `OTC_PROJECT_ID`: Project to scope the token to
- `OTC_REGION_NAME`: Region (e.g. `eu-de`)
- `OTC_AUTH_TYPE`: Set to `aksk` for AK/SK authentication

> **Note:** if `OTC_CLOUD` is not set and a `clouds.yaml` exists (in the working directory, `~/.config/openstack/`, or `/etc/openstack/`), otc-cli silently falls back to that file's top-level `selected_cloud` entry — and any `ak`/`sk`/`security_token` stored there for that cloud take precedence over your exported env vars. On automation runners, make sure no stale `clouds.yaml` is present, and always set `OTC_CLOUD` explicitly to a name that does **not** appear in any file on the runner, so env-var auth can't be silently overridden by a leftover file-based credential.

## Usage

### Authentication

Login using the selected cloud configuration:

```bash
otc login
```

When the selected cloud has an `oidc` block, `otc login` opens the OS default
browser, completes Entra ID login using authorization code + PKCE, exchanges the
resulting ID token for an OTC Keystone token, scopes it to the configured
project, and stores that short-lived token in `clouds.yaml`.

The browser callback confirms only that Entra returned an authorization code.
The terminal reports the final result after the Entra and OTC token exchanges
complete.

On macOS, `otc login` uses the OS default browser by default. Safari is
supported for the OIDC default-browser flow without enabling Apple Events.

On Linux, OIDC default-browser login uses `xdg-open`. On Windows, it uses the
system URL handler.

For OIDC login, you can choose which browser opens the Entra login URL:

```bash
otc login --browser firefox
```

The `--browser` flag is only an opener for OIDC login. It does not automate the
browser, read cookies, or execute JavaScript in Safari/Firefox/Chrome. Legacy
SAML/SSO login does not support `--browser`.

#### Hosts without a browser

The default OIDC flow needs a browser that can reach a callback listener on the
same machine, so it does not work over plain SSH on a headless host. `otc login`
always prints the sign-in URL, but on such a host use the device-code flow
instead:

```bash
otc login --device-code
```

This prints a short code to enter at a Microsoft verification URL from any other
device, and needs no local browser, no callback listener and no port forwarding.
It is still an interactive user login, intended for jump hosts and containers.
It is not workload identity for unattended CI/CD; use a dedicated workload
identity or service credential for automation.

With specific cloud configuration:

```bash
otc login --cloud my-cloud --domain-id YOUR_DOMAIN_ID --idp YOUR_IDP
```

If the selected cloud does not include SSO settings in `clouds.yaml`, pass them
explicitly:

```bash
otc login \
  --cloud my-cloud \
  --domain-id YOUR_DOMAIN_ID \
  --idp YOUR_IDP
```

Custom authentication parameters:

```bash
otc login \
  --url https://auth.otc.t-systems.com/authui/federation/websso \
  --auth-url https://iam.eu-de.otc.t-systems.com/v3 \
  --domain-id YOUR_DOMAIN_ID \
  --idp YOUR_IDP \
  --protocol saml \
  --expiration 3600
```

### AK/SK Login (CI/CD & Automation)

`otc login` requires an interactive browser and is not suitable for CI/CD pipelines (e.g. Bamboo). For automation, use a permanent AK/SK pair instead — no `clouds.yaml` or interactive login needed.

**One-time setup on OTC:**

1. Create a dedicated IAM user for the automation pipeline (do not reuse a personal/human account).
2. Attach a least-privilege custom policy/group granting only the permissions the pipeline needs (e.g. `list`/`show` on the services it queries).
3. Under that user, generate a permanent **Access Key (AK) / Secret Key (SK)** pair (IAM console → Access Keys). Permanent keys don't expire, can be individually disabled/deleted at any time to revoke access, and every API call made with them is attributable to that key in Cloud Trace Service (CTS) for auditing.

**Usage:** export the credentials as environment variables and run commands directly — no config file required:

```bash
export OTC_CLOUD=ci-automation   # any name not present in a clouds.yaml on this runner
export OTC_AUTH_URL=https://iam.eu-de.otc.t-systems.com/v3
export OTC_AUTH_TYPE=aksk
export OTC_AK=<access-key-id>
export OTC_SK=<secret-access-key>
export OTC_PROJECT_NAME=eu-de_prod
export OTC_REGION_NAME=eu-de

otc elb list
otc ecs list
```

## Features
### Identity

Show which OTC domain, project, user and roles the current credentials (clouds.yaml, AK/SK env vars, etc.) resolve to — useful for verifying which account a Bamboo/CI job is actually authenticated as:

```bash
otc whoami
```

### ECS (Elastic Cloud Server)

List ECS instances from cloud and region specified in config files:

```bash
otc ecs list
```

```bash
otc ecs show <name> 
```

With specific cloud and region:

```bash
otc ecs list --cloud my-cloud --region eu-de
```

#### Required permissions

```json
{
  "Version": "1.1",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ecs:servers:list",
        "ecs:servers:get",
        "ecs:cloudServers:list",
        "ecs:cloudServers:get"
      ]
    }
  ]
}
```

### SFC (Scalable File Service)
```bash
otc sfs list
```

#### Required permissions

```json
{
  "Version": "1.1",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "sfsturbo:shares:getAllShares"
      ]
    }
  ]
}
```

### RDS (Relational Database Service)
```bash
otc rds list
```

#### Required permissions

```json
{
  "Version": "1.1",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "rds:instance:list"
      ]
    }
  ]
}
```

### ELB (Elastic Load Balancer)
```bash
otc elb list
```

```bash
otc elb show <name>
```

Modify attributes (e.g. disable deletion protection before a delete):

```bash
otc elb modify <name> --deletion-protection-enabled=false
```

Delete a load balancer:

```bash
otc elb delete <name>
```

#### Required permissions

```json
{
  "Version": "1.1",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "elb:loadbalancers:list",
        "elb:loadbalancers:get",
        "elb:loadbalancers:delete",
        "elb:loadbalancers:*"
      ]
    }
  ]
}
```

### CCE (Cloud Container Engine)

List CCE clusters:

```bash
otc cce list
```

Get kubeconfig for a cluster:

```bash
otc cce config CLUSTER_NAME
```

Save kubeconfig to file:

```bash
otc cce config CLUSTER_NAME --output kubeconfig.yaml
```

#### Required permissions

```json
{
  "Version": "1.1",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "cce:cluster:list",
        "cce:cluster:get"
      ]
    }
  ]
}
```

## Global Flags

These flags are available for all commands:

- `-c, --cloud`: Name of the cloud from clouds.yaml to use
- `-r, --region`: Region to use for the cloud
- `-p, --project`: Project name to use for authentication
- `-f, --format`: Output format for formatted commands, possible options: `table`, `json`, `yaml`. Defaults to `table`.

## Login Flags

- `--debug`: Print OIDC login diagnostics without printing token values.
- `--browser`: Browser to open for OIDC login. Defaults to the OS default
  browser.
- `--device-code`: Use the OIDC device-code flow instead of opening a browser.
  This is an interactive, OIDC-only flow for hosts without a browser and cannot
  be combined with an explicit `--browser`.

## Development

### Prerequisites

- Go 1.24 or higher

### Building

Compile everything for the current machine:

```bash
go build -v ./...
```

Produce a runnable `otc` binary:

```bash
go build -o otc .
```

#### Stamping the version

`otc --version` reads `cmd.Version`, which defaults to `dev`. Set it at link
time:

```bash
go build -ldflags "-X github.com/ysoftdevs/otc-cli/cmd.Version=$(git describe --tags --always)" -o otc .
```

#### Cross-compiling

The binary is pure Go with no cgo dependency, so cross-compiling needs nothing
but `GOOS` and `GOARCH` — no toolchain, no C compiler:

```bash
GOOS=darwin GOARCH=arm64 go build -o dist/otc-darwin-arm64 .   # Apple Silicon
GOOS=darwin GOARCH=amd64 go build -o dist/otc-darwin-amd64 .   # Intel Mac
GOOS=linux  GOARCH=arm64 go build -o dist/otc-linux-arm64  .   # ARM64 Linux
GOOS=linux  GOARCH=amd64 go build -o dist/otc-linux-amd64  .   # x86-64 Linux
GOOS=windows GOARCH=arm64 go build -o dist/otc-windows-arm64.exe . # ARM64 Windows
GOOS=windows GOARCH=amd64 go build -o dist/otc-windows-amd64.exe . # x86-64 Windows
```

All six targets in one go, version-stamped and size-reduced:

```bash
VERSION=$(git describe --tags --always)
LDFLAGS="-s -w -X github.com/ysoftdevs/otc-cli/cmd.Version=$VERSION"
for target in darwin/arm64 darwin/amd64 linux/arm64 linux/amd64 windows/arm64 windows/amd64; do
  GOOS=${target%/*} GOARCH=${target#*/} \
    go build -ldflags "$LDFLAGS" -o "dist/otc-${target%/*}-${target#*/}$([ "${target%/*}" = windows ] && printf .exe)" .
done
```

Note that the loop above is written for `bash`. In `zsh` — the default shell on
macOS — an unquoted `$target` is not word-split, so build each target with its
own command or run the loop under `bash`.

Useful build flags:

| Flag | Effect |
|------|--------|
| `-ldflags "-s -w"` | Strips the symbol table and DWARF data, roughly 15% smaller binary (13.2 MB to 11.3 MB) |
| `-ldflags "-X <pkg>.Version=..."` | Sets the version reported by `otc --version` |
| `-trimpath` | Removes local filesystem paths, making builds reproducible |
| `-o <path>` | Output file rather than the default package name |

Platform-specific code is selected by build tags, so a cross-compiled binary
contains only the relevant legacy login backend:
`system_browser_darwin.go`, `system_browser_linux.go`, or
`system_browser_windows.go`. Compiling on one OS therefore does not type-check
the others; cross-build every release target before publishing.

### Running Tests

```bash
go test -v ./...
```

Because of the build tags above, `go test` only exercises the backend for the
host OS. To check the other one, either cross-compile it as shown above or run
the suite on that platform.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
