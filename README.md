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

Login using browser-based SSO:

```bash
otc login
```

With specific cloud configuration:

```bash
otc login --cloud my-cloud --domain-id YOUR_DOMAIN_ID
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

Required policy (list, modify attributes, and delete load balancers) — verified against OTC's IAM console (`Version` must be `1.1`; OTC does not register a `1.1`-schema `elb:loadbalancers:update` action, so the wildcard below is required for `otc elb modify` until a discrete action is confirmed):

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

- `elb:loadbalancers:list` / `get`: list and describe load balancers (`otc elb list`, `otc elb show`).
- `elb:loadbalancers:*`: covers modifying a load balancer (`otc elb modify`, e.g. `deletion_protection_enable`), since OTC has no separate registered `update` action.
- `elb:loadbalancers:delete`: delete a load balancer (`otc elb delete`).

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

## Global Flags

These flags are available for all commands:

- `-c, --cloud`: Name of the cloud from clouds.yaml to use
- `-r, --region`: Region to use for the cloud
- `-p, --project`: Project name to use for authentication
- `-f, --format`: Changes output style, possible options: `yaml, json, table, value`. Defaults to `table`.

## Development

### Prerequisites

- Go 1.21 or higher

### Building

```bash
go build -v ./...
```

### Running Tests

```bash
go test -v ./...
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.