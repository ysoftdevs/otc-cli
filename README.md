# OTC CLI

A command-line interface (CLI) tool for Open Telekom Cloud (OTC) services.

## Features

- 🔐 **Authentication**: Browser-based SSO login with credential management
- ☁️ **Multi-cloud Support**: Manage multiple cloud configurations via `clouds.yaml`
- 🖥️ **ECS Management**: List and manage Elastic Cloud Servers
- 🐳 **CCE Operations**: List clusters and manage CCE (Cloud Container Engine) configurations
- 🌍 **Multi-region**: Support for different regions and projects

## Installation

### From Source

```bash
git clone https://github.com/yourusername/otc-cli.git
cd otc-cli
go build -o otc .
```

### Pre-built Binaries

Download the latest release for your platform from the [Releases](https://github.com/ysoftdevs/otc-cli/releases) page.

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

### ECS (Elastic Cloud Server)

List ECS instances from cloud and region specified in config files:

```bash
otc ecs list
```

With specific cloud and region:

```bash
otc ecs list --cloud my-cloud --region eu-de
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