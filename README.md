# Vault Databricks Plugin

A HashiCorp Vault plugin for dynamically generating Databricks API tokens using OAuth machine-to-machine authentication. This plugin enables secure, automated token management for Databricks workspaces without requiring static API tokens.

## Features

- Dynamic generation of Databricks OBO (On-Behalf-Of) tokens
- OAuth machine-to-machine authentication with Databricks
- Configurable token lifetime (default: 10 years)
- Integration with external Vault storage backend
- Support for multiple environments and service principals

## Prerequisites

- HashiCorp Vault server
- Go 1.23.4 or later
- Databricks workspace with OAuth app configured
- Access to external Vault storage backend ("gtn" mount)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/adelghattassi1/vault-plugin-databricks.git
cd vault-plugin-databricks
```

2. Build the plugin:
```bash
go build -o vault-plugin-databricks main.go
```

3. Register the plugin with Vault:
```bash
vault plugin register -sha256=$(sha256sum vault-plugin-databricks | cut -d' ' -f1) secret vault-plugin-databricks
```

4. Enable the plugin:
```bash
vault secrets enable -path=databricks vault-plugin-databricks
```

## Configuration

The plugin requires configuration of service principals with OAuth credentials. Configuration is stored in the external "gtn" storage backend.

### Service Principal Configuration Path
```
gtn/{product}/{environment}/dbx_tokens/service_principals/{application_id}/configuration
```

Configuration format:
```json
{
  "base_url": "https://your-workspace.cloud.databricks.com",
  "client_id": "your-oauth-client-id",
  "client_secret": "your-oauth-client-secret"
}
```

## Usage

### Create a Token
```bash
vault write databricks/token/{product}/{environment}/{application_id}/{token_name} \
  lifetime_seconds=31536000 \
  comment="Token for automated workflows"
```

### Read a Token
```bash
vault read databricks/token/{product}/{environment}/{application_id}/{token_name}
```

### List Tokens
```bash
vault list databricks/tokens/{product}/{environment}/{application_id}
```

### Delete a Token
```bash
vault delete databricks/token/{product}/{environment}/{application_id}/{token_name}
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST/PUT | `/token/{product}/{environment}/{application_id}/{token_name}` | Create a new token |
| GET | `/token/{product}/{environment}/{application_id}/{token_name}` | Read token details |
| DELETE | `/token/{product}/{environment}/{application_id}/{token_name}` | Delete a token |
| LIST | `/tokens/{product}/{environment}/{application_id}` | List all tokens for a service principal |

## Parameters

- `product`: Product name for organization
- `environment`: Environment (dev, staging, prod, etc.)
- `application_id`: Databricks service principal application ID
- `token_name`: Unique identifier for the token
- `lifetime_seconds`: Token lifetime in seconds (default: 315,360,000 = 10 years)
- `comment`: Optional description for the token

## Response Format

```json
{
  "token_name": "my-token",
  "token_id": "databricks-token-id",
  "token_value": "dapi...",
  "application_id": "service-principal-id",
  "lifetime_years": 10.0,
  "comment": "Token description",
  "creation_time": "2024-01-01T00:00:00Z",
  "expiry_time": "2034-01-01T00:00:00Z"
}
```

## Development

### Build
```bash
go build -o vault-plugin-databricks
```

### Dependencies
- `github.com/databricks/databricks-sdk-go` - Databricks SDK
- `github.com/hashicorp/vault/api` - Vault API client
- `github.com/hashicorp/vault/sdk` - Vault plugin SDK

## Architecture

The plugin integrates with:
- Databricks OAuth API for token generation
- External Vault storage backend ("gtn" mount) for configuration and token storage
- HashiCorp Vault plugin framework

## Security Considerations

- OAuth client secrets are stored securely in the external Vault backend
- Generated tokens are stored with metadata for tracking and management
- Plugin supports TLS configuration for secure communication
- Tokens can be revoked through Databricks API (commented out in current implementation)

## License

This project is licensed under the terms specified in the repository.