package backend

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *DatabricksBackend) listConfigEntries(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	configs, err := req.Storage.List(ctx, "config/")
	if err != nil {
		return nil, fmt.Errorf("failed to list config entries: %v", err)
	}

	responseData := map[string]interface{}{
		"config_entries": configs,
	}

	return &logical.Response{
		Data: responseData,
	}, nil
}

// schema for configuring the Databricks token plugin
var configSchema = map[string]*framework.FieldSchema{
	"name": {
		Type:        framework.TypeString,
		Description: "The name of the configuration.",
		Required:    true,
	},
	"base_url": {
		Type:        framework.TypeString,
		Description: "Databricks base URL (e.g., https://<workspace-id>.cloud.databricks.com)",
		Default:     "https://databricks.cloud.com",
	},
	"client_id": {
		Type:        framework.TypeString,
		Description: "Databricks OAuth client ID for M2M authentication",
		Required:    true,
	},
	"client_secret": {
		Type:        framework.TypeString,
		Description: "Databricks OAuth client secret for M2M authentication",
		Required:    true,
	},
}

func configDetail(config *ConfigStorageEntry) map[string]interface{} {
	return map[string]interface{}{
		"base_url":      config.BaseURL,
		"client_id":     config.ClientID,
		"client_secret": "********", // Masked for security
	}
}

func (b *DatabricksBackend) handleDeleteConfig(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name, ok := d.GetOk("name")
	if !ok {
		return nil, fmt.Errorf("name not provided")
	}

	configKey := fmt.Sprintf("config/%s", name.(string))

	if err := req.Storage.Delete(ctx, configKey); err != nil {
		return nil, fmt.Errorf("failed to delete configuration: %v", err)
	}

	return nil, nil
}

func (b *DatabricksBackend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage, data)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: configDetail(config),
	}, nil
}

func (b *DatabricksBackend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	warnings := []string{}
	name, ok := data.GetOk("name")
	if !ok {
		return nil, fmt.Errorf("name parameter not provided")
	}
	nameStr := name.(string)
	config, err := getConfig(ctx, req.Storage, data)
	if err != nil {
		return nil, err
	}
	if config == nil {
		config = &ConfigStorageEntry{}
	}

	baseURL, ok := data.GetOk("base_url")
	if ok {
		config.BaseURL = baseURL.(string)
	} else if config.BaseURL == "" {
		config.BaseURL = configSchema["base_url"].Default.(string)
	}

	clientID, ok := data.GetOk("client_id")
	if ok {
		config.ClientID = clientID.(string)
	} else if config.ClientID == "" {
		return nil, fmt.Errorf("client_id is required")
	}

	clientSecret, ok := data.GetOk("client_secret")
	if ok {
		config.ClientSecret = clientSecret.(string)
	} else if config.ClientSecret == "" {
		return nil, fmt.Errorf("client_secret is required")
	}

	entry, err := logical.StorageEntryJSON("config/"+nameStr, config)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return &logical.Response{
		Data:     configDetail(config),
		Warnings: warnings,
	}, nil
}

func pathConfig(b *DatabricksBackend) []*framework.Path {
	paths := []*framework.Path{
		{
			Pattern: "config/(?P<name>.+)",
			Fields:  configSchema,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathConfigRead,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathConfigWrite,
					Examples: configExamples,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.handleDeleteConfig,
				},
			},
			HelpSynopsis:    pathConfigHelpSyn,
			HelpDescription: pathConfigHelpDesc,
		},
	}
	return paths
}

func pathConfigList(b *DatabricksBackend) []*framework.Path {
	paths := []*framework.Path{
		{
			Pattern: "configs/",
			Fields:  configSchema,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.listConfigEntries,
				},
			},
			HelpSynopsis:    pathConfigHelpSyn,
			HelpDescription: pathConfigHelpDesc,
		},
	}
	return paths
}

const pathConfigHelpSyn = `
Configure the Databricks backend.
`

const pathConfigHelpDesc = `
The Databricks backend requires OAuth credentials (client_id and client_secret) for creating access tokens via M2M authentication.
This endpoint is used to configure those credentials as well as default values for the backend in general.
`

var configExamples = []framework.RequestExample{
	{
		Description: "Create/update backend configuration",
		Data: map[string]interface{}{
			"base_url":      "https://my-databricks-workspace.cloud.databricks.com",
			"client_id":     "my-client-id",
			"client_secret": "my-client-secret",
		},
	},
}
