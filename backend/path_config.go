package backend

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *DatabricksBackend) listConfigEntries(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	externalStorage, err := b.getExternalStorage()
	if err != nil {
		return nil, fmt.Errorf("failed to get external storage: %v", err)
	}
	product, ok := d.GetOk("product")
	if !ok {
		return nil, fmt.Errorf("product parameter not provided")
	}
	environment, ok := d.GetOk("environment")
	if !ok {
		return nil, fmt.Errorf("environment parameter not provided")
	}

	configPath := fmt.Sprintf("%s/%s/dbx_tokens/service_principals", product, environment)
	configs, err := externalStorage.List(ctx, configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to list config entries: %v", err)
	}

	responseData := map[string]interface{}{
		"keys": configs,
	}

	return &logical.Response{
		Data: responseData,
		Warnings: []string{
			fmt.Sprintf("configuration stored under path: gtn/%s", configPath),
		},
	}, nil
}

var configSchema = map[string]*framework.FieldSchema{
	"application_id": {
		Type:        framework.TypeString,
		Description: "The application ID of the service principal.",
		Required:    true,
	},
	"product": {
		Type:        framework.TypeString,
		Description: "Name of the product associated with the service principal.",
		Required:    true,
	},
	"environment": {
		Type:        framework.TypeString,
		Description: "Environment of the service principal (e.g., dev, prod).",
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
		"client_secret": "********",
	}
}

func (b *DatabricksBackend) handleDeleteConfig(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name, ok := d.GetOk("application_id")
	if !ok {
		return nil, fmt.Errorf("name not provided")
	}
	product, ok := d.GetOk("product")
	if !ok {
		return nil, fmt.Errorf("product not provided")
	}
	environment, ok := d.GetOk("environment")
	if !ok {
		return nil, fmt.Errorf("environment not provided")
	}

	configPath := fmt.Sprintf("%s/%s/dbx_tokens/%s/configuration", product, environment, name)
	externalStorage, err := b.getExternalStorage()
	if err != nil {
		return nil, fmt.Errorf("failed to get external storage: %v", err)
	}

	if err := externalStorage.Delete(ctx, configPath); err != nil {
		return nil, fmt.Errorf("failed to delete configuration: %v", err)
	}

	return nil, nil
}

func (b *DatabricksBackend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	externalStorage, err := b.getExternalStorage()
	if err != nil {
		return nil, fmt.Errorf("failed to get external storage: %v", err)
	}
	config, err := getConfig(ctx, externalStorage, data)
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
	name, ok := data.GetOk("application_id")
	if !ok {
		return nil, fmt.Errorf("name parameter not provided")
	}
	product, ok := data.GetOk("product")
	if !ok {
		return nil, fmt.Errorf("product parameter not provided")
	}
	environment, ok := data.GetOk("environment")
	if !ok {
		return nil, fmt.Errorf("environment parameter not provided")
	}

	configPath := fmt.Sprintf("%s/%s/dbx_tokens/service_principals/%s/configuration", product, environment, name)
	externalStorage, err := b.getExternalStorage()
	if err != nil {
		return nil, fmt.Errorf("failed to get external storage: %v", err)
	}

	config, err := getConfig(ctx, externalStorage, data)
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

	entry, err := logical.StorageEntryJSON(configPath, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage entry: %v", err)
	}

	if err := externalStorage.Put(ctx, entry); err != nil {
		return nil, fmt.Errorf("failed to store configuration: %v", err)
	}

	return &logical.Response{
		Data: configDetail(config),
		Warnings: []string{
			fmt.Sprintf("configuration stored under path: gtn/%s", configPath),
		},
	}, nil
}

func pathConfig(b *DatabricksBackend) []*framework.Path {
	paths := []*framework.Path{
		{
			Pattern: "config/(?P<product>.+)/(?P<environment>.+)/(?P<application_id>.+)",
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
			Pattern: "configs/(?P<product>.+)/(?P<environment>.+)",
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
Configure the Databricks backend with service principal credentials.
`

const pathConfigHelpDesc = `
The Databricks backend requires OAuth credentials (client_id and client_secret) for creating access tokens via M2M authentication.
This endpoint configures service principal credentials under a product and environment, stored in the external "gtn" mount.
The product and environment are used in the path structure but not stored as secret data.
`

var configExamples = []framework.RequestExample{
	{
		Description: "Create/update service principal configuration",
		Data: map[string]interface{}{
			"product":        "my-product",
			"environment":    "dev",
			"application_id": "my-sp-id",
			"base_url":       "https://my-databricks-workspace.cloud.databricks.com",
			"client_id":      "my-client-id",
			"client_secret":  "my-client-secret",
		},
	},
}
