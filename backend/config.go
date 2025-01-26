package backend

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const pathPatternConfig = "config/"

func (b *DatabricksBackend) pathConfig() *framework.Path {
	return &framework.Path{
		Pattern: pathPatternConfig,
		Fields: map[string]*framework.FieldSchema{
			"databricks_token": {
				Type:        framework.TypeString,
				Description: "Databricks token used for authentication.",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.handleWriteConfig,
			logical.CreateOperation: b.handleWriteConfig,
			logical.ReadOperation:   b.handleReadConfig,
		},
		HelpSynopsis: "This path allows you to configure Databricks settings for token management.",
	}
}

func (b *DatabricksBackend) handleWriteConfig(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	databricksToken, ok := data.GetOk("databricks_token")
	if !ok {
		return nil, fmt.Errorf("missing databricks_token in request")
	}

	entry := &logical.StorageEntry{
		Key:   pathPatternConfig,
		Value: []byte(databricksToken.(string)),
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, fmt.Errorf("failed to store configuration: %v", err)
	}

	return nil, nil
}

func (b *DatabricksBackend) handleReadConfig(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	entry, err := req.Storage.Get(ctx, pathPatternConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to read configuration: %v", err)
	}
	if entry == nil {
		return nil, fmt.Errorf("configuration not found")
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"databricks_token": string(entry.Value),
		},
	}, nil
}
