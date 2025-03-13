package backend

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func getConfig(ctx context.Context, s logical.Storage, data *framework.FieldData) (*ConfigStorageEntry, error) {
	name, ok := data.GetOk("application_id")
	if !ok {
		return nil, fmt.Errorf("name not provided")
	}
	product, ok := data.GetOk("product")
	if !ok {
		return nil, fmt.Errorf("product not provided")
	}
	environment, ok := data.GetOk("environment")
	if !ok {
		return nil, fmt.Errorf("environment not provided")
	}

	configPath := fmt.Sprintf("%s/%s/dbx_tokens/service_principals/%s/configuration", product, environment, name)

	entry, err := s.Get(ctx, configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve config from %s: %v", configPath, err)
	}
	if entry == nil {
		return nil, nil
	}

	var config ConfigStorageEntry
	if err := json.Unmarshal(entry.Value, &config); err != nil {
		return nil, fmt.Errorf("failed to decode config at %s: %v", configPath, err)
	}

	return &config, nil
}
