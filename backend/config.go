package backend

import (
	"context"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// ConfigStorageEntry structure represents the config as it is stored within vault

func getConfig(ctx context.Context, s logical.Storage, data *framework.FieldData) (*ConfigStorageEntry, error) {
	name := data.Get("name").(string)
	var config ConfigStorageEntry
	configRaw, err := s.Get(ctx, "config/"+name)
	if err != nil {
		return nil, err
	}
	if configRaw == nil {
		return nil, nil
	}

	if err := configRaw.DecodeJSON(&config); err != nil {
		return nil, err
	}

	return &config, err
}
