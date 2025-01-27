package backend

import (
	"context"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

// ConfigStorageEntry structure represents the config as it is stored within vault
type ConfigStorageEntry struct {
	BaseURL string        `json:"base_url" structs:"base_url" mapstructure:"base_url"`
	Token   string        `json:"token" structs:"token" mapstructure:"token"`
	MaxTTL  time.Duration `json:"max_ttl" structs:"max_ttl" mapstructure:"max_ttl"`
}

func getConfig(ctx context.Context, s logical.Storage) (*ConfigStorageEntry, error) {
	var config ConfigStorageEntry
	configRaw, err := s.Get(ctx, pathPatternConfig)
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
