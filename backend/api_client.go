package backend

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/logical"
)

// APILogicalStorage adapts api.Logical to the logical.Storage interface
type APILogicalStorage struct {
	client     *api.Logical
	mountPoint string
}

// Get retrieves a storage entry from the external "gtn" mount
func (s *APILogicalStorage) Get(ctx context.Context, key string) (*logical.StorageEntry, error) {
	// For KV v2, read from /data/
	path := s.mountPoint + "/data/" + key
	secret, err := s.client.ReadWithContext(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to read from %s: %v", path, err)
	}
	if secret == nil || secret.Data == nil {
		return nil, nil // Not found
	}

	// KV v2 stores data under "data" key
	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid data format in %s", path)
	}

	value, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize data: %v", err)
	}

	return &logical.StorageEntry{
		Key:   key,
		Value: value,
	}, nil
}

// Put stores a storage entry in the external "gtn" mount
func (s *APILogicalStorage) Put(ctx context.Context, entry *logical.StorageEntry) error {
	// Deserialize the entry value into a map
	var data map[string]interface{}
	if err := json.Unmarshal(entry.Value, &data); err != nil {
		return fmt.Errorf("failed to unmarshal data: %v", err)
	}

	// For KV v2, write to /data/
	path := s.mountPoint + "/data/" + entry.Key
	_, err := s.client.WriteWithContext(ctx, path, map[string]interface{}{
		"data": data,
	})
	if err != nil {
		return fmt.Errorf("failed to write to %s: %v", path, err)
	}
	return nil
}

// List retrieves a list of keys under a prefix from the external "gtn" mount
func (s *APILogicalStorage) List(ctx context.Context, prefix string) ([]string, error) {
	// For KV v2, list from /metadata/
	path := s.mountPoint + "/metadata/" + prefix
	secret, err := s.client.ListWithContext(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to list %s: %v", path, err)
	}
	if secret == nil || secret.Data == nil {
		return []string{}, nil // No keys found
	}

	keys, ok := secret.Data["keys"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid list response from %s", path)
	}

	result := make([]string, len(keys))
	for i, k := range keys {
		result[i] = k.(string)
	}
	return result, nil
}

// Delete removes a storage entry from the external "gtn" mount
func (s *APILogicalStorage) Delete(ctx context.Context, key string) error {
	// For KV v2, delete from /data/
	path := s.mountPoint + "/data/" + key
	_, err := s.client.DeleteWithContext(ctx, path)
	if err != nil {
		return fmt.Errorf("failed to delete %s: %v", path, err)
	}
	return nil
}
