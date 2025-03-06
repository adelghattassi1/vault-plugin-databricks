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
	secret, err := s.client.ReadWithContext(ctx, s.mountPoint+"/"+key)
	if err != nil {
		return nil, fmt.Errorf("failed to read from %s/%s: %v", s.mountPoint, key, err)
	}
	if secret == nil || secret.Data == nil {
		return nil, nil // Not found
	}

	// Assume data is stored under the "data" key in the KV store
	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid data format in %s/%s", s.mountPoint, key)
	}

	// Serialize the data to bytes
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
	// Deserialize the entry value into a map for storage
	var data map[string]interface{}
	if err := json.Unmarshal(entry.Value, &data); err != nil {
		return fmt.Errorf("failed to unmarshal data: %v", err)
	}

	_, err := s.client.WriteWithContext(ctx, s.mountPoint+"/"+entry.Key, map[string]interface{}{
		"data": data,
	})
	if err != nil {
		return fmt.Errorf("failed to write to %s/%s: %v", s.mountPoint, entry.Key, err)
	}
	return nil
}

// List retrieves a list of keys under a prefix from the external "gtn" mount
func (s *APILogicalStorage) List(ctx context.Context, prefix string) ([]string, error) {
	secret, err := s.client.ListWithContext(ctx, s.mountPoint+"/"+prefix)
	if err != nil {
		return nil, fmt.Errorf("failed to list %s/%s: %v", s.mountPoint, prefix, err)
	}
	if secret == nil || secret.Data == nil {
		return []string{}, nil // No keys found
	}

	keys, ok := secret.Data["keys"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid list response from %s/%s", s.mountPoint, prefix)
	}

	result := make([]string, len(keys))
	for i, k := range keys {
		result[i] = k.(string)
	}
	return result, nil
}

// Delete removes a storage entry from the external "gtn" mount
func (s *APILogicalStorage) Delete(ctx context.Context, key string) error {
	_, err := s.client.DeleteWithContext(ctx, s.mountPoint+"/"+key)
	if err != nil {
		return fmt.Errorf("failed to delete %s/%s: %v", s.mountPoint, key, err)
	}
	return nil
}
