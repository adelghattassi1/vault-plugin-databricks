package backend

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/databricks/databricks-sdk-go"
	"github.com/databricks/databricks-sdk-go/service/settings"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathCreateToken(b *DatabricksBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "token",
			Fields: map[string]*framework.FieldSchema{
				"config_name": {
					Type:        framework.TypeString,
					Description: "Name of the configuration to use for token creation.",
					Required:    true,
				},
				"token_name": { // Added token_name field
					Type:        framework.TypeString,
					Description: "Unique name for the token within the configuration.",
					Required:    true,
				},
				"application_id": {
					Type:        framework.TypeString,
					Description: "Application ID of the service principal.",
					Required:    true,
				},
				"lifetime_seconds": {
					Type:        framework.TypeInt,
					Description: "The number of seconds before the token expires.",
					Required:    true,
				},
				"comment": {
					Type:        framework.TypeString,
					Description: "Comment that describes the purpose of the token.",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleCreateToken,
				},
			},
		},
	}
}

type TokenStorageEntry struct {
	TokenName       string        `json:"token_name"` // Added TokenName
	TokenID         string        `json:"token_id"`
	TokenValue      string        `json:"token_value"`
	ApplicationID   string        `json:"application_id"`
	Lifetime        time.Duration `json:"lifetime_seconds"`
	Comment         string        `json:"comment"`
	CreationTime    time.Time     `json:"creation_time"`
	ExpiryTime      time.Time     `json:"expiry_time"`
	Configuration   string        `json:"configuration"`
	LastRotated     time.Time     `json:"last_rotated"`
	RotationEnabled bool          `json:"rotation_enabled"`
}

func tokenDetail(token *TokenStorageEntry) map[string]interface{} {
	return map[string]interface{}{
		"token_name":       token.TokenName, // Added token_name
		"token_id":         token.TokenID,
		"token_value":      token.TokenValue,
		"application_id":   token.ApplicationID,
		"lifetime_seconds": int64(token.Lifetime / time.Second),
		"comment":          token.Comment,
		"creation_time":    token.CreationTime.Format(time.RFC3339),
		"expiry_time":      token.ExpiryTime.Format(time.RFC3339),
		"configuration":    token.Configuration,
		"last_rotated":     token.LastRotated.Format(time.RFC3339),
		"rotation_enabled": token.RotationEnabled,
	}
}

func (b *DatabricksBackend) handleCreateToken(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	configName := d.Get("config_name").(string)
	tokenName, ok := d.GetOk("token_name")
	if !ok || tokenName == "" {
		return nil, fmt.Errorf("token_name is required")
	}
	tokenNameStr := tokenName.(string)
	applicationID := d.Get("application_id").(string)
	lifetimeSeconds := d.Get("lifetime_seconds").(int)
	comment := d.Get("comment").(string)

	if lifetimeSeconds < 60 || lifetimeSeconds > 7776000 {
		return nil, fmt.Errorf("lifetime_seconds must be between 60 and 7776000")
	}

	configEntry, err := req.Storage.Get(ctx, "config/"+configName)
	if err != nil {
		b.Logger().Error("Failed to retrieve configuration", "error", err)
		return nil, fmt.Errorf("failed to retrieve configuration: %v", err)
	}
	if configEntry == nil {
		return nil, fmt.Errorf("configuration not found: %s", configName)
	}
	var config ConfigStorageEntry
	if err := configEntry.DecodeJSON(&config); err != nil {
		b.Logger().Error("Failed to decode configuration", "error", err)
		return nil, fmt.Errorf("error decoding configuration: %v", err)
	}

	client, err := databricks.NewWorkspaceClient(&databricks.Config{
		Host:  config.BaseURL,
		Token: config.Token,
	})
	if err != nil {
		b.Logger().Error("Failed to create Databricks client", "error", err)
		return nil, fmt.Errorf("failed to create Databricks client: %v", err)
	}

	b.lock.Lock()
	b.clients[configName] = client
	b.lock.Unlock()

	// Check if token_name already exists
	storagePath := fmt.Sprintf("%s/%s/%s", pathPatternToken, configName, tokenNameStr)
	existingEntry, err := req.Storage.Get(ctx, storagePath)
	if err != nil {
		return nil, fmt.Errorf("error checking existing token: %v", err)
	}
	if existingEntry != nil {
		return nil, fmt.Errorf("token with name %s already exists in configuration %s", tokenNameStr, configName)
	}

	token, err := client.TokenManagement.CreateOboToken(ctx, settings.CreateOboTokenRequest{
		ApplicationId:   applicationID,
		Comment:         comment,
		LifetimeSeconds: int64(lifetimeSeconds),
	})
	if err != nil {
		b.Logger().Error("Failed to create token", "error", err)
		return nil, fmt.Errorf("failed to create token: %v", err)
	}

	tokenEntry := TokenStorageEntry{
		TokenName:       tokenNameStr, // Set TokenName
		TokenID:         token.TokenInfo.TokenId,
		TokenValue:      token.TokenValue,
		ApplicationID:   applicationID,
		Lifetime:        time.Duration(lifetimeSeconds) * time.Second,
		Comment:         comment,
		CreationTime:    time.UnixMilli(token.TokenInfo.CreationTime),
		ExpiryTime:      time.UnixMilli(token.TokenInfo.ExpiryTime),
		Configuration:   configName,
		LastRotated:     time.Now(),
		RotationEnabled: true,
	}

	// Use token_name in the storage path instead of token_id
	storageEntry, err := logical.StorageEntryJSON(storagePath, tokenEntry)
	if err != nil {
		b.Logger().Error("Failed to create storage entry", "error", err)
		return nil, fmt.Errorf("failed to create storage entry: %v", err)
	}
	if err := req.Storage.Put(ctx, storageEntry); err != nil {
		b.Logger().Error("Failed to store token", "error", err)
		return nil, fmt.Errorf("failed to store token: %v", err)
	}

	b.Logger().Info("Token created successfully", "token_name", tokenNameStr)
	return &logical.Response{
		Data: tokenDetail(&tokenEntry),
	}, nil
}

func (b *DatabricksBackend) checkAndRotateToken(ctx context.Context, storage logical.Storage, configName, tokenName string) {
	path := fmt.Sprintf("%s/%s/%s", pathPatternToken, configName, tokenName) // Use tokenName

	entry, err := storage.Get(ctx, path)
	if err != nil || entry == nil {
		return
	}

	var token TokenStorageEntry
	if err := json.Unmarshal(entry.Value, &token); err != nil {
		b.Logger().Error("Failed to unmarshal token", "error", err)
		return
	}

	if !token.RotationEnabled || time.Now().Before(token.ExpiryTime.Add(-rotationGracePeriod)) {
		return
	}

	configEntry, err := storage.Get(ctx, "config/"+configName)
	if err != nil || configEntry == nil {
		return
	}

	var config ConfigStorageEntry
	if err := configEntry.DecodeJSON(&config); err != nil {
		return
	}

	b.lock.RLock()
	client, exists := b.clients[configName]
	b.lock.RUnlock()
	if !exists {
		client, err = databricks.NewWorkspaceClient(&databricks.Config{
			Host:  config.BaseURL,
			Token: config.Token,
		})
		if err != nil {
			return
		}
		b.lock.Lock()
		b.clients[configName] = client
		b.lock.Unlock()
	}

	// Create new token first
	newToken, err := client.TokenManagement.CreateOboToken(ctx, settings.CreateOboTokenRequest{
		ApplicationId:   token.ApplicationID,
		Comment:         token.Comment,
		LifetimeSeconds: int64(token.Lifetime / time.Second),
	})
	if err != nil {
		b.Logger().Error("Failed to create new token during rotation", "error", err)
		return
	}

	// Store the old token ID to revoke later
	oldTokenID := token.TokenID

	// Update token details with new token info
	token.TokenID = newToken.TokenInfo.TokenId
	token.TokenValue = newToken.TokenValue
	token.CreationTime = time.UnixMilli(newToken.TokenInfo.CreationTime)
	token.ExpiryTime = time.UnixMilli(newToken.TokenInfo.ExpiryTime)
	token.LastRotated = time.Now()

	newEntry, err := logical.StorageEntryJSON(path, token)
	if err != nil {
		b.Logger().Error("Failed to create storage entry for rotated token", "error", err)
		return
	}
	if err := storage.Put(ctx, newEntry); err != nil {
		b.Logger().Error("Failed to store rotated token", "error", err)
		return
	}

	// Revoke old token only after new token is successfully stored
	err = client.TokenManagement.DeleteByTokenId(ctx, oldTokenID)
	if err != nil {
		b.Logger().Warn("Failed to revoke old token after rotation", "error", err)
		// Continue since new token is already in place
	}

	b.Logger().Info("Successfully rotated token", "token_name", tokenName)
}

func pathReadDeleteToken(b *DatabricksBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "token/(?P<config_name>[^/]+)/(?P<token_name>[^/]+)", // Use token_name
			Fields: map[string]*framework.FieldSchema{
				"config_name": {
					Type:        framework.TypeString,
					Description: "The name of the configuration under which the token is stored.",
					Required:    true,
				},
				"token_name": { // Changed from token_id
					Type:        framework.TypeString,
					Description: "The name of the token to read or delete.",
					Required:    true,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleReadToken,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.handleDeleteToken,
				},
			},
		},
	}
}

func (b *DatabricksBackend) handleReadToken(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	configName, ok := d.GetOk("config_name")
	if !ok {
		return nil, fmt.Errorf("config_name not provided")
	}

	tokenName, ok := d.GetOk("token_name") // Changed from token_id
	if !ok {
		return nil, fmt.Errorf("token_name not provided")
	}

	entry, err := req.Storage.Get(ctx, fmt.Sprintf("%s/%s/%s", pathPatternToken, configName.(string), tokenName.(string)))
	if err != nil {
		return nil, fmt.Errorf("failed to read token: %v", err)
	}
	if entry == nil {
		return nil, fmt.Errorf("token not found for config: %s, token_name: %s", configName.(string), tokenName.(string))
	}

	var tokenData TokenStorageEntry
	if err := json.Unmarshal(entry.Value, &tokenData); err != nil {
		return nil, fmt.Errorf("failed to parse stored token data: %v", err)
	}

	return &logical.Response{
		Data: tokenDetail(&tokenData),
	}, nil
}

func (b *DatabricksBackend) handleDeleteToken(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	configName, ok := d.GetOk("config_name")
	if !ok {
		return nil, fmt.Errorf("config_name not provided")
	}

	tokenName, ok := d.GetOk("token_name") // Changed from token_id
	if !ok {
		return nil, fmt.Errorf("token_name not provided")
	}

	key := fmt.Sprintf("%s/%s/%s", pathPatternToken, configName.(string), tokenName.(string))

	entry, err := req.Storage.Get(ctx, key)
	if err == nil && entry != nil {
		var token TokenStorageEntry
		if err := json.Unmarshal(entry.Value, &token); err == nil {
			b.lock.RLock()
			client, exists := b.clients[configName.(string)]
			b.lock.RUnlock()
			if exists {
				err = client.TokenManagement.DeleteByTokenId(ctx, token.TokenID)
				if err != nil {
					b.Logger().Warn("Failed to revoke token during deletion", "error", err)
				}
			}
		}
	}

	if err := req.Storage.Delete(ctx, key); err != nil {
		return nil, fmt.Errorf("failed to delete token: %v", err)
	}

	return nil, nil
}

func pathListTokens(b *DatabricksBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: fmt.Sprintf("tokens/%s?/?", framework.GenericNameRegex("config_name")),
			Fields: map[string]*framework.FieldSchema{
				"config_name": {
					Type:        framework.TypeString,
					Description: "The name of the configuration to list tokens for.",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.handleListTokens,
				},
			},
		},
	}
}

func (b *DatabricksBackend) handleListTokens(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Extract the config_name field from the request data
	configName, ok := d.GetOk("config_name")
	if !ok {
		return nil, fmt.Errorf("config_name not provided")
	}

	// List tokens from storage
	tokens, err := req.Storage.List(ctx, fmt.Sprintf("%s/%s/", pathPatternToken, configName))
	if err != nil {
		return nil, fmt.Errorf("failed to list tokens: %v", err)
	}

	// Return a successful response with the token list
	return &logical.Response{
		Data: map[string]interface{}{
			"keys": tokens,
		},
	}, nil
}

func pathUpdateToken(b *DatabricksBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "token/(?P<config_name>[^/]+)/(?P<token_name>[^/]+)", // Use token_name
			Fields: map[string]*framework.FieldSchema{
				"config_name": {
					Type:        framework.TypeString,
					Description: "The name of the configuration under which the token is stored.",
				},
				"token_name": { // Changed from token_id
					Type:        framework.TypeString,
					Description: "The name of the token to update.",
				},
				"comment": {
					Type:        framework.TypeString,
					Description: "Updated comment for the token.",
				},
				"rotation_enabled": {
					Type:        framework.TypeBool,
					Description: "Enable or disable automatic token rotation",
					Default:     true,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleUpdateToken,
				},
			},
		},
	}
}

func (b *DatabricksBackend) handleUpdateToken(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	configName, ok := d.GetOk("config_name")
	if !ok {
		return nil, fmt.Errorf("config_name not provided")
	}

	tokenName, ok := d.GetOk("token_name") // Changed from token_id
	if !ok {
		return nil, fmt.Errorf("token_name not provided")
	}

	path := fmt.Sprintf("%s/%s/%s", pathPatternToken, configName.(string), tokenName.(string))
	entry, err := req.Storage.Get(ctx, path)
	if err != nil || entry == nil {
		return nil, fmt.Errorf("token not found: %s", tokenName.(string))
	}

	var token TokenStorageEntry
	if err := json.Unmarshal(entry.Value, &token); err != nil {
		return nil, fmt.Errorf("failed to parse token data: %v", err)
	}

	if comment, ok := d.GetOk("comment"); ok {
		token.Comment = comment.(string)
	}
	if rotationEnabled, ok := d.GetOk("rotation_enabled"); ok {
		token.RotationEnabled = rotationEnabled.(bool)
	}

	newEntry, err := logical.StorageEntryJSON(path, token)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage entry: %v", err)
	}
	if err := req.Storage.Put(ctx, newEntry); err != nil {
		return nil, fmt.Errorf("failed to update token: %v", err)
	}

	return &logical.Response{
		Data: tokenDetail(&token),
	}, nil
}
