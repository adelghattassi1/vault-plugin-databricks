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
	TokenID         string        `json:"token_id" structs:"token_id" mapstructure:"token_id"`
	TokenValue      string        `json:"token_value" structs:"token_value" mapstructure:"token_value"`
	ApplicationID   string        `json:"application_id" structs:"application_id" mapstructure:"application_id"`
	Lifetime        time.Duration `json:"lifetime_seconds" structs:"lifetime_seconds" mapstructure:"lifetime_seconds"`
	Comment         string        `json:"comment" structs:"comment" mapstructure:"comment"`
	CreationTime    time.Time     `json:"creation_time" structs:"creation_time" mapstructure:"creation_time"`
	ExpiryTime      time.Time     `json:"expiry_time" structs:"expiry_time" mapstructure:"expiry_time"`
	Configuration   string        `json:"configuration" structs:"configuration" mapstructure:"configuration"`
	LastRotated     time.Time     `json:"last_rotated"`
	RotationEnabled bool          `json:"rotation_enabled"`
}

func tokenDetail(token *TokenStorageEntry) map[string]interface{} {
	return map[string]interface{}{
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

	request := settings.CreateOboTokenRequest{
		ApplicationId:   applicationID,
		Comment:         comment,
		LifetimeSeconds: int64(lifetimeSeconds),
	}
	token, err := client.TokenManagement.CreateOboToken(ctx, request)
	if err != nil {
		b.Logger().Error("Failed to create token", "error", err)
		return nil, fmt.Errorf("failed to create token: %v", err)
	}

	tokenEntry := TokenStorageEntry{
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

	storageEntry, err := logical.StorageEntryJSON(fmt.Sprintf("%s/%s/%s", pathPatternToken, configName, token.TokenInfo.TokenId), tokenEntry)
	if err != nil {
		b.Logger().Error("Failed to create storage entry", "error", err)
		return nil, fmt.Errorf("failed to create storage entry: %v", err)
	}
	if err := req.Storage.Put(ctx, storageEntry); err != nil {
		b.Logger().Error("Failed to store token", "error", err)
		return nil, fmt.Errorf("failed to store token: %v", err)
	}

	b.Logger().Info("Token created successfully", "token_id", token.TokenInfo.TokenId)
	return &logical.Response{
		Data: tokenDetail(&tokenEntry),
	}, nil
}

func (b *DatabricksBackend) checkAndRotateToken(ctx context.Context, storage logical.Storage, configName, tokenID string) {
	path := fmt.Sprintf("%s/%s/%s", pathPatternToken, configName, tokenID)

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

	// Revoke old token using Delete (correct method as per Databricks SDK)
	err = client.TokenManagement.DeleteByTokenId(ctx, token.TokenID)
	if err != nil {
		b.Logger().Warn("Failed to revoke old token during rotation", "error", err)
	}

	newToken, err := client.TokenManagement.CreateOboToken(ctx, settings.CreateOboTokenRequest{
		ApplicationId:   token.ApplicationID,
		Comment:         token.Comment,
		LifetimeSeconds: int64(token.Lifetime / time.Second),
	})
	if err != nil {
		b.Logger().Error("Failed to rotate token", "error", err)
		return
	}

	token.TokenID = newToken.TokenInfo.TokenId
	token.TokenValue = newToken.TokenValue
	token.CreationTime = time.UnixMilli(newToken.TokenInfo.CreationTime)
	token.ExpiryTime = time.UnixMilli(newToken.TokenInfo.ExpiryTime)
	token.LastRotated = time.Now()

	newEntry, err := logical.StorageEntryJSON(path, token)
	if err != nil {
		return
	}
	if err := storage.Put(ctx, newEntry); err != nil {
		b.Logger().Error("Failed to store rotated token", "error", err)
		return
	}

	b.Logger().Info("Successfully rotated token", "token_id", tokenID)
}

func pathReadDeleteToken(b *DatabricksBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "token/(?P<config_name>[^/]+)/(?P<token_id>[^/]+)",
			Fields: map[string]*framework.FieldSchema{
				"config_name": {
					Type:        framework.TypeString,
					Description: "The name of the configuration under which the token is stored.",
				},
				"token_id": {
					Type:        framework.TypeString,
					Description: "The ID of the token to read.",
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

	tokenID, ok := d.GetOk("token_id")
	if !ok {
		return nil, fmt.Errorf("token_id not provided")
	}

	entry, err := req.Storage.Get(ctx, fmt.Sprintf("%s/%s/%s", pathPatternToken, configName.(string), tokenID.(string)))
	if err != nil {
		return nil, fmt.Errorf("failed to read token: %v", err)
	}
	if entry == nil {
		return nil, fmt.Errorf("token not found for config: %s", configName.(string))
	}

	var tokenData TokenStorageEntry
	if err := json.Unmarshal(entry.Value, &tokenData); err != nil {
		return nil, fmt.Errorf("failed to parse stored token data: %v", err)
	}

	tokenData.Lifetime = time.Duration(tokenData.Lifetime.Seconds()) * time.Second

	return &logical.Response{
		Data: tokenDetail(&tokenData),
	}, nil
}

func (b *DatabricksBackend) handleDeleteToken(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	configName, ok := d.GetOk("config_name")
	if !ok {
		return nil, fmt.Errorf("config_name not provided")
	}

	tokenID, ok := d.GetOk("token_id")
	if !ok {
		return nil, fmt.Errorf("token_id not provided")
	}

	key := fmt.Sprintf("%s/%s/%s", pathPatternToken, configName.(string), tokenID.(string))

	// Revoke token from Databricks before deletion
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

func listTokensEntries(ctx context.Context, storage logical.Storage, d *framework.FieldData) ([]string, error) {
	configName, ok := d.GetOk("config_name")
	if !ok {
		return nil, fmt.Errorf("config_name not provided")
	}
	tokens, err := storage.List(ctx, fmt.Sprintf("%s/%s/", pathPatternToken, configName))
	if err != nil {
		return nil, err
	}
	return tokens, nil
}

func (b *DatabricksBackend) handleListTokens(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	warnings := []string{}
	tokens, err := listTokensEntries(ctx, req.Storage, d)
	b.Logger().Info("Keys found", "keys", tokens)
	if err != nil {
		return nil, fmt.Errorf("failed to list tokens: %s", tokens)
	}
	resp := &logical.Response{
		Data:     map[string]interface{}{},
		Warnings: warnings,
	}
	if len(tokens) != 0 {
		resp.Data["keys"] = tokens
	}
	return resp, nil
}

func pathUpdateToken(b *DatabricksBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "token/(?P<config_name>[^/]+)/(?P<token_id>[^/]+)",
			Fields: map[string]*framework.FieldSchema{
				"config_name": {
					Type:        framework.TypeString,
					Description: "The name of the configuration under which the token is stored.",
				},
				"token_id": {
					Type:        framework.TypeString,
					Description: "The ID of the token to update.",
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

	tokenID, ok := d.GetOk("token_id")
	if !ok {
		return nil, fmt.Errorf("token_id not provided")
	}

	newComment, ok := d.GetOk("comment")
	if !ok {
		return nil, fmt.Errorf("comment not provided")
	}

	entry, err := req.Storage.Get(ctx, fmt.Sprintf("%s/%s/%s", pathPatternToken, configName.(string), tokenID.(string)))
	if err != nil || entry == nil {
		return nil, fmt.Errorf("failed to find token: %v", err)
	}

	var token TokenStorageEntry
	if err := json.Unmarshal(entry.Value, &token); err != nil {
		return nil, fmt.Errorf("failed to parse token data: %v", err)
	}

	token.Comment = newComment.(string)
	if rotationEnabled, ok := d.GetOk("rotation_enabled"); ok {
		token.RotationEnabled = rotationEnabled.(bool)
	}

	newEntry, err := logical.StorageEntryJSON(fmt.Sprintf("%s/%s/%s", pathPatternToken, configName, tokenID), token)
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
