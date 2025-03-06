package backend

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/databricks/databricks-sdk-go/service/settings"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathCreateToken(b *DatabricksBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "token/(?P<product>.+)/(?P<environment>.+)/(?P<sp_name>.+)/(?P<token_name>.+)",
			Fields: map[string]*framework.FieldSchema{
				"product": {
					Type:        framework.TypeString,
					Description: "Name of the product.",
					Required:    true,
				},
				"environment": {
					Type:        framework.TypeString,
					Description: "Environment of the service principal.",
					Required:    true,
				},
				"sp_name": {
					Type:        framework.TypeString,
					Description: "Name of the service principal.",
					Required:    true,
				},
				"token_name": {
					Type:        framework.TypeString,
					Description: "Unique name for the token.",
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
	TokenName       string        `json:"token_name"`
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

type ConfigStorageEntry struct {
	Product      string `json:"product"`
	Environment  string `json:"environment"`
	Name         string `json:"name"`
	BaseURL      string `json:"base_url"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

func tokenDetail(token *TokenStorageEntry) map[string]interface{} {
	return map[string]interface{}{
		"token_name":       token.TokenName,
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
	product, ok := d.GetOk("product")
	if !ok {
		return nil, fmt.Errorf("product not provided")
	}
	environment, ok := d.GetOk("environment")
	if !ok {
		return nil, fmt.Errorf("environment not provided")
	}
	spName, ok := d.GetOk("sp_name")
	if !ok {
		return nil, fmt.Errorf("sp_name not provided")
	}
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

	configPath := fmt.Sprintf("%s/%s/%s", product, environment, spName)
	externalStorage, err := b.getExternalStorage()
	if err != nil {
		return nil, fmt.Errorf("failed to get external storage: %v", err)
	}
	entry, err := externalStorage.Get(ctx, configPath)
	if err != nil {
		b.Logger().Error("Failed to retrieve configuration", "path", configPath, "error", err)
		return nil, fmt.Errorf("failed to retrieve configuration: %v", err)
	}
	if entry == nil {
		return nil, fmt.Errorf("configuration not found: %s", configPath)
	}
	var config ConfigStorageEntry
	if err := json.Unmarshal(entry.Value, &config); err != nil {
		b.Logger().Error("Failed to decode configuration", "path", configPath, "error", err)
		return nil, fmt.Errorf("error decoding configuration: %v", err)
	}

	client, err := b.getWorkspaceClient(config)
	if err != nil {
		b.Logger().Error("Failed to get Databricks client", "error", err)
		return nil, fmt.Errorf("failed to get Databricks client: %v", err)
	}

	tokenPath := fmt.Sprintf("%s/tokens/%s", configPath, tokenNameStr)
	existingEntry, err := externalStorage.Get(ctx, tokenPath)
	if err != nil {
		return nil, fmt.Errorf("error checking existing token: %v", err)
	}
	if existingEntry != nil {
		return nil, fmt.Errorf("token with name %s already exists in configuration %s", tokenNameStr, configPath)
	}

	token, err := client.TokenManagement.CreateOboToken(ctx, settings.CreateOboTokenRequest{
		ApplicationId:   applicationID,
		Comment:         comment,
		LifetimeSeconds: int64(lifetimeSeconds),
	})
	if err != nil {
		b.Logger().Error("Failed to create OBO token", "error", err)
		return nil, fmt.Errorf("failed to create OBO token: %v", err)
	}

	tokenEntry := TokenStorageEntry{
		TokenName:       tokenNameStr,
		TokenID:         token.TokenInfo.TokenId,
		TokenValue:      token.TokenValue,
		ApplicationID:   applicationID,
		Lifetime:        time.Duration(lifetimeSeconds) * time.Second,
		Comment:         comment,
		CreationTime:    time.UnixMilli(token.TokenInfo.CreationTime),
		ExpiryTime:      time.UnixMilli(token.TokenInfo.ExpiryTime),
		Configuration:   configPath,
		LastRotated:     time.Now(),
		RotationEnabled: true,
	}

	storageEntry, err := logical.StorageEntryJSON(tokenPath, tokenEntry)
	if err != nil {
		b.Logger().Error("Failed to create storage entry", "error", err)
		return nil, fmt.Errorf("failed to create storage entry: %v", err)
	}
	if err := externalStorage.Put(ctx, storageEntry); err != nil {
		b.Logger().Error("Failed to store token", "error", err)
		return nil, fmt.Errorf("failed to store token: %v", err)
	}

	b.Logger().Info("Token created successfully", "token_name", tokenNameStr)
	return &logical.Response{
		Data: tokenDetail(&tokenEntry),
	}, nil
}

func (b *DatabricksBackend) checkAndRotateToken(ctx context.Context, storage logical.Storage, configName, tokenName string) {
	defer func() {
		if r := recover(); r != nil {
			b.Logger().Error("Panic during token rotation", "token_name", tokenName, "panic", r)
		}
	}()

	path := fmt.Sprintf("%s/tokens/%s", configName, tokenName)
	b.Logger().Info("Checking token for rotation", "path", path)

	entry, err := storage.Get(ctx, path)
	if err != nil {
		b.Logger().Error("Failed to retrieve token for rotation", "path", path, "error", err)
		return
	}
	if entry == nil {
		b.Logger().Warn("Token not found for rotation", "path", path)
		return
	}
	b.Logger().Info("Retrieved token", "path", path)

	var token TokenStorageEntry
	if err := json.Unmarshal(entry.Value, &token); err != nil {
		b.Logger().Error("Failed to unmarshal token", "path", path, "error", err)
		return
	}
	b.Logger().Info("Unmarshaled token", "token_name", tokenName)

	now := time.Now()
	rotationThreshold := token.ExpiryTime.Add(-rotationGracePeriod)
	b.Logger().Info("Rotation check", "token_name", tokenName, "now", now.Format(time.RFC3339), "threshold", rotationThreshold.Format(time.RFC3339), "expiry", token.ExpiryTime.Format(time.RFC3339), "rotation_enabled", token.RotationEnabled)

	if !token.RotationEnabled || now.Before(rotationThreshold) {
		b.Logger().Info("Token does not need rotation", "token_name", tokenName, "rotation_enabled", token.RotationEnabled, "now_before_threshold", now.Before(rotationThreshold))
		return
	}

	b.Logger().Info("Initiating rotation", "token_name", tokenName, "token_id", token.TokenID)

	if err := ctx.Err(); err != nil {
		b.Logger().Info("Context canceled or timed out before config retrieval", "token_name", tokenName, "error", err)
		return
	}

	configCtx, configCancel := context.WithTimeout(ctx, 30*time.Second)
	defer configCancel()
	b.Logger().Info("Retrieving config", "config", configName)
	configEntry, err := storage.Get(configCtx, configName)
	if err != nil {
		b.Logger().Info("Failed to retrieve config for rotation", "config", configName, "error", err)
		return
	}
	if configEntry == nil {
		b.Logger().Info("Config not found for rotation", "config", configName)
		return
	}
	b.Logger().Info("Retrieved config", "config", configName)

	var config ConfigStorageEntry
	if err := json.Unmarshal(configEntry.Value, &config); err != nil {
		b.Logger().Info("Failed to decode config for rotation", "config", configName, "error", err)
		return
	}
	b.Logger().Info("Decoded config", "config", configName)

	b.Logger().Info("Getting workspace client", "config", configName)
	client, err := b.getWorkspaceClient(config)
	if err != nil {
		b.Logger().Info("Failed to get Databricks client for rotation", "config", configName, "error", err)
		return
	}
	b.Logger().Info("Initialized client", "config", configName)

	apiCtx, apiCancel := context.WithTimeout(ctx, 30*time.Second)
	defer apiCancel()
	b.Logger().Info("Creating new OBO token", "token_name", tokenName)
	newToken, err := client.TokenManagement.CreateOboToken(apiCtx, settings.CreateOboTokenRequest{
		ApplicationId:   token.ApplicationID,
		Comment:         token.Comment,
		LifetimeSeconds: int64(token.Lifetime / time.Second),
	})
	if err != nil {
		b.Logger().Info("Failed to create new token during rotation", "token_name", tokenName, "error", err)
		return
	}
	b.Logger().Info("Created new OBO token", "token_name", tokenName, "new_token_id", newToken.TokenInfo.TokenId)

	oldTokenID := token.TokenID
	token.TokenID = newToken.TokenInfo.TokenId
	token.TokenValue = newToken.TokenValue
	token.CreationTime = time.UnixMilli(newToken.TokenInfo.CreationTime)
	token.ExpiryTime = time.UnixMilli(newToken.TokenInfo.ExpiryTime)
	token.LastRotated = now

	newEntry, err := logical.StorageEntryJSON(path, token)
	if err != nil {
		b.Logger().Info("Failed to create storage entry for rotated token", "token_name", tokenName, "error", err)
		return
	}
	if err := storage.Put(ctx, newEntry); err != nil {
		b.Logger().Info("Failed to store rotated token", "token_name", tokenName, "error", err)
		return
	}

	deleteCtx, deleteCancel := context.WithTimeout(ctx, 30*time.Second)
	defer deleteCancel()
	b.Logger().Info("Revoking old token", "token_name", tokenName, "old_token_id", oldTokenID)
	err = client.TokenManagement.DeleteByTokenId(deleteCtx, oldTokenID)
	if err != nil {
		b.Logger().Info("Failed to revoke old token after rotation", "token_name", tokenName, "old_token_id", oldTokenID, "error", err)
	} else {
		b.Logger().Info("Revoked old token", "token_name", tokenName, "old_token_id", oldTokenID)
	}

	b.Logger().Info("Successfully rotated token", "token_name", tokenName, "new_token_id", token.TokenID)
}

func pathTokenOperations(b *DatabricksBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "token/(?P<product>.+)/(?P<environment>.+)/(?P<sp_name>.+)/(?P<token_name>.+)",
			Fields: map[string]*framework.FieldSchema{
				"product": {
					Type:        framework.TypeString,
					Description: "Name of the product.",
					Required:    true,
				},
				"environment": {
					Type:        framework.TypeString,
					Description: "Environment of the service principal.",
					Required:    true,
				},
				"sp_name": {
					Type:        framework.TypeString,
					Description: "Name of the service principal.",
					Required:    true,
				},
				"token_name": {
					Type:        framework.TypeString,
					Description: "The name of the token to read, update, or delete.",
					Required:    true,
				},
				"comment": {
					Type:        framework.TypeString,
					Description: "Updated comment for the token (for update operation).",
				},
				"rotation_enabled": {
					Type:        framework.TypeBool,
					Description: "Enable or disable automatic token rotation (for update operation)",
					Default:     true,
				},
				"lifetime_seconds": {
					Type:        framework.TypeInt,
					Description: "The number of seconds before the token expires (for update operation). If omitted, preserves the existing lifetime.",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleReadToken,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleUpdateToken,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.handleDeleteToken,
				},
			},
		},
	}
}

func (b *DatabricksBackend) handleReadToken(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	product, ok := d.GetOk("product")
	if !ok {
		return nil, fmt.Errorf("product not provided")
	}
	environment, ok := d.GetOk("environment")
	if !ok {
		return nil, fmt.Errorf("environment not provided")
	}
	spName, ok := d.GetOk("sp_name")
	if !ok {
		return nil, fmt.Errorf("sp_name not provided")
	}
	tokenName, ok := d.GetOk("token_name")
	if !ok {
		return nil, fmt.Errorf("token_name not provided")
	}

	externalStorage, err := b.getExternalStorage()
	if err != nil {
		return nil, fmt.Errorf("failed to get external storage: %v", err)
	}

	tokenPath := fmt.Sprintf("%s/%s/%s/tokens/%s", product, environment, spName, tokenName)
	entry, err := externalStorage.Get(ctx, tokenPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read token: %v", err)
	}
	if entry == nil {
		return nil, fmt.Errorf("token not found for config: %s, token_name: %s", tokenPath, tokenName)
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
	product, ok := d.GetOk("product")
	if !ok {
		return nil, fmt.Errorf("product not provided")
	}
	environment, ok := d.GetOk("environment")
	if !ok {
		return nil, fmt.Errorf("environment not provided")
	}
	spName, ok := d.GetOk("sp_name")
	if !ok {
		return nil, fmt.Errorf("sp_name not provided")
	}
	tokenName, ok := d.GetOk("token_name")
	if !ok {
		return nil, fmt.Errorf("token_name not provided")
	}

	configPath := fmt.Sprintf("%s/%s/%s", product, environment, spName)
	tokenPath := fmt.Sprintf("%s/tokens/%s", configPath, tokenName)

	externalStorage, err := b.getExternalStorage()
	if err != nil {
		return nil, fmt.Errorf("failed to get external storage: %v", err)
	}

	configEntry, err := externalStorage.Get(ctx, configPath)
	if err != nil || configEntry == nil {
		return nil, fmt.Errorf("failed to retrieve configuration: %v", err)
	}
	var config ConfigStorageEntry
	if err := json.Unmarshal(configEntry.Value, &config); err != nil {
		return nil, fmt.Errorf("error decoding configuration: %v", err)
	}

	client, err := b.getWorkspaceClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to get Databricks client: %v", err)
	}

	entry, err := externalStorage.Get(ctx, tokenPath)
	if err == nil && entry != nil {
		var token TokenStorageEntry
		if err := json.Unmarshal(entry.Value, &token); err == nil {
			err = client.TokenManagement.DeleteByTokenId(ctx, token.TokenID)
			if err != nil {
				b.Logger().Warn("Failed to revoke token during deletion", "error", err)
			}
		}
	}

	if err := externalStorage.Delete(ctx, tokenPath); err != nil {
		return nil, fmt.Errorf("failed to delete token: %v", err)
	}

	return nil, nil
}

func pathListTokens(b *DatabricksBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "tokens/(?P<product>.+)/(?P<environment>.+)/(?P<sp_name>.+)",
			Fields: map[string]*framework.FieldSchema{
				"product": {
					Type:        framework.TypeString,
					Description: "Name of the product.",
					Required:    true,
				},
				"environment": {
					Type:        framework.TypeString,
					Description: "Environment of the service principal.",
					Required:    true,
				},
				"sp_name": {
					Type:        framework.TypeString,
					Description: "Name of the service principal.",
					Required:    true,
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
	product, ok := d.GetOk("product")
	if !ok {
		return nil, fmt.Errorf("product not provided")
	}
	environment, ok := d.GetOk("environment")
	if !ok {
		return nil, fmt.Errorf("environment not provided")
	}
	spName, ok := d.GetOk("sp_name")
	if !ok {
		return nil, fmt.Errorf("sp_name not provided")
	}

	externalStorage, err := b.getExternalStorage()
	if err != nil {
		return nil, fmt.Errorf("failed to get external storage: %v", err)
	}

	tokenPrefix := fmt.Sprintf("%s/%s/%s/tokens/", product, environment, spName)
	tokens, err := externalStorage.List(ctx, tokenPrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to list tokens: %v", err)
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"keys": tokens,
		},
	}, nil
}

func (b *DatabricksBackend) handleUpdateToken(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	product, ok := d.GetOk("product")
	if !ok {
		return nil, fmt.Errorf("product not provided")
	}
	environment, ok := d.GetOk("environment")
	if !ok {
		return nil, fmt.Errorf("environment not provided")
	}
	spName, ok := d.GetOk("sp_name")
	if !ok {
		return nil, fmt.Errorf("sp_name not provided")
	}
	tokenName, ok := d.GetOk("token_name")
	if !ok {
		return nil, fmt.Errorf("token_name not provided")
	}

	configPath := fmt.Sprintf("%s/%s/%s", product, environment, spName)
	tokenPath := fmt.Sprintf("%s/tokens/%s", configPath, tokenName)
	b.Logger().Info("Updating token", "path", tokenPath)

	externalStorage, err := b.getExternalStorage()
	if err != nil {
		return nil, fmt.Errorf("failed to get external storage: %v", err)
	}

	entry, err := externalStorage.Get(ctx, tokenPath)
	if err != nil || entry == nil {
		b.Logger().Error("Token not found", "path", tokenPath, "error", err)
		return nil, fmt.Errorf("token not found: %s", tokenName)
	}

	var token TokenStorageEntry
	if err := json.Unmarshal(entry.Value, &token); err != nil {
		b.Logger().Error("Unmarshal failed", "path", tokenPath, "error", err)
		return nil, fmt.Errorf("failed to parse token data: %v", err)
	}

	configEntry, err := externalStorage.Get(ctx, configPath)
	if err != nil || configEntry == nil {
		b.Logger().Error("Failed to retrieve config for update", "config", configPath, "error", err)
		return nil, fmt.Errorf("configuration not found: %s", configPath)
	}
	var config ConfigStorageEntry
	if err := json.Unmarshal(configEntry.Value, &config); err != nil {
		b.Logger().Error("Failed to decode config", "config", configPath, "error", err)
		return nil, fmt.Errorf("error decoding configuration: %v", err)
	}

	client, err := b.getWorkspaceClient(config)
	if err != nil {
		b.Logger().Error("Failed to get Databricks client for update", "config", configPath, "error", err)
		return nil, fmt.Errorf("failed to get Databricks client: %v", err)
	}

	comment := token.Comment
	if newComment, ok := d.GetOk("comment"); ok {
		comment = newComment.(string)
	}
	lifetimeSeconds := int64(token.Lifetime / time.Second)
	if newLifetime, ok := d.GetOk("lifetime_seconds"); ok {
		lifetimeSeconds = int64(newLifetime.(int))
	}
	rotationEnabled := token.RotationEnabled
	if newRotationEnabled, ok := d.GetOk("rotation_enabled"); ok {
		rotationEnabled = newRotationEnabled.(bool)
	}

	oldTokenID := token.TokenID
	err = client.TokenManagement.DeleteByTokenId(ctx, oldTokenID)
	if err != nil {
		b.Logger().Warn("Failed to delete old token during update", "token_name", tokenName, "token_id", oldTokenID, "error", err)
	}

	newToken, err := client.TokenManagement.CreateOboToken(ctx, settings.CreateOboTokenRequest{
		ApplicationId:   token.ApplicationID,
		Comment:         comment,
		LifetimeSeconds: lifetimeSeconds,
	})
	if err != nil {
		b.Logger().Error("Failed to create new token during update", "token_name", tokenName, "error", err)
		return nil, fmt.Errorf("failed to create new token: %v", err)
	}

	token.TokenID = newToken.TokenInfo.TokenId
	token.TokenValue = newToken.TokenValue
	token.Comment = comment
	token.Lifetime = time.Duration(lifetimeSeconds) * time.Second
	token.CreationTime = time.UnixMilli(newToken.TokenInfo.CreationTime)
	token.ExpiryTime = time.UnixMilli(newToken.TokenInfo.ExpiryTime)
	token.LastRotated = time.Now()
	token.RotationEnabled = rotationEnabled

	b.Logger().Info("Updated token fields", "token_name", tokenName, "token_id", token.TokenID, "comment", token.Comment, "rotation_enabled", token.RotationEnabled)

	newEntry, err := logical.StorageEntryJSON(tokenPath, token)
	if err != nil {
		b.Logger().Error("Failed to create storage entry", "path", tokenPath, "error", err)
		return nil, fmt.Errorf("failed to create storage entry: %v", err)
	}
	if err := externalStorage.Put(ctx, newEntry); err != nil {
		b.Logger().Error("Failed to store updated token", "path", tokenPath, "error", err)
		return nil, fmt.Errorf("failed to update token: %v", err)
	}

	return &logical.Response{
		Data: tokenDetail(&token),
	}, nil
}
