package backend

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"io"
	"net/http"
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

func (b *DatabricksBackend) handleCreateToken(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	configName, ok := d.GetOk("config_name")
	if !ok {
		return nil, fmt.Errorf("config_name not provided")
	}
	configNameStr := configName.(string)

	entry, err := req.Storage.Get(ctx, "config/"+configNameStr)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve configuration: %v", err)
	}
	if entry == nil {
		return nil, fmt.Errorf("configuration not found with name: %s", configNameStr)
	}

	var config ConfigStorageEntry
	if err := entry.DecodeJSON(&config); err != nil {
		return nil, fmt.Errorf("error decoding configuration: %v", err)
	}

	databricksInstance := config.BaseURL
	databricksToken := config.Token

	// Retrieve token creation parameters
	applicationID, ok := d.GetOk("application_id")
	if !ok {
		return nil, fmt.Errorf("application_id not provided")
	}
	lifetimeSeconds, ok := d.GetOk("lifetime_seconds")
	if !ok {
		return nil, fmt.Errorf("lifetime_seconds not provided")
	}
	comment, _ := d.GetOk("comment") // Comment is optional

	// Prepare the request payload
	requestPayload := map[string]interface{}{
		"application_id":   applicationID.(string),
		"lifetime_seconds": lifetimeSeconds.(int),
		"comment":          comment,
	}

	requestBody, err := json.Marshal(requestPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %v", err)
	}

	apiURL := fmt.Sprintf("%s/api/2.0/token-management/on-behalf-of/tokens", databricksInstance)

	// Create and configure the HTTP request
	httpReq, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %v", err)
	}
	if databricksToken == "" {
		return nil, fmt.Errorf("Databricks token not configured")
	}
	httpReq.Header.Set("Authorization", "Bearer "+databricksToken)
	httpReq.Header.Set("Content-Type", "application/json")

	client := b.getClient() // Assume b.getClient() returns an *http.Client
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to perform HTTP request: %v", err)
	}
	defer resp.Body.Close()

	// Read and process the response
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to create token, status code: %d, response: %s", resp.StatusCode, string(bodyBytes))
	}

	var responseMap map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &responseMap); err != nil {
		return nil, fmt.Errorf("failed to parse Databricks API response: %v", err)
	}

	tokenInfo, ok := responseMap["token_info"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("databricks API response missing token_info field")
	}

	tokenID, ok := tokenInfo["token_id"].(string)
	if !ok {
		return nil, fmt.Errorf("token_info field missing token_id")
	}

	key := fmt.Sprintf("tokens/%s/%s", configNameStr, tokenID)

	tokenEntry := &logical.StorageEntry{
		Key:   key,
		Value: bodyBytes,
	}

	if err := req.Storage.Put(ctx, tokenEntry); err != nil {
		return nil, fmt.Errorf("failed to store token in Vault: %v", err)
	}

	return &logical.Response{
		Data: responseMap,
	}, nil
}

func pathReadToken(b *DatabricksBackend) []*framework.Path {
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

	entry, err := req.Storage.Get(ctx, fmt.Sprintf("tokens/%s/%s", configName.(string), tokenID.(string)))
	if err != nil {
		return nil, fmt.Errorf("failed to read token: %v", err)
	}
	if entry == nil {
		return nil, fmt.Errorf("token not found for config: %s", configName.(string))
	}

	var tokenData map[string]interface{}
	if err := json.Unmarshal(entry.Value, &tokenData); err != nil {
		return nil, fmt.Errorf("failed to parse stored token data: %v", err)
	}

	return &logical.Response{
		Data: tokenData,
	}, nil
}

func pathListTokens(b *DatabricksBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: fmt.Sprintf("%s?/?", pathPatternToken),
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.handleListTokens,
				},
			},
		},
	}
}

func (b *DatabricksBackend) handleListTokens(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	tokens, err := req.Storage.List(ctx, fmt.Sprintf("%s/", pathPatternToken))
	if err != nil {
		return nil, fmt.Errorf("failed to list tokens for config: %s", pathPatternToken)
	}
	return logical.ListResponse(tokens), nil
}

func pathUpdateToken(b *DatabricksBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "token/update/(?P<config_name>[^/]+)/(?P<token_id>[^/]+)",
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

	entry, err := req.Storage.Get(ctx, fmt.Sprintf("tokens/%s/%s", configName.(string), tokenID.(string)))
	if err != nil || entry == nil {
		return nil, fmt.Errorf("failed to find token: %v", err)
	}

	var tokenData map[string]interface{}
	if err := json.Unmarshal(entry.Value, &tokenData); err != nil {
		return nil, fmt.Errorf("failed to parse token data: %v", err)
	}

	tokenData["comment"] = newComment

	updatedValue, err := json.Marshal(tokenData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal updated token data: %v", err)
	}

	entry.Value = updatedValue
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, fmt.Errorf("failed to update token: %v", err)
	}

	return &logical.Response{
		Data: tokenData,
	}, nil
}
