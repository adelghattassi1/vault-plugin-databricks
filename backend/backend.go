package backend

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type backend struct {
	*framework.Backend
}

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := &backend{}
	b.Backend = &framework.Backend{
		Help: "Plugin to manage Databricks on-behalf-of tokens",
		Paths: []*framework.Path{
			b.pathCreateToken(),
			b.pathReadToken(),
			b.pathListTokens(),
			b.pathUpdateToken(),
		},
	}
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func (b *backend) Type() logical.BackendType {
	return logical.TypeLogical
}

func (b *backend) pathCreateToken() *framework.Path {
	return &framework.Path{
		Pattern: "token/create",
		Fields: map[string]*framework.FieldSchema{
			"databricks_url": {
				Type:        framework.TypeString,
				Description: "URL of the Databricks instance.",
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
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.handleCreateToken,
			},
		},
		ExistenceCheck: b.tokenExists,
	}
}

func (b *backend) pathReadToken() *framework.Path {
	return &framework.Path{
		Pattern: "token/read/(?P<token_id>.+)",
		Fields: map[string]*framework.FieldSchema{
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
	}
}

func (b *backend) pathListTokens() *framework.Path {
	return &framework.Path{
		Pattern: "token/list",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.handleListTokens,
			},
		},
	}
}

func (b *backend) pathUpdateToken() *framework.Path {
	return &framework.Path{
		Pattern: "token/update/(?P<token_id>.+)",
		Fields: map[string]*framework.FieldSchema{
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
	}
}

func (b *backend) tokenExists(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	key := "tokens/" + d.Get("token_id").(string)
	entry, err := req.Storage.Get(ctx, key)
	if err != nil || entry == nil {
		return false, nil
	}
	return true, nil
}

func (b *backend) handleCreateToken(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	databricksInstance := d.Get("databricks_url").(string)
	applicationID := d.Get("application_id").(string)
	lifetimeSeconds := d.Get("lifetime_seconds").(int)
	comment := d.Get("comment").(string)

	requestPayload := map[string]interface{}{
		"application_id":   applicationID,
		"lifetime_seconds": lifetimeSeconds,
		"comment":          comment,
	}

	requestBody, err := json.Marshal(requestPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %v", err)
	}

	apiURL := fmt.Sprintf("%s/api/2.0/token-management/on-behalf-of/tokens", databricksInstance)

	httpReq, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %v", err)
	}

	httpReq.Header.Set("Authorization", "Bearer "+os.Getenv("DATABRICKS_TOKEN"))
	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to perform HTTP request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to create token, status code: %d", resp.StatusCode)
	}

	var responseMap map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&responseMap); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	// Store the token information in the storage backend
	key := fmt.Sprintf("tokens/%s", responseMap["token_info"].(map[string]interface{})["token_id"].(string))
	entry := &logical.StorageEntry{
		Key:   key,
		Value: requestBody, // Store the request body or responseMap as needed
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, fmt.Errorf("failed to store token: %v", err)
	}

	return &logical.Response{
		Data: responseMap,
	}, nil
}

func (b *backend) handleReadToken(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	tokenID := d.Get("token_id").(string)

	// Retrieve token data from storage
	entry, err := req.Storage.Get(ctx, "tokens/"+tokenID)
	if err != nil {
		return nil, fmt.Errorf("failed to read token: %v", err)
	}
	if entry == nil {
		return nil, nil // Return nil if the token ID does not exist
	}

	var tokenData map[string]interface{}
	if err := json.Unmarshal(entry.Value, &tokenData); err != nil {
		return nil, fmt.Errorf("failed to parse token data: %v", err)
	}

	return &logical.Response{
		Data: tokenData,
	}, nil
}

func (b *backend) handleListTokens(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	keys, err := req.Storage.List(ctx, "tokens/")
	if err != nil {
		return nil, fmt.Errorf("failed to list tokens: %v", err)
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"keys": keys,
		},
	}, nil
}

func (b *backend) handleUpdateToken(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	tokenID := d.Get("token_id").(string)
	newComment := d.Get("comment").(string)

	// Retrieve token data from storage
	entry, err := req.Storage.Get(ctx, "tokens/"+tokenID)
	if err != nil || entry == nil {
		return nil, fmt.Errorf("failed to find token: %v", err)
	}

	var tokenData map[string]interface{}
	if err := json.Unmarshal(entry.Value, &tokenData); err != nil {
		return nil, fmt.Errorf("failed to parse token data: %v", err)
	}

	// Update the comment
	tokenData["comment"] = newComment

	// Marshal the updated data and store it back
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
