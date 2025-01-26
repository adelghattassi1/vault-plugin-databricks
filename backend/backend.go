package databrickstoken

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/logical"
)

const pathPatternConfig = "config/"

// DatabricksBackend is the backend for the Databricks plugin
type DatabricksBackend struct {
	*framework.Backend
	view      logical.Storage
	client    *http.Client
	lock      sync.RWMutex
	roleLocks []*locksutil.LockEntry
}

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := Backend(conf)
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

// Backend initializes and returns a new DatabricksBackend
func Backend(conf *logical.BackendConfig) *DatabricksBackend {
	backend := &DatabricksBackend{
		view:      conf.StorageView,
		roleLocks: locksutil.CreateLocks(),
		client:    &http.Client{},
	}

	backend.Backend = &framework.Backend{
		BackendType: logical.TypeLogical,
		Help:        strings.TrimSpace(backendHelp),
		Paths: []*framework.Path{
			backend.pathConfig(),
			backend.pathCreateToken(),
			backend.pathReadToken(),
			backend.pathListTokens(),
			backend.pathUpdateToken(),
		},
		Invalidate: backend.invalidate,
	}

	return backend
}

func (b *DatabricksBackend) getClient() *http.Client {
	b.lock.RLock()
	defer b.lock.RUnlock()

	return b.client
}

func (b *DatabricksBackend) reset() {
	b.lock.Lock()
	defer b.lock.Unlock()

	b.client = nil
}

func (b *DatabricksBackend) invalidate(ctx context.Context, key string) {
	switch key {
	case pathPatternConfig:
		b.reset()
	}
}

func (b *DatabricksBackend) pathConfig() *framework.Path {
	return &framework.Path{
		Pattern: pathPatternConfig,
		Fields: map[string]*framework.FieldSchema{
			"databricks_token": {
				Type:        framework.TypeString,
				Description: "Databricks token used for authentication.",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.handleWriteConfig,
			logical.CreateOperation: b.handleWriteConfig,
			logical.ReadOperation:   b.handleReadConfig,
		},
		HelpSynopsis: "This path allows you to configure Databricks settings for token management.",
	}
}

func (b *DatabricksBackend) handleWriteConfig(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	databricksToken, ok := data.GetOk("databricks_token")
	if !ok {
		return nil, fmt.Errorf("missing databricks_token in request")
	}

	entry := &logical.StorageEntry{
		Key:   pathPatternConfig,
		Value: []byte(databricksToken.(string)),
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, fmt.Errorf("failed to store configuration: %v", err)
	}

	return nil, nil
}

func (b *DatabricksBackend) handleReadConfig(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	entry, err := req.Storage.Get(ctx, pathPatternConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to read configuration: %v", err)
	}
	if entry == nil {
		return nil, fmt.Errorf("configuration not found")
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"databricks_token": string(entry.Value),
		},
	}, nil
}

func (b *DatabricksBackend) pathCreateToken() *framework.Path {
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
	}
}

func (b *DatabricksBackend) handleCreateToken(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	databricksInstance, ok := d.GetOk("databricks_url")
	if !ok {
		return nil, fmt.Errorf("databricks_url not provided")
	}
	applicationID, ok := d.GetOk("application_id")
	if !ok {
		return nil, fmt.Errorf("application_id not provided")
	}
	lifetimeSeconds, ok := d.GetOk("lifetime_seconds")
	if !ok {
		return nil, fmt.Errorf("lifetime_seconds not provided")
	}

	comment, _ := d.GetOk("comment") // Comment is optional

	requestPayload := map[string]interface{}{
		"application_id":   applicationID.(string),
		"lifetime_seconds": lifetimeSeconds.(int),
		"comment":          comment,
	}

	requestBody, err := json.Marshal(requestPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %v", err)
	}

	apiURL := fmt.Sprintf("%s/api/2.0/token-management/on-behalf-of/tokens", databricksInstance.(string))

	httpReq, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %v", err)
	}

	databricksToken := os.Getenv("DATABRICKS_TOKEN")
	if databricksToken == "" {
		return nil, fmt.Errorf("DATABRICKS_TOKEN environment variable is not set")
	}
	httpReq.Header.Set("Authorization", "Bearer "+databricksToken)
	httpReq.Header.Set("Content-Type", "application/json")

	client := b.getClient()
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to perform HTTP request: %v", err)
	}
	defer func(Body io.ReadCloser) {
		if err := Body.Close(); err != nil {
			b.Logger().Warn("failed to close response body", "error", err)
		}
	}(resp.Body)

	bodyBytes, _ := io.ReadAll(resp.Body)
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

	key := fmt.Sprintf("tokens/%s", tokenID)
	entry := &logical.StorageEntry{
		Key:   key,
		Value: bodyBytes,
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, fmt.Errorf("failed to store token in Vault: %v", err)
	}

	return &logical.Response{
		Data: responseMap,
	}, nil
}

func (b *DatabricksBackend) pathReadToken() *framework.Path {
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

func (b *DatabricksBackend) handleReadToken(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	tokenID, ok := d.GetOk("token_id")
	if !ok {
		return nil, fmt.Errorf("token_id not provided")
	}

	entry, err := req.Storage.Get(ctx, fmt.Sprintf("tokens/%s", tokenID.(string)))
	if err != nil {
		return nil, fmt.Errorf("failed to read token: %v", err)
	}
	if entry == nil {
		return nil, fmt.Errorf("token not found")
	}

	var tokenData map[string]interface{}
	if err := json.Unmarshal(entry.Value, &tokenData); err != nil {
		return nil, fmt.Errorf("failed to parse stored token data: %v", err)
	}

	return &logical.Response{
		Data: tokenData,
	}, nil
}

func (b *DatabricksBackend) pathListTokens() *framework.Path {
	return &framework.Path{
		Pattern: "token/list",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.handleListTokens,
			},
		},
	}
}

func (b *DatabricksBackend) handleListTokens(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
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

func (b *DatabricksBackend) pathUpdateToken() *framework.Path {
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

func (b *DatabricksBackend) handleUpdateToken(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	tokenID, ok := d.GetOk("token_id")
	if !ok {
		return nil, fmt.Errorf("token_id not provided")
	}
	newComment, ok := d.GetOk("comment")
	if !ok {
		return nil, fmt.Errorf("comment not provided")
	}

	entry, err := req.Storage.Get(ctx, fmt.Sprintf("tokens/%s", tokenID.(string)))
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

const backendHelp = `
The Databricks token engine dynamically generates Databricks API tokens
for managing resources. This enables users to gain access to Databricks
without needing to manage static API tokens.

Configure credentials using the "config/" endpoints. Generate tokens using the "token/" endpoints.
`
