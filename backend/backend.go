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
		Help: "Plugin to create Databricks on-behalf-of tokens",
		Paths: []*framework.Path{
			b.pathCreateToken(),
		},
	}
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
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

// tokenExists checks if a token exists
func (b *backend) tokenExists(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	// For simplicity, return false to allow creation
	// Implement logic here if you have a way to check token existence
	return false, nil
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

	return &logical.Response{
		Data: responseMap,
	}, nil
}
