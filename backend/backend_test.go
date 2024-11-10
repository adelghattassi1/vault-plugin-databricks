package backend

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

// TestBackendFactory tests the creation of the backend.
func TestBackendFactory(t *testing.T) {
	b, err := Factory(context.Background(), &logical.BackendConfig{
		System:      &logical.StaticSystemView{},
		StorageView: &logical.InmemStorage{},
	})
	if err != nil {
		t.Fatalf("unable to create backend: %v", err)
	}

	if b == nil {
		t.Fatal("backend is nil")
	}
}

// TestHandleCreateToken tests the handleCreateToken function.
func TestHandleCreateToken(t *testing.T) {
	backend, err := Factory(context.Background(), &logical.BackendConfig{
		System:      &logical.StaticSystemView{},
		StorageView: &logical.InmemStorage{},
	})
	if err != nil {
		t.Fatalf("unable to create backend: %v", err)
	}

	databricksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST request, got %s", r.Method)
		}

		var reqBody map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
			t.Fatal(err)
		}

		if reqBody["application_id"] != "test-app-id" {
			t.Fatalf("expected application_id 'test-app-id', got %v", reqBody["application_id"])
		}

		response := map[string]interface{}{
			"token_value": "dapicbd47dac9bba881f2f00727e8ab5b5cc",
			"token_info": map[string]interface{}{
				"token_id": "5684c955822ac792a51ae2aeb80190f13457bab3e2e2934c133a08b38454816c",
				"comment":  "Test token",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer databricksServer.Close()

	databricksInstanceURL := databricksServer.URL
	storage := &logical.InmemStorage{} // Initialize in-memory storage

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "token/create",
		Data: map[string]interface{}{
			"databricks_url":   databricksInstanceURL,
			"application_id":   "test-app-id",
			"lifetime_seconds": 3600,
			"comment":          "Test token",
		},
		Storage: storage,
	}

	resp, err := backend.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("handle request: %v", err)
	}

	if resp == nil {
		t.Fatal("expected response")
	}

	tokenValue, ok := resp.Data["token_value"].(string)
	if !ok || tokenValue != "dapicbd47dac9bba881f2f00727e8ab5b5cc" {
		t.Fatalf("unexpected token value: %v", resp.Data["token_value"])
	}
}
