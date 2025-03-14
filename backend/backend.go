package backend

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/databricks/databricks-sdk-go"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	tokenCheckInterval  = 87600 * time.Hour
	rotationGracePeriod = 5 * time.Hour
)

type DatabricksBackend struct {
	*framework.Backend
	client      *http.Client
	clients     map[string]*databricks.WorkspaceClient
	view        logical.Storage
	lock        sync.RWMutex
	roleLocks   []*locksutil.LockEntry
	ctx         context.Context
	cancel      context.CancelFunc
	vaultClient *api.Client // Vault API client for external storage
}

func (b *DatabricksBackend) getClient() *http.Client {
	if b.client == nil {
		b.client = &http.Client{
			Timeout: 10 * time.Second,
		}
	}
	return b.client
}

func (b *DatabricksBackend) getWorkspaceClient(config ConfigStorageEntry) (*databricks.WorkspaceClient, error) {
	key := config.BaseURL + config.ClientID
	b.lock.RLock()
	client, exists := b.clients[key]
	b.lock.RUnlock()
	b.Logger().Info("Checking Databricks client", "exists", exists)
	if exists {
		return client, nil
	}

	cfg := &databricks.Config{
		Host:         config.BaseURL,
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		AuthType:     "oauth-m2m",
	}
	client, err := databricks.NewWorkspaceClient(cfg)
	if err != nil {
		b.Logger().Error("Failed to create Databricks client", "error", err)
		return nil, fmt.Errorf("failed to create Databricks client: %v", err)
	}

	b.lock.Lock()
	b.clients[key] = client
	b.lock.Unlock()
	b.Logger().Info("Created new Databricks client", "key", key)
	return client, nil
}

// getExternalStorage returns an adapted Vault API client for the "gtn" mount
func (b *DatabricksBackend) getExternalStorage() (logical.Storage, error) {
	if b.vaultClient == nil {
		return nil, fmt.Errorf("Vault API client not initialized")
	}
	return &APILogicalStorage{
		client:     b.vaultClient.Logical(),
		mountPoint: "gtn",
	}, nil
}

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := Backend(conf)

	token, ok := conf.Config["token"]
	if !ok || token == "" {
		return nil, fmt.Errorf("missing token in configuration for Vault API client")
	}
	vaultAddr, ok := conf.Config["address"]
	if !ok || vaultAddr == "" {
		return nil, fmt.Errorf("missing vaultAddr in configuration for Vault API client")
	}
	client, err := api.NewClient(&api.Config{
		Address: vaultAddr,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %v", err)
	}
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // Disable TLS verification
			},
		},
	}

	// Initialize Vault API client with custom HTTP client
	client, err = api.NewClient(&api.Config{
		Address:    vaultAddr,
		HttpClient: httpClient, // Use custom client with InsecureSkipVerify
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %v", err)
	}
	client.SetToken(token)
	b.vaultClient = client

	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	//go b.startTokenRotation(b.ctx, conf.StorageView)
	return b, nil
}

func Backend(conf *logical.BackendConfig) *DatabricksBackend {
	ctx, cancel := context.WithCancel(context.Background())
	backend := &DatabricksBackend{
		view:      conf.StorageView,
		clients:   make(map[string]*databricks.WorkspaceClient),
		roleLocks: locksutil.CreateLocks(),
		ctx:       ctx,
		cancel:    cancel,
	}
	backend.Backend = &framework.Backend{
		BackendType: logical.TypeLogical,
		Help:        strings.TrimSpace(backendHelp),
		Paths: framework.PathAppend(
			pathConfig(backend),
			pathConfigList(backend),
			pathTokenOperations(backend),
			pathListTokens(backend),
		),
	}
	return backend
}

func (b *DatabricksBackend) Cleanup(ctx context.Context) {
	b.cancel()
}

//func (b *DatabricksBackend) startTokenRotation(ctx context.Context, storage logical.Storage) {
//	ticker := time.NewTicker(tokenCheckInterval)
//	defer ticker.Stop()
//
//	for {
//		select {
//		case <-ctx.Done():
//			b.Logger().Info("Token rotation stopped")
//			return
//		case <-ticker.C:
//			b.Logger().Debug("Starting token rotation check")
//			b.rotateExpiredTokens(ctx, storage)
//		}
//	}
//}

//func (b *DatabricksBackend) rotateExpiredTokens(ctx context.Context, storage logical.Storage) {
//	b.lock.Lock()
//	defer b.lock.Unlock()
//
//	if ctx.Err() != nil {
//		b.Logger().Info("Skipping config listing due to canceled context")
//		return
//	}
//
//	externalStorage, err := b.getExternalStorage()
//	if err != nil {
//		b.Logger().Error("Failed to get external storage", "error", err)
//		return
//	}
//
//	configs, err := externalStorage.List(ctx, "")
//	if err != nil {
//		b.Logger().Error("Failed to list configs for rotation", "error", err)
//		return
//	}
//
//	for _, config := range configs {
//		if ctx.Err() != nil {
//			b.Logger().Info("Skipping token listing due to canceled context")
//			break
//		}
//
//		tokens, err := externalStorage.List(ctx, fmt.Sprintf("%s/tokens/", config))
//		if err != nil {
//			b.Logger().Error("Failed to list tokens for config", "config", config, "error", err)
//			continue
//		}
//
//		for _, tokenName := range tokens {
//			b.checkAndRotateToken(ctx, externalStorage, config, tokenName)
//		}
//	}
//}

const backendHelp = `
The Databricks token engine dynamically generates Databricks API tokens
for managing resources. This enables users to gain access to Databricks
without needing to manage static API tokens. Tokens are automatically
rotated before expiration to ensure continuous access.

Configure service principals using the "sp/" endpoints. Generate tokens using the "token/" endpoints.
`
