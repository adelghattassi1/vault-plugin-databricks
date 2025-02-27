package backend

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/databricks/databricks-sdk-go"
	"github.com/hashicorp/vault/api" // Add Vault API package
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	tokenCheckInterval  = 2 * time.Minute
	rotationGracePeriod = 5 * time.Minute
)

type DatabricksBackend struct {
	*framework.Backend
	client      *http.Client
	vaultClient *api.Client // Vault API client for cross-mount operations
	clients     map[string]*databricks.WorkspaceClient
	view        logical.Storage
	lock        sync.RWMutex
	roleLocks   []*locksutil.LockEntry
	stopCh      chan struct{}
}

func (b *DatabricksBackend) getClient() *http.Client {
	if b.client == nil {
		b.client = &http.Client{
			Timeout: 10 * time.Second,
		}
	}
	return b.client
}

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := Backend(conf)

	// Initialize Vault client from config or environment
	vaultAddr := conf.Config["vault_addr"]
	vaultToken := conf.Config["vault_token"]
	if vaultAddr == "" {
		vaultAddr = os.Getenv("VAULT_ADDR")
	}
	if vaultToken == "" {
		vaultToken = os.Getenv("VAULT_TOKEN")
	}

	if vaultAddr != "" && vaultToken != "" {
		vaultClient, err := api.NewClient(&api.Config{
			Address: vaultAddr,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create Vault client: %v", err)
		}
		vaultClient.SetToken(vaultToken)
		b.vaultClient = vaultClient
		b.Logger().Info("Vault client initialized", "address", vaultAddr)
	} else {
		b.Logger().Warn("Vault client not initialized; vault_addr or vault_token missing")
	}

	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	go b.startTokenRotation(ctx, conf.StorageView)
	return b, nil
}

func Backend(conf *logical.BackendConfig) *DatabricksBackend {
	backend := &DatabricksBackend{
		view:      conf.StorageView,
		clients:   make(map[string]*databricks.WorkspaceClient),
		roleLocks: locksutil.CreateLocks(),
		stopCh:    make(chan struct{}),
	}

	backend.Backend = &framework.Backend{
		BackendType: logical.TypeLogical,
		Help:        strings.TrimSpace(backendHelp),
		Paths: framework.PathAppend(
			pathConfig(backend),
			pathConfigList(backend),
			pathCreateToken(backend),
			pathTokenOperations(backend),
			pathListTokens(backend),
		),
	}

	return backend
}

func (b *DatabricksBackend) Cleanup(ctx context.Context) {
	close(b.stopCh)
}

func (b *DatabricksBackend) startTokenRotation(ctx context.Context, storage logical.Storage) {
	ticker := time.NewTicker(tokenCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			b.Logger().Info("Token rotation stopped due to context cancellation")
			return
		case <-b.stopCh:
			b.Logger().Info("Token rotation stopped due to backend cleanup")
			return
		case <-ticker.C:
			if ctx.Err() != nil {
				b.Logger().Info("Skipping token rotation due to canceled context")
				continue
			}
			b.Logger().Debug("Starting token rotation check")
			b.rotateExpiredTokens(ctx, storage)
		}
	}
}

func (b *DatabricksBackend) rotateExpiredTokens(ctx context.Context, storage logical.Storage) {
	b.lock.Lock()
	defer b.lock.Unlock()

	if ctx.Err() != nil {
		b.Logger().Info("Skipping config listing due to canceled context")
		return
	}

	configs, err := storage.List(ctx, "config/")
	if err != nil {
		b.Logger().Error("Failed to list configs for rotation", "error", err)
		return
	}

	for _, config := range configs {
		if ctx.Err() != nil {
			b.Logger().Info("Skipping token listing due to canceled context")
			break
		}

		tokens, err := storage.List(ctx, fmt.Sprintf("%s/%s/", pathPatternToken, config))
		if err != nil {
			b.Logger().Error("Failed to list tokens for config", "config", config, "error", err)
			continue
		}

		for _, tokenName := range tokens {
			b.checkAndRotateToken(ctx, storage, config, tokenName)
		}
	}
}

const backendHelp = `
The Databricks token engine dynamically generates Databricks API tokens
for managing resources. This enables users to gain access to Databricks
without needing to manage static API tokens. Tokens are automatically
rotated before expiration to ensure continuous access.

Configure credentials using the "config/" endpoints. Generate tokens using the "token/" endpoints.
`
