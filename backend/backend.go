package backend

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/databricks/databricks-sdk-go"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	tokenCheckInterval  = 5 * time.Minute // Check every hour
	rotationGracePeriod = 1 * time.Minute // Rotate 1 hour before expiry
)

type DatabricksBackend struct {
	*framework.Backend
	client    *http.Client
	clients   map[string]*databricks.WorkspaceClient // Added for client caching
	view      logical.Storage
	lock      sync.RWMutex
	roleLocks []*locksutil.LockEntry
	stopCh    chan struct{} // Added for rotation cleanup
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
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	// Start token rotation
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
			pathReadDeleteToken(backend),
			pathListTokens(backend),
			pathUpdateToken(backend),
		),
	}

	return backend
}

// Cleanup method to stop rotation goroutine
func (b *DatabricksBackend) Cleanup(ctx context.Context) {
	close(b.stopCh)
}

// Token rotation background process
func (b *DatabricksBackend) startTokenRotation(ctx context.Context, storage logical.Storage) {
	ticker := time.NewTicker(tokenCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-b.stopCh:
			return
		case <-ticker.C:
			b.rotateExpiredTokens(ctx, storage)
		}
	}
}

func (b *DatabricksBackend) rotateExpiredTokens(ctx context.Context, storage logical.Storage) {
	b.lock.Lock()
	defer b.lock.Unlock()

	configs, err := storage.List(ctx, "config/")
	if err != nil {
		b.Logger().Error("Failed to list configs for rotation", "error", err)
		return
	}

	for _, config := range configs {
		tokens, err := storage.List(ctx, fmt.Sprintf("%s/%s/", pathPatternToken, config))
		if err != nil {
			b.Logger().Error("Failed to list tokens for rotation", "error", err)
			continue
		}

		for _, tokenID := range tokens {
			b.checkAndRotateToken(ctx, storage, config, tokenID)
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
