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
	clients   map[string]*databricks.WorkspaceClient
	view      logical.Storage
	lock      sync.RWMutex
	roleLocks []*locksutil.LockEntry
	stopCh    chan struct{}
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

	// Start token rotation goroutine with a cancellable context
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

// Cleanup closes the stop channel to terminate the rotation goroutine
func (b *DatabricksBackend) Cleanup(ctx context.Context) {
	close(b.stopCh)
}

// startTokenRotation runs a background process to check and rotate tokens
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
			// Check context before proceeding
			if ctx.Err() != nil {
				b.Logger().Info("Skipping token rotation due to canceled context")
				return
			}
			b.rotateExpiredTokens(ctx, storage)
		}
	}
}

// rotateExpiredTokens checks all stored tokens and rotates expired ones
func (b *DatabricksBackend) rotateExpiredTokens(ctx context.Context, storage logical.Storage) {
	b.lock.Lock()
	defer b.lock.Unlock()

	// Check context before listing configs
	if ctx.Err() != nil {
		b.Logger().Info("Skipping config listing due to canceled context")
		return
	}

	configs, err := storage.List(ctx, "config/")
	if err != nil {
		// Log the error but check if it's due to context cancellation
		if ctx.Err() != nil {
			b.Logger().Info("Failed to list configs for rotation due to context cancellation", "error", err)
		} else {
			b.Logger().Error("Failed to list configs for rotation", "error", err)
		}
		return
	}

	for _, config := range configs {
		// Check context before listing tokens
		if ctx.Err() != nil {
			b.Logger().Info("Skipping token listing due to canceled context")
			return
		}

		tokens, err := storage.List(ctx, fmt.Sprintf("%s/%s/", pathPatternToken, config))
		if err != nil {
			if ctx.Err() != nil {
				b.Logger().Info("Failed to list tokens for rotation due to context cancellation", "error", err)
			} else {
				b.Logger().Error("Failed to list tokens for rotation", "error", err)
			}
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
