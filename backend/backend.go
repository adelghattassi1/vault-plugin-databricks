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
	tokenCheckInterval  = 2 * time.Minute
	rotationGracePeriod = 5 * time.Minute
)

type DatabricksBackend struct {
	*framework.Backend
	client    *http.Client
	clients   map[string]*databricks.WorkspaceClient
	view      logical.Storage
	lock      sync.RWMutex
	roleLocks []*locksutil.LockEntry
	ctx       context.Context
	cancel    context.CancelFunc
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
	client, exists := b.clients[key]
	b.Logger().Info("failed to create Databricks client: ", " exists", exists)
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
		b.Logger().Info("failed to create Databricks client: ", " error", err)
		return nil, fmt.Errorf("failed to create Databricks client: %v", err)
	}

	b.lock.Lock()
	b.clients[key] = client
	b.Logger().Info("failed to create Databricks client: ", "b.clients[key] ", b.clients[key])
	b.lock.Unlock()
	return client, nil
}

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := Backend(conf)
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	go b.startTokenRotation(b.ctx, conf.StorageView)
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
			pathCreateToken(backend),
			pathTokenOperations(backend),
			pathListTokens(backend),
		),
	}
	return backend
}

func (b *DatabricksBackend) Cleanup(ctx context.Context) {
	b.cancel()
}

func (b *DatabricksBackend) startTokenRotation(ctx context.Context, storage logical.Storage) {
	ticker := time.NewTicker(tokenCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			b.Logger().Info("Token rotation stopped")
			return
		case <-ticker.C:
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
