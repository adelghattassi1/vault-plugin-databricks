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

type CachedToken struct {
	AccessToken string
	ExpiresAt   time.Time
}
type DatabricksBackend struct {
	*framework.Backend
	client    *http.Client
	clients   map[string]*databricks.WorkspaceClient
	view      logical.Storage
	lock      sync.RWMutex
	roleLocks []*locksutil.LockEntry
	stopCh    chan struct{}
	ctx       context.Context    // New context for the backend's lifetime
	cancel    context.CancelFunc // Function to cancel the context
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
	go b.startTokenRotation(b.ctx, conf.StorageView) // Use b.ctx instead of ctx
	return b, nil
}

func Backend(conf *logical.BackendConfig) *DatabricksBackend {
	ctx, cancel := context.WithCancel(context.Background()) // Create a long-lived context
	backend := &DatabricksBackend{
		view:      conf.StorageView,
		clients:   make(map[string]*databricks.WorkspaceClient),
		roleLocks: locksutil.CreateLocks(),
		stopCh:    make(chan struct{}),
		ctx:       ctx,    // Assign the context
		cancel:    cancel, // Assign the cancel function
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

func (b *DatabricksBackend) Cleanup(ctx context.Context) {
	b.cancel()
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
