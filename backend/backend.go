package backend

import (
	"context"
	"net/http"
	"strings"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/logical"
)

type DatabricksBackend struct {
	*framework.Backend
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

func Backend(conf *logical.BackendConfig) *DatabricksBackend {
	backend := &DatabricksBackend{
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

func (b *DatabricksBackend) invalidate(ctx context.Context, key string) {
	switch key {
	case pathPatternConfig:
		b.reset()
	}
}

func (b *DatabricksBackend) reset() {
	b.lock.Lock()
	defer b.lock.Unlock()

	b.client = nil
}

const backendHelp = `
The Databricks token engine dynamically generates Databricks API tokens
for managing resources. This enables users to gain access to Databricks
without needing to manage static API tokens.

Configure credentials using the "config/" endpoints. Generate tokens using the "token/" endpoints.
`
