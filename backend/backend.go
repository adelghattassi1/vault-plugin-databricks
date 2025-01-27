package backend

import (
	"context"
	"strings"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/logical"
)

type DatabricksBackend struct {
	*framework.Backend
	view      logical.Storage
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
		view:      conf.StorageView,
		roleLocks: locksutil.CreateLocks(),
	}

	backend.Backend = &framework.Backend{
		BackendType: logical.TypeLogical,
		Help:        strings.TrimSpace(backendHelp),
		Paths: framework.PathAppend(
			pathConfig(backend),
		),
	}

	return backend
}

const backendHelp = `
The Databricks token engine dynamically generates Databricks API tokens
for managing resources. This enables users to gain access to Databricks
without needing to manage static API tokens.

Configure credentials using the "config/" endpoints. Generate tokens using the "token/" endpoints.
`
