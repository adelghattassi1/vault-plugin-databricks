package backend

import (
	"net/http"
)

func (b *DatabricksBackend) getClient() *http.Client {
	b.lock.RLock()
	defer b.lock.RUnlock()

	return b.client
}
