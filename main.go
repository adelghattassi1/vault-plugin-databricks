package main

import (
	"os"

	"github.com/adelghattassi1/vault-plugin-databricks/backend"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/plugin"
)

func main() {
	logger := hclog.New(&hclog.LoggerOptions{})

	if err := run(logger); err != nil {
		logger.Error("plugin shutting down", "error", err)
		os.Exit(1)
	}
}

func run(logger hclog.Logger) error {
	meta := &api.PluginAPIClientMeta{}
	if err := meta.FlagSet().Parse(os.Args[1:]); err != nil {
		return err
	}

	return plugin.Serve(&plugin.ServeOpts{
		TLSProviderFunc:    api.VaultPluginTLSProvider(meta.GetTLSConfig()),
		BackendFactoryFunc: backend.Factory,
		Logger:             logger,
	})
}
