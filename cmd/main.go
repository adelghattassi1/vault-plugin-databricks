package main

import (
	"os"

	"github.com/adelghattassi1/vault-plugin-databricks/backend"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/plugin"
)

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}

	flags := apiClientMeta.FlagSet()
	if err := flags.Parse(os.Args[1:]); err != nil {
		fatalErr(err)
	}

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	if err := plugin.ServeMultiplex(&plugin.ServeOpts{
		BackendFactoryFunc: backend.Factory,
		TLSProviderFunc:    tlsProviderFunc,
	}); err != nil {
		fatalErr(err)
	}
}

func fatalErr(err error) {
	hclog.New(&hclog.LoggerOptions{}).Error(
		"plugin shutting down",
		"error",
		err,
	)
	os.Exit(1)
}
