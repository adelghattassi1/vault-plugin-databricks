package backend

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func NoTTLWarning(s string) string {
	return fmt.Sprintf("%s is not set. Token can be generated with expiration 'never'", s)
}

func LT24HourTTLWarning(s string) string {
	return fmt.Sprintf("%[1]s is set with less than 24 hours. With current token expiry limitation, this %[1]s is ignored", s)
}

// schema for the configuring Gitlab token plugin, this will map the fields coming in from the
// vault request field map
var configSchema = map[string]*framework.FieldSchema{
	"base_url": {
		Type:        framework.TypeString,
		Description: `databricks base url`,
		Default:     "https://databricks.cloud.com",
	},
	"token": {
		Type:        framework.TypeString,
		Description: `databricks token that has permissions to generate on behalf of access tokens`,
	},
	"max_ttl": {
		Type:        framework.TypeDurationSecond,
		Description: `Maximum lifetime a generated token will be valid for. If <= 0, will use system default(0, never expire)`,
		Default:     0,
	},
}

func configDetail(config *ConfigStorageEntry) map[string]interface{} {
	return map[string]interface{}{
		"base_url": config,
		"max_ttl":  int64(config.MaxTTL / time.Second),
	}
}

func (b *DatabricksBackend) pathConfigList() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "config/?",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.handleConfigList,
				},
			},
		},
	}
}

func (b *DatabricksBackend) handleConfigList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	keys, err := req.Storage.List(ctx, "config/")
	if err != nil {
		return nil, fmt.Errorf("failed to list configurations: %v", err)
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"keys": keys,
		},
	}, nil
}

//func (b *DatabricksBackend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
//	config, err := getConfig(ctx, req.Storage)
//	if err != nil {
//		return nil, err
//	}
//	if config == nil {
//		return nil, nil
//	}
//
//	return &logical.Response{
//		Data: configDetail(config),
//	}, nil
//}
//
//func (b *DatabricksBackend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
//	warnings := []string{}
//
//	config, err := getConfig(ctx, req.Storage)
//	if err != nil {
//		return nil, err
//	}
//	if config == nil {
//		config = &ConfigStorageEntry{}
//	}
//
//	baseURL, ok := data.GetOk("base_url")
//	if ok {
//		config.BaseURL = baseURL.(string)
//	} else if config.BaseURL == "" {
//		config.BaseURL = configSchema["base_url"].Default.(string)
//	}
//
//	if token, ok := data.GetOk("token"); ok {
//		config.Token = token.(string)
//	}
//
//	maxTTLRaw, ok := data.GetOk("max_ttl")
//	if ok && maxTTLRaw.(int) > 0 {
//		// Until Gitlab implements granular token expiry.
//		// bounce anything less than 24 hours
//		if maxTTLRaw.(int) < (24 * 3600) {
//			warnings = append(warnings, LT24HourTTLWarning("max_ttl"))
//		} else {
//			config.MaxTTL = time.Duration(maxTTLRaw.(int)) * time.Second
//		}
//	}
//
//	if config.MaxTTL == 0 {
//		warnings = append(warnings, NoTTLWarning("max_ttl"))
//	}
//
//	// maxTTLRaw, ok := data.GetOk("max_ttl")
//	// if ok && maxTTLRaw.(int) > 0 {
//	// 	config.MaxTTL = time.Duration(maxTTLRaw.(int)) * time.Second
//	// } else if config.MaxTTL == time.Duration(0) {
//	// 	config.MaxTTL = time.Duration(configSchema["max_ttl"].Default.(int)) * time.Second
//	// }
//
//	entry, err := logical.StorageEntryJSON(pathPatternConfig, config)
//	if err != nil {
//		return nil, err
//	}
//
//	if err := req.Storage.Put(ctx, entry); err != nil {
//		return nil, err
//	}
//
//	return &logical.Response{
//		Data:     configDetail(config),
//		Warnings: warnings,
//	}, nil
//}

//func pathConfig(b *DatabricksBackend) []*framework.Path {
//	paths := []*framework.Path{
//		{
//			Pattern: pathPatternConfig,
//			Fields:  configSchema,
//
//			Operations: map[logical.Operation]framework.OperationHandler{
//				logical.ReadOperation: &framework.PathOperation{
//					Callback: b.pathConfigRead,
//				},
//				logical.UpdateOperation: &framework.PathOperation{
//					Callback: b.pathConfigWrite,
//					Examples: configExamples,
//				},
//			},
//
//			HelpSynopsis:    pathConfigHelpSyn,
//			HelpDescription: pathConfigHelpDesc,
//		},
//	}
//
//	return paths
//}

func pathConfig(b *DatabricksBackend) []*framework.Path {
	paths := []*framework.Path{
		{
			Pattern: "config/(?P<name>.+)",
			Fields:  configSchema,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.handleConfigWrite,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleConfigWrite,
					Examples: configExamples,
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleConfigRead,
				},
			},
			HelpSynopsis:    pathConfigHelpSyn,
			HelpDescription: pathConfigHelpDesc,
		},
	}
	return paths
}

func (b *DatabricksBackend) handleConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	config := &ConfigStorageEntry{
		BaseURL: d.Get("base_url").(string),
		Token:   d.Get("token").(string),
		MaxTTL:  time.Duration(d.Get("max_ttl").(int)) * time.Second,
	}

	entry, err := logical.StorageEntryJSON("config/"+name, config)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return &logical.Response{}, nil
}

func (b *DatabricksBackend) handleConfigRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	entry, err := req.Storage.Get(ctx, "config/"+name)
	if err != nil || entry == nil {
		return nil, fmt.Errorf("failed to retrieve configuration")
	}

	var config ConfigStorageEntry
	if err := entry.DecodeJSON(&config); err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"base_url": config.BaseURL,
			"token":    config.Token,
			"max_ttl":  config.MaxTTL.Seconds(),
		},
	}, nil
}

const pathConfigHelpSyn = `
Configure the Databricks backend.
`

const pathConfigHelpDesc = `
The Databricks backend requires credentials for creating a project access token.
This endpoint is used to configure those credentials as well as default values
for the backend in general.
`

var configExamples = []framework.RequestExample{
	{
		Description: "Create/update backend configuration",
		Data: map[string]interface{}{
			"base_url": "https://my.Databricks.com",
			"token":    "MyPersonalAccessToken",
			"max_ttl":  "168h",
		},
	},
}
