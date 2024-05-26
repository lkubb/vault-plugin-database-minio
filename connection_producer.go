package minio

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/hashicorp/go-secure-stdlib/tlsutil"
	dbplugin "github.com/hashicorp/vault/sdk/database/dbplugin/v5"
	"github.com/hashicorp/vault/sdk/database/helper/connutil"
	api "github.com/minio/madmin-go/v3"
	iampolicy "github.com/minio/pkg/iam/policy"
	"github.com/mitchellh/mapstructure"
)

type minioConnectionProducer struct {
	Host              string      `json:"host" structs:"host" mapstructure:"host"`
	Port              int         `json:"port" structs:"port" mapstructure:"port"`
	Username          string      `json:"username" structs:"username" mapstructure:"username"`
	Password          string      `json:"password" structs:"password" mapstructure:"password"`
	TLS               bool        `json:"tls" structs:"tls" mapstructure:"tls"`
	InsecureTLS       bool        `json:"insecure_tls" structs:"insecure_tls" mapstructure:"insecure_tls"`
	TLSServerName     string      `json:"tls_server_name" structs:"tls_server_name" mapstructure:"tls_server_name"`
	TLSMinVersion     string      `json:"tls_min_version" structs:"tls_min_version" mapstructure:"tls_min_version"`
	PemBundle         string      `json:"pem_bundle" structs:"pem_bundle" mapstructure:"pem_bundle"`
	PemJSON           string      `json:"pem_json" structs:"pem_json" mapstructure:"pem_json"`
	ConnectTimeoutRaw interface{} `json:"connect_timeout" structs:"connect_timeout" mapstructure:"connect_timeout"`

	connectTimeout time.Duration
	rawConfig      map[string]interface{}
	sslOpts        *tls.Config

	Initialized bool
	Type        string
	client      *api.AdminClient
	sync.Mutex
}

func (c *minioConnectionProducer) Initialize(ctx context.Context, req dbplugin.InitializeRequest) error {
	c.Lock()
	defer c.Unlock()

	c.rawConfig = req.Config

	err := mapstructure.WeakDecode(req.Config, c)
	if err != nil {
		return err
	}

	if c.ConnectTimeoutRaw == nil {
		c.ConnectTimeoutRaw = "5s"
	}
	if c.Port == 0 {
		c.Port = 9000
	}
	c.connectTimeout, err = parseutil.ParseDurationSecond(c.ConnectTimeoutRaw)
	if err != nil {
		return fmt.Errorf("invalid connect_timeout: %w", err)
	}

	switch {
	case len(c.Host) == 0:
		return fmt.Errorf("host cannot be empty")
	case len(c.Username) == 0:
		return fmt.Errorf("username cannot be empty")
	case len(c.Password) == 0:
		return fmt.Errorf("password cannot be empty")
	case len(c.PemJSON) > 0 && len(c.PemBundle) > 0:
		return fmt.Errorf("cannot specify both pem_json and pem_bundle")
	}

	var tlsMinVersion uint16 = tls.VersionTLS12
	if c.TLSMinVersion != "" {
		ver, exists := tlsutil.TLSLookup[c.TLSMinVersion]
		if !exists {
			return fmt.Errorf("unrecognized TLS version [%s]", c.TLSMinVersion)
		}
		tlsMinVersion = ver
	}

	switch {
	case len(c.PemJSON) != 0:
		cfg, err := jsonBundleToTLSConfig(c.PemJSON, tlsMinVersion, c.TLSServerName, c.InsecureTLS)
		if err != nil {
			return fmt.Errorf("failed to parse pem_json: %w", err)
		}
		c.sslOpts = cfg
		c.TLS = true

	case len(c.PemBundle) != 0:
		cfg, err := pemBundleToTLSConfig(c.PemBundle, tlsMinVersion, c.TLSServerName, c.InsecureTLS)
		if err != nil {
			return fmt.Errorf("failed to parse pem_bundle: %w", err)
		}
		c.sslOpts = cfg
		c.TLS = true

	case c.InsecureTLS:
		c.sslOpts = &tls.Config{
			InsecureSkipVerify: c.InsecureTLS,
		}

	case c.TLS:
		c.sslOpts = &tls.Config{
			ServerName:         c.TLSServerName,
			InsecureSkipVerify: c.InsecureTLS,
			MinVersion:         tlsMinVersion,
		}
	}

	c.Initialized = true

	if req.VerifyConnection {
		if _, err := c.Connection(ctx); err != nil {
			return fmt.Errorf("error verifying connection: %w", err)
		}
	}

	return nil
}

func (c *minioConnectionProducer) Connection(ctx context.Context) (interface{}, error) {
	if !c.Initialized {
		return nil, connutil.ErrNotInitialized
	}

	if c.client != nil {
		return c.client, nil
	}

	client, err := c.createClient(ctx)
	if err != nil {
		return nil, err
	}

	c.client = client

	return client, nil
}

func (c *minioConnectionProducer) Close() error {
	c.Lock()
	defer c.Unlock()

	c.client = nil

	return nil
}

func (c *minioConnectionProducer) createClient(ctx context.Context) (*api.AdminClient, error) {
	client, err := api.New(net.JoinHostPort(c.Host, strconv.Itoa(c.Port)), c.Username, c.Password, c.TLS)
	if err != nil {
		return nil, err
	}
	// cannot set client.(Connect)Timeout
	tr := &http.Transport{
		ResponseHeaderTimeout: c.connectTimeout,
	}
	if c.TLS {
		tr.TLSClientConfig = c.sslOpts
	}
	client.SetCustomTransport(tr)

	// Check server status
	_, err = client.ServerInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("Error checking server status: %w", err)
	}

	// Verify necessary authorizations
	err = checkAuthorizations(ctx, client)
	if err != nil {
		return nil, err
	}

	return client, nil
}

func (c *minioConnectionProducer) secretValues() map[string]string {
	return map[string]string{
		c.Password:  "[password]",
		c.PemBundle: "[pem_bundle]",
		c.PemJSON:   "[pem_json]",
	}
}

func checkAuthorizations(ctx context.Context, client *api.AdminClient) error {
	info, err := client.AccountInfo(ctx, api.AccountOpts{PrefixUsage: false})
	if err != nil {
		return fmt.Errorf("Failed fetching account info: %w", err)
	}
	policy, err := iampolicy.ParseConfig(bytes.NewReader(info.Policy))
	if err != nil {
		return fmt.Errorf("Failed parsing policy: %w", err)
	}
	auths := []iampolicy.Action{iampolicy.CreateUserAdminAction, iampolicy.DeleteUserAdminAction, iampolicy.ListUsersAdminAction, iampolicy.EnableUserAdminAction, iampolicy.DisableUserAdminAction, iampolicy.GetUserAdminAction, iampolicy.AddUserToGroupAdminAction, iampolicy.RemoveUserFromGroupAdminAction, iampolicy.GetGroupAdminAction, iampolicy.ListGroupsAdminAction, iampolicy.EnableGroupAdminAction, iampolicy.DisableGroupAdminAction, iampolicy.CreatePolicyAdminAction, iampolicy.DeletePolicyAdminAction, iampolicy.GetPolicyAdminAction, iampolicy.AttachPolicyAdminAction, iampolicy.ListUserPoliciesAdminAction}
	for _, auth := range auths {
		if !policy.IsAllowed(iampolicy.Args{Action: auth}) {
			return fmt.Errorf("Missing authorization: %s", auth)
		}
	}
	return nil
}
