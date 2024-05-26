package minio

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"reflect"
	"strconv"
	"testing"
	"time"

	backoff "github.com/cenkalti/backoff/v3"
	"github.com/hashicorp/vault/sdk/helper/docker"
	dbplugin "github.com/hashicorp/vault/sdk/database/dbplugin/v5"
	dbtesting "github.com/hashicorp/vault/sdk/database/dbplugin/v5/testing"
	api "github.com/minio/madmin-go/v3"
	"github.com/stretchr/testify/require"
)

type (
	checkFunc   func(t testing.TB, address string, port int, username, password string, sslOpts *tls.Config) error
	fixtureFunc func(t testing.TB, address string, port int, sslOpts *tls.Config)
)

const (
	createUserDynamicStatements          = `{"policy": {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["admin:ServerInfo"]}]}}`
	staticPolicy                         = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["admin:ServerInfo"]}]}`
	createUserStaticStatements           = `{"static_policies": ["test"]}`
	createUserDynamicAndStaticStatements = `{"policy": {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["admin:ListUsers"]}]}, "static_policies": ["test"]}`
	createUserGroupStatements            = `{"groups": ["testgroup"], "policy": {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["admin:ServerInfo","admin:ListGroups","admin:ListUsers"]}]}}`
	createUserAllStatements              = `{"groups": ["testgroup"], "policy": {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["admin:ListUsers","admin:ListGroups"]}]}, "static_policies": ["test"]}`
	createUserStaticMissingStatements    = `{"static_policies": ["testmissing"]}`
)

func TestCreateUser(t *testing.T) {
	type testCase struct {
		usernameTemplate      string
		newUserReq            dbplugin.NewUserRequest
		expectErr             bool
		expectedUsernameRegex string
		expectedErrRegex      string
		checkFuncs            []checkFunc
		fixtureFuncs          []fixtureFunc
	}

	tests := map[string]testCase{
		"default_username_template": {
			newUserReq: dbplugin.NewUserRequest{
				UsernameConfig: dbplugin.UsernameMetadata{
					DisplayName: "token",
					RoleName:    "mylongrolenamewithmanycharacters",
				},
				Statements: dbplugin.Statements{
					Commands: []string{createUserDynamicStatements},
				},
				Password:   "newuserpass",
				Expiration: time.Now().Add(1 * time.Minute),
			},
			expectedUsernameRegex: `^v_token_mylongrolenamew_[a-z0-9]{20}_[0-9]{10}$`,
			checkFuncs:            []checkFunc{connect},
		},
		"custom_username_template": {
			usernameTemplate: `foo_{{random 20}}_{{.RoleName | replace "e" "3"}}_{{unix_time}}`,
			newUserReq: dbplugin.NewUserRequest{
				UsernameConfig: dbplugin.UsernameMetadata{
					DisplayName: "token",
					RoleName:    "mylongrolenamewithmanycharacters",
				},
				Statements: dbplugin.Statements{
					Commands: []string{createUserDynamicStatements},
				},
				Password:   "newuserpass",
				Expiration: time.Now().Add(1 * time.Minute),
			},
			expectedUsernameRegex: `^foo_[a-zA-Z0-9]{20}_mylongrol3nam3withmanycharact3rs_[0-9]{10}$`,
			checkFuncs:            []checkFunc{connect},
		},
		"static_policies": {
			newUserReq: dbplugin.NewUserRequest{
				UsernameConfig: dbplugin.UsernameMetadata{
					DisplayName: "token",
					RoleName:    "mylongrolenamewithmanycharacters",
				},
				Statements: dbplugin.Statements{
					Commands: []string{createUserStaticStatements},
				},
				Password:   "newuserpass",
				Expiration: time.Now().Add(1 * time.Minute),
			},
			fixtureFuncs: []fixtureFunc{createPolicy},
			checkFuncs:   []checkFunc{connect},
		},
		"static_policies_missing": {
			newUserReq: dbplugin.NewUserRequest{
				UsernameConfig: dbplugin.UsernameMetadata{
					DisplayName: "token",
					RoleName:    "mylongrolenamewithmanycharacters",
				},
				Statements: dbplugin.Statements{
					Commands: []string{createUserStaticMissingStatements},
				},
				Password:   "newuserpass",
				Expiration: time.Now().Add(1 * time.Minute),
			},
			expectErr:        true,
			expectedErrRegex: `Static policy [\w]+ does not exist`,
		},
		"static_and_dynamic_policies": {
			newUserReq: dbplugin.NewUserRequest{
				UsernameConfig: dbplugin.UsernameMetadata{
					DisplayName: "token",
					RoleName:    "mylongrolenamewithmanycharacters",
				},
				Statements: dbplugin.Statements{
					Commands: []string{createUserDynamicAndStaticStatements},
				},
				Password:   "newuserpass",
				Expiration: time.Now().Add(1 * time.Minute),
			},
			fixtureFuncs: []fixtureFunc{createPolicy},
			checkFuncs:   []checkFunc{connect, checkUsers},
		},
		"groups": {
			newUserReq: dbplugin.NewUserRequest{
				UsernameConfig: dbplugin.UsernameMetadata{
					DisplayName: "token",
					RoleName:    "mylongrolenamewithmanycharacters",
				},
				Statements: dbplugin.Statements{
					Commands: []string{createUserGroupStatements},
				},
				Password:   "newuserpass",
				Expiration: time.Now().Add(1 * time.Minute),
			},
			checkFuncs: []checkFunc{connect, checkGroups},
		},
		"static_and_dynamic_policies_with_groups": {
			newUserReq: dbplugin.NewUserRequest{
				UsernameConfig: dbplugin.UsernameMetadata{
					DisplayName: "token",
					RoleName:    "mylongrolenamewithmanycharacters",
				},
				Statements: dbplugin.Statements{
					Commands: []string{createUserAllStatements},
				},
				Password:   "newuserpass",
				Expiration: time.Now().Add(1 * time.Minute),
			},
			fixtureFuncs: []fixtureFunc{createPolicy},
			checkFuncs:   []checkFunc{connect, checkGroups},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			db, cleanup := getMinio(t, test.usernameTemplate)
			defer cleanup()

			for _, fixtureFunc := range test.fixtureFuncs {
				fixtureFunc(t, db.Host, db.Port, nil)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			newUserResp, err := db.NewUser(ctx, test.newUserReq)
			if !test.expectErr && err != nil {
				t.Fatalf("no error expected, got: %s", err)
			}
			if test.expectErr {
				if err == nil {
					t.Fatalf("err expected, got nil")
				}
				if test.expectedErrRegex != "" {
					require.Regexp(t, test.expectedErrRegex, err.Error())
				}
			}
			if test.expectedUsernameRegex != "" {
				require.Regexp(t, test.expectedUsernameRegex, newUserResp.Username)
			}
			for _, checkFunc := range test.checkFuncs {
				performAssert(t, db.Host, db.Port, newUserResp.Username, test.newUserReq.Password, nil, 5*time.Second, checkFunc)
			}
		})
	}
}

func TestUpdateUserPassword(t *testing.T) {
	db, cleanup := getMinio(t, "")
	defer cleanup()

	password := "myreallysecurepassword"
	createReq := dbplugin.NewUserRequest{
		UsernameConfig: dbplugin.UsernameMetadata{
			DisplayName: "test",
			RoleName:    "test",
		},
		Statements: dbplugin.Statements{
			Commands: []string{createUserDynamicStatements},
		},
		Password:   password,
		Expiration: time.Now().Add(1 * time.Minute),
	}

	createResp := dbtesting.AssertNewUser(t, db, createReq)

	performAssert(t, db.Host, db.Port, createResp.Username, password, nil, 5*time.Second, connect)

	newPassword := "somenewpassword"
	updateReq := dbplugin.UpdateUserRequest{
		Username: createResp.Username,
		Password: &dbplugin.ChangePassword{
			NewPassword: newPassword,
			Statements:  dbplugin.Statements{},
		},
		Expiration: nil,
	}

	dbtesting.AssertUpdateUser(t, db, updateReq)

	performAssert(t, db.Host, db.Port, createResp.Username, newPassword, nil, 5*time.Second, connect)
}

func TestDeleteUser(t *testing.T) {
	db, cleanup := getMinio(t, "")
	defer cleanup()

	password := "myreallysecurepassword"
	createReq := dbplugin.NewUserRequest{
		UsernameConfig: dbplugin.UsernameMetadata{
			DisplayName: "test",
			RoleName:    "test",
		},
		Statements: dbplugin.Statements{
			Commands: []string{createUserDynamicStatements},
		},
		Password:   password,
		Expiration: time.Now().Add(1 * time.Minute),
	}

	createResp := dbtesting.AssertNewUser(t, db, createReq)

	performAssert(t, db.Host, db.Port, createResp.Username, password, nil, 5*time.Second, connect)

	deleteReq := dbplugin.DeleteUserRequest{
		Username: createResp.Username,
	}

	dbtesting.AssertDeleteUser(t, db, deleteReq)

	performAssert(t, db.Host, db.Port, createResp.Username, password, nil, 5*time.Second, noConnect)
}

func performAssert(t testing.TB, address string, port int, username, password string, sslOpts *tls.Config, timeout time.Duration, check checkFunc) {
	t.Helper()
	op := func() error {
		return check(t, address, port, username, password, sslOpts)
	}
	bo := backoff.NewExponentialBackOff()
	bo.MaxElapsedTime = timeout
	bo.InitialInterval = 500 * time.Millisecond
	bo.MaxInterval = bo.InitialInterval
	bo.RandomizationFactor = 0.0

	err := backoff.Retry(op, bo)
	if err != nil {
		t.Fatalf("failed after %s: %s", timeout, err)
	}
}

func connect(t testing.TB, address string, port int, username, password string, sslOpts *tls.Config) error {
	t.Helper()
	client, err := api.New(net.JoinHostPort(address, strconv.Itoa(port)), username, password, sslOpts != nil)
	if err != nil {
		return err
	}
	_, err = client.ServerInfo(context.Background())
	if err != nil {
		return err
	}
	return nil
}

func noConnect(t testing.TB, address string, port int, username, password string, sslOpts *tls.Config) error {
	err := connect(t, address, port, username, password, sslOpts)
	if err != nil {
		return nil
	}
	return fmt.Errorf("Connection succeeded")
}

func checkUsers(t testing.TB, address string, port int, username, password string, sslOpts *tls.Config) error {
	client, err := api.New(net.JoinHostPort(address, strconv.Itoa(port)), username, password, sslOpts != nil)
	if err != nil {
		return err
	}
	_, err = client.ListUsers(context.Background())
	if err != nil {
		return err
	}
	return nil
}

func checkGroups(t testing.TB, address string, port int, username, password string, sslOpts *tls.Config) error {
	client, err := api.New(net.JoinHostPort(address, strconv.Itoa(port)), username, password, sslOpts != nil)
	if err != nil {
		return err
	}
	groups, err := client.ListGroups(context.Background())
	if err != nil {
		return err
	}
	for _, group := range groups {
		if group == "testgroup" {
			users, err := client.ListUsers(context.Background())
			if err != nil {
				return err
			}
			for user, info := range users {
				if user == username {
					for _, memberOf := range info.MemberOf {
						if memberOf == group {
							return nil
						}
					}
					return fmt.Errorf("User is not member of testgroup")
				}
			}
			return fmt.Errorf("Could not find user")
		}
	}
	return fmt.Errorf("Group `testgroup` not present")
}

func createPolicy(t testing.TB, address string, port int, sslOpts *tls.Config) {
	client, err := api.New(net.JoinHostPort(address, strconv.Itoa(port)), "minioadmin", "minioadmin", false)
	if err != nil {
		t.Fatalf("%v", err)
	}
	err = client.AddCannedPolicy(context.Background(), "test", []byte(staticPolicy))
	if err != nil {
		t.Fatalf("%v", err)
	}
}

type containerConfig struct {
	containerName string
	imageName     string
	version       string
	env           []string

	sslOpts *tls.Config
}

type ContainerOpt func(*containerConfig)

func ContainerName(name string) ContainerOpt {
	return func(cfg *containerConfig) {
		cfg.containerName = name
	}
}

func Image(imageName string, version string) ContainerOpt {
	return func(cfg *containerConfig) {
		cfg.imageName = imageName
		cfg.version = version

		// Reset the environment because there's a very good chance the default environment doesn't apply to the
		// non-default image being used
		cfg.env = nil
	}
}

func Version(version string) ContainerOpt {
	return func(cfg *containerConfig) {
		cfg.version = version
	}
}

func Env(keyValue string) ContainerOpt {
	return func(cfg *containerConfig) {
		cfg.env = append(cfg.env, keyValue)
	}
}

func SslOpts(sslOpts *tls.Config) ContainerOpt {
	return func(cfg *containerConfig) {
		cfg.sslOpts = sslOpts
	}
}

type Host struct {
	Name string
	Port string
}

func (h Host) ConnectionURL() string {
	return net.JoinHostPort(h.Name, h.Port)
}

func PrepareTestContainer(t *testing.T, opts ...ContainerOpt) (Host, func()) {
	t.Helper()

	containerCfg := &containerConfig{
		imageName:     "quay.io/minio/minio",
		containerName: "minio",
		version:       "latest",
		env:           []string{},
	}

	for _, opt := range opts {
		opt(containerCfg)
	}

	runOpts := docker.RunOptions{
		ContainerName: containerCfg.containerName,
		ImageRepo:     containerCfg.imageName,
		ImageTag:      containerCfg.version,
		Ports:         []string{"9000/tcp"},
		Env:           containerCfg.env,
		Cmd:           []string{"server", "/data"},
	}
	runner, err := docker.NewServiceRunner(runOpts)
	if err != nil {
		t.Fatalf("Could not start docker minio: %s", err)
	}

	svc, err := runner.StartService(context.Background(), func(ctx context.Context, host string, port int) (docker.ServiceConfig, error) {
		cfg := docker.NewServiceHostPort(host, port)
		client, err := api.New(net.JoinHostPort(host, strconv.Itoa(port)), "minioadmin", "minioadmin", false)
		if err != nil {
			return nil, fmt.Errorf("error creating client: %s", err)
		}
		_, err = client.ServerInfo(ctx)
		if err != nil {
			return nil, fmt.Errorf("error checking serverinfo: %s", err)
		}
		return cfg, nil
	})
	if err != nil {
		t.Fatalf("Could not start docker minio: %s", err)
	}

	host, port, err := net.SplitHostPort(svc.Config.Address())
	if err != nil {
		t.Fatalf("Failed to split host & port from address (%s): %s", svc.Config.Address(), err)
	}
	h := Host{
		Name: host,
		Port: port,
	}
	return h, svc.Cleanup
}

func getMinio(t *testing.T, usernameTemplate string) (*Minio, func()) {
	host, cleanup := PrepareTestContainer(t,
		Version("latest"),
	)

	db := new()
	initReq := dbplugin.InitializeRequest{
		Config: map[string]interface{}{
			"host":            host.Name,
			"port":            host.Port,
			"username":        "minioadmin",
			"password":        "minioadmin",
			"connect_timeout": "20s",
		},
		VerifyConnection: true,
	}

	expectedConfig := map[string]interface{}{
		"host":            host.Name,
		"port":            host.Port,
		"username":        "minioadmin",
		"password":        "minioadmin",
		"connect_timeout": "20s",
	}

	if usernameTemplate != "" {
		initReq.Config["username_template"] = usernameTemplate
		expectedConfig["username_template"] = usernameTemplate
	}

	initResp := dbtesting.AssertInitialize(t, db, initReq)
	if !reflect.DeepEqual(initResp.Config, expectedConfig) {
		t.Fatalf("Initialize response config actual: %#v\nExpected: %#v", initResp.Config, expectedConfig)
	}

	if !db.Initialized {
		t.Fatal("Database should be initialized")
	}
	return db, cleanup
}
