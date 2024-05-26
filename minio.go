package minio

import (
	"context"
	"encoding/json"
	"fmt"

	multierror "github.com/hashicorp/go-multierror"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	dbplugin "github.com/hashicorp/vault/sdk/database/dbplugin/v5"
	"github.com/hashicorp/vault/sdk/database/helper/dbutil"
	"github.com/hashicorp/vault/sdk/helper/template"
	api "github.com/minio/madmin-go/v3"
	iampolicy "github.com/minio/pkg/iam/policy"
)

var _ dbplugin.Database = &Minio{}

const (
	defaultUserNameTemplate = `{{ printf "v_%s_%s_%s_%s" (.DisplayName | truncate 15) (.RoleName | truncate 15) (random 20) (unix_time) | truncate 100 | replace "-" "_" | lowercase }}`
	minioTypeName           = "minio"
)

type Minio struct {
	*minioConnectionProducer

	usernameProducer template.StringTemplate
}

func New() (interface{}, error) {
	db := new()
	dbType := dbplugin.NewDatabaseErrorSanitizerMiddleware(db, db.secretValues)

	return dbType, nil
}

func new() *Minio {
	connProducer := &minioConnectionProducer{}
	connProducer.Type = minioTypeName

	return &Minio{
		minioConnectionProducer: connProducer,
	}
}

// Type returns the TypeName for this backend
func (c *Minio) Type() (string, error) {
	return minioTypeName, nil
}

func (c *Minio) getConnection(ctx context.Context) (*api.AdminClient, error) {
	client, err := c.Connection(ctx)
	if err != nil {
		return nil, err
	}

	return client.(*api.AdminClient), nil
}

func (c *Minio) Initialize(ctx context.Context, req dbplugin.InitializeRequest) (dbplugin.InitializeResponse, error) {
	usernameTemplate, err := strutil.GetString(req.Config, "username_template")
	if err != nil {
		return dbplugin.InitializeResponse{}, fmt.Errorf("failed to retrieve username_template: %w", err)
	}
	if usernameTemplate == "" {
		usernameTemplate = defaultUserNameTemplate
	}

	up, err := template.NewTemplate(template.Template(usernameTemplate))
	if err != nil {
		return dbplugin.InitializeResponse{}, fmt.Errorf("unable to initialize username template: %w", err)
	}
	c.usernameProducer = up

	_, err = c.usernameProducer.Generate(dbplugin.UsernameMetadata{})
	if err != nil {
		return dbplugin.InitializeResponse{}, fmt.Errorf("invalid username template: %w", err)
	}

	err = c.minioConnectionProducer.Initialize(ctx, req)
	if err != nil {
		return dbplugin.InitializeResponse{}, fmt.Errorf("failed to initialize: %w", err)
	}

	resp := dbplugin.InitializeResponse{
		Config: req.Config,
	}
	return resp, nil
}

func (c *Minio) NewUser(ctx context.Context, req dbplugin.NewUserRequest) (dbplugin.NewUserResponse, error) {
	c.Lock()
	defer c.Unlock()

	defs, err := newCreationStatement(req.Statements.Commands)
	if err != nil {
		return dbplugin.NewUserResponse{}, fmt.Errorf("Unable to parse creation_statements: %w", err)
	}

	client, err := c.getConnection(ctx)
	if err != nil {
		return dbplugin.NewUserResponse{}, err
	}

	err = defs.validate(ctx, client)
	if err != nil {
		return dbplugin.NewUserResponse{}, fmt.Errorf("Failed validating creation_statements: %w", err)
	}

	username, err := c.usernameProducer.Generate(req.UsernameConfig)
	if err != nil {
		return dbplugin.NewUserResponse{}, err
	}

	var finalPolicies []string
	userPolicy := ""
	if defs.Policy != nil {
		jsonPolicy, err := json.Marshal(defs.Policy)
		if err != nil {
			return dbplugin.NewUserResponse{}, fmt.Errorf("Failed marshalling creation statement policy: %w", err)
		}
		err = client.AddCannedPolicy(ctx, username, jsonPolicy)
		if err != nil {
			rollbackErr := rollbackPolicy(ctx, client, username)
			if rollbackErr != nil {
				err = multierror.Append(err, rollbackErr)
			}
			return dbplugin.NewUserResponse{}, err
		}
		userPolicy = username
		finalPolicies = append(finalPolicies, userPolicy)
	}

	userReq := api.AddOrUpdateUserReq{SecretKey: req.Password, Status: api.AccountEnabled} // Policy: userPolicy did not work, why?
	err = client.SetUserReq(ctx, username, userReq)
	if err != nil {
		return rollback(ctx, client, username, userPolicy, err)
	}

	for _, pol := range defs.StaticPolicies {
		finalPolicies = append(finalPolicies, pol)
	}

	if len(finalPolicies) > 0 {
		policiesReq := api.PolicyAssociationReq{Policies: finalPolicies, User: username}
		_, err = client.AttachPolicy(ctx, policiesReq)
		if err != nil {
			return rollback(ctx, client, username, userPolicy, err)
		}
	}

	for _, groupName := range defs.Groups {
		groupReq := api.GroupAddRemove{Group: groupName, Members: []string{username}}
		err = client.UpdateGroupMembers(ctx, groupReq)
		if err != nil {
			return rollback(ctx, client, username, userPolicy, err)
		}
	}
	resp := dbplugin.NewUserResponse{
		Username: username,
	}

	return resp, nil
}

func rollback(ctx context.Context, client *api.AdminClient, username, policyName string, err error) (dbplugin.NewUserResponse, error) {
	rollbackErr := rollbackUser(ctx, client, username)
	if rollbackErr != nil {
		err = multierror.Append(err, rollbackErr)
	}
	if policyName != "" {
		rollbackErr := rollbackPolicy(ctx, client, policyName)
		if rollbackErr != nil {
			err = multierror.Append(err, rollbackErr)
		}
	}
	return dbplugin.NewUserResponse{}, err
}

func rollbackUser(ctx context.Context, client *api.AdminClient, username string) error {
	_, err := client.GetUserInfo(ctx, username)
	errResponse, isErrorResponse := err.(api.ErrorResponse)
	if err != nil && isErrorResponse && errResponse.Code == "404 Not Found" {
		// The user does not exist. Otherwise, try to remove user anyways
		return nil
	}
	return client.RemoveUser(ctx, username)
}

func rollbackPolicy(ctx context.Context, client *api.AdminClient, policyName string) error {
	exists, err := policyExists(ctx, client, policyName)
	if err == nil && !exists {
		return nil
	}
	return client.RemoveCannedPolicy(ctx, policyName)
}

func (c *Minio) UpdateUser(ctx context.Context, req dbplugin.UpdateUserRequest) (dbplugin.UpdateUserResponse, error) {
	if req.Password == nil && req.Expiration == nil {
		return dbplugin.UpdateUserResponse{}, fmt.Errorf("no changes requested")
	}

	if req.Password != nil {
		err := c.changeUserPassword(ctx, req.Username, req.Password)
		return dbplugin.UpdateUserResponse{}, err
	}
	// expiration is a noop
	return dbplugin.UpdateUserResponse{}, nil
}

func (c *Minio) changeUserPassword(ctx context.Context, username string, changePass *dbplugin.ChangePassword) error {
	client, err := c.getConnection(ctx)
	if err != nil {
		return err
	}

	return client.SetUser(ctx, username, changePass.NewPassword, api.AccountEnabled)
}

func (c *Minio) DeleteUser(ctx context.Context, req dbplugin.DeleteUserRequest) (dbplugin.DeleteUserResponse, error) {
	c.Lock()
	defer c.Unlock()

	client, err := c.getConnection(ctx)
	if err != nil {
		return dbplugin.DeleteUserResponse{}, err
	}

	err = client.RemoveUser(ctx, req.Username)
	return dbplugin.DeleteUserResponse{}, err
}

type creationStatement struct {
	StaticPolicies []string          `json:"static_policies"`
	Groups         []string          `json:"groups"`
	Policy         *iampolicy.Policy `json:"policy"`
}

func newCreationStatement(cmd []string) (*creationStatement, error) {
	if len(cmd) == 0 {
		return nil, dbutil.ErrEmptyCreationStatement
	}
	if len(cmd) > 1 {
		return nil, fmt.Errorf("Only 1 creation statement supported")
	}
	stmt := &creationStatement{}
	if err := json.Unmarshal([]byte(cmd[0]), stmt); err != nil {
		return nil, fmt.Errorf("unable to unmarshal %s: %w", []byte(cmd[0]), err)
	}
	return stmt, nil
}

func (stmt *creationStatement) validate(ctx context.Context, client *api.AdminClient) error {
	if stmt.Policy != nil {
		err := stmt.Policy.Validate()
		if err != nil {
			return fmt.Errorf("Invalid creation statement policy: %w", err)
		}
	}
	if len(stmt.StaticPolicies) > 0 {
		for _, policyName := range stmt.StaticPolicies {
			exists, err := policyExists(ctx, client, policyName)
			if err != nil {
				return fmt.Errorf("Failed validating static policy exists: %w", err)
			}
			if !exists {
				return fmt.Errorf("Static policy %s does not exist", policyName)
			}
		}
	}
	// groups are created on demand
	return nil
}

func policyExists(ctx context.Context, client *api.AdminClient, policyName string) (bool, error) {
	_, err := client.InfoCannedPolicyV2(ctx, policyName)
	if err != nil {
		errResponse, isErrorResponse := err.(api.ErrorResponse)
		if isErrorResponse && errResponse.Code == "XMinioAdminNoSuchPolicy" {
			return false, nil
		}
		return false, fmt.Errorf("Failed validating policy %s exists: %w", policyName, err)
	}
	return true, nil
}
