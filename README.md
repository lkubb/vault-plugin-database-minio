# MinIO Vault Database Plugin
This plugin allows Vault to manage MinIO authentication and authorization.

## Prerequisites
### MinIO
After initialization, you will need to create a policy and dedicated user account for Vault.

The policy should look like this:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "admin:CreateUser",
                "admin:ListGroups",
                "admin:EnableUser",
                "admin:GetPolicy",
                "admin:GetUser",
                "admin:RemoveUserFromGroup",
                "admin:ServerInfo",
                "admin:CreatePolicy",
                "admin:DisableGroup",
                "admin:EnableGroup",
                "admin:DisableUser",
                "admin:ListUserPolicies",
                "admin:DeleteUser",
                "admin:GetGroup",
                "admin:ListUsers",
                "admin:AddUserToGroup",
                "admin:AttachUserOrGroupPolicy",
                "admin:DeletePolicy"
            ]
        }
    ]
}
```

Proceed with creating the Vault user and assign it this policy.

### Vault
First, ensure your Vault configuration defines `plugin_directory` and `api_address` correctly (the latter is used for inter-process communication, consider TLS certificates!).

Currently, there are no binary releases, hence you will need to compile this plugin, e.g.:

```bash
go build ./cmd/minio-database-plugin
# or gox -osarch="linux/amd64" ./cmd/minio-database-plugin
```

Then move the plugin into `plugin_directory`, ensure correct ownership/permissions and register it:

```bash
vault plugin register -sha256=${BINARY_SHA_SUM} minio-database-plugin
```

## Configuration
### Connection
* `host`: FQDN/IP address of the MinIO API. **Required.**
* `port`: The port the MinIO API server is listening on (int). Defaults to `9000`.
* `username`: The name of the dedicated Vault user. **Required.**
* `password`: The initial password of the dedicated Vault user. **Required.**
* `tls`: Whether to enable TLS. Defaults to `false`.
* `insecure_tls`: Whether to skip verifying server certificates. Defaults to `false`.
* `tls_server_name`: Specifies the name to use as the SNI host when connecting to the MinIO server via TLS.
* `tls_min_version`: Minimum acceptable TLS version (string). Defaults to `1.2`
* `pem_bundle`: Specifies concatenated PEM blocks containing a certificate and private key; a certificate, private key, and issuing CA certificate; or just a CA certificate. Only one of `pem_bundle` or `pem_json` can be specified.
* `pem_json`: Specifies JSON containing a certificate and private key; a certificate, private key, and issuing CA certificate; or just a CA certificate. The value in this field must be an encoded JSON object. For convenience, the format is the same as the output of the `issue` command from the `pki` secrets engine; see the [pki documentation](https://developer.hashicorp.com/vault/docs/secrets/pki). Only one of `pem_bundle` or `pem_json` can be specified.
* `connect_timeout`: Timeout for HTTP connections. Defaults to `5s`.

### Role
A role's `creation_statements` define which permissions the issued user will carry and, optionally, which groups the user will belong to. It should be a list containing a single, JSON-encoded string value. The JSON data can contain the following fields:
* `policy`: [IAM policy](https://min.io/docs/minio/linux/administration/identity-access-management/policy-based-access-control.html) which will be created for each issued user account. This is the most secure method of assigning permissions.
* `static_policies`: A string-valued list of existing policy names that should be assigned to a user account issued under this role. Mind that the policies themselves are not managed by Vault.
* `groups`: A list of group names the issued user should be part of. Groups are created on demand. Mind that the associated policy itself is not managed by Vault.

## Notes
* This plugin is in very early development.
* MinIO must be not be using the Gateway/Filesystem backends, otherwise you will see this error: `This 'admin' API is not supported by server in 'mode-server-fs'`. Noticeably, the TrueNAS CORE native `S3` service is outdated in that respect. You can install the MinIO plugin though, which is more recent.

## Related
* https://github.com/kula/vault-plugin-secrets-minio
