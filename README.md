# KeyVault Bicep Extension

## Usage

1. Download the [Samples folder](https://download-directory.github.io/?url=https%3A%2F%2Fgithub.com%2Fanthony-c-martin%2Fbicep-ext-keyvault%2Ftree%2Fmain%2Fsamples), and unzip it.
1. Open the unzipped Samples folder in VSCode, and select one of the `.bicepparam` files you wish to deploy.
1. Launch the [Deploy Pane](https://github.com/Azure/bicep/blob/main/docs/experimental/deploy-ui.md) to run the deployment.

The [samples](./samples) folder covers the common scenarios:

| Sample | Scenario |
| --- | --- |
| [basic](./samples/basic) | A tour of the extension in one file. Start here. |
| [app-secrets](./samples/app-secrets) | Seed an application's configuration secrets, declared from a list. |
| [encryption-keys](./samples/encryption-keys) | A customer-managed encryption key and a token signing key, with rotation. |
| [certificates](./samples/certificates) | Self-signed, CA-issued and imported certificates. |
| [managed-hsm](./samples/managed-hsm) | An HSM-backed signing key, plus the HSM's own RBAC. |
| [multi-vault](./samples/multi-vault) | Replicate a secret across several vaults from one deployment. |

> [!NOTE]
> Extension binary packages are not signed on a Mac. If you see a "Failed to launch provider" error, you
> will need to manually sign the extension package, using the path from the error message, e.g.:
>
> `codesign -s - '/Users/ant/.bicep/br/ghcr.io.anthony-c-martin.bicep-ext-keyvault/0.1.1$/extension.bin'`

## Configuration

The extension is configured once, and every resource inherits the configuration unless it overrides
it.

```bicep
extension keyvault with {
  vaultUri: 'https://myvault.vault.azure.net/'
}
```

| Property | Type | Description |
| --- | --- | --- |
| `vaultUri` | string | Default Key Vault endpoint. Resources may override this with their own `vaultUri`. |
| `managedHsmUri` | string | Default Managed HSM endpoint. Resources may override this with their own `managedHsmUri`. |
| `purgeOnDelete` | bool | Permanently purge objects on delete instead of leaving them soft-deleted. Defaults to `false`. |
| `recoverSoftDeleted` | bool | Recover an object that is in a soft-deleted state instead of failing to create it. Defaults to `false`. |

Authentication uses `DefaultAzureCredential`, so it picks up the Azure CLI, environment variables,
managed identity, and the other standard sources.

Because both endpoints can be overridden per resource, one file can manage objects across several
vaults:

```bicep
resource shared 'Secret' = {
  vaultUri: 'https://other-vault.vault.azure.net/'
  name: 'shared-secret'
  value: secretValue
}
```

## Resources

All resources support create, read (drift detection) and delete. Writes are idempotent: a new
version of a secret, key or certificate is only created when the desired state actually differs from
what the vault already holds.

| Resource | Manages |
| --- | --- |
| `Secret` | A secret (`/secrets/<name>`). |
| `Key` | A cryptographic key, including its rotation and release policies (`/keys/<name>`). |
| `Certificate` | A certificate, either generated from a policy or imported (`/certificates/<name>`). |
| `CertificateIssuer` | A certificate authority registration (`/certificates/issuers/<name>`). |
| `CertificateContacts` | The vault-wide certificate contact list (`/certificates/contacts`). |
| `ManagedHsmKey` | A key in a Managed HSM. |
| `ManagedHsmKeyRotationPolicy` | The rotation policy for a Managed HSM key. |
| `ManagedHsmRoleDefinition` | A custom role in the Managed HSM's local RBAC system. |
| `ManagedHsmRoleAssignment` | A role assignment in the Managed HSM's local RBAC system. |

Read-only properties (`version`, `id`, `versionlessId`, `thumbprint`, `publicKeyPem`, …) are
populated after deployment and can be consumed as outputs:

```bicep
output secretUri string = secret.versionlessId
output publicKey string = key.publicKeyOpenSsh
```

### `Secret`

| Property | Type | Notes |
| --- | --- | --- |
| `name` | string | **Required.** Identifier. |
| `value` | string | **Required**, write-only and secure. Changing it creates a new version. |
| `vaultUri` | string | Overrides the configured vault. |
| `contentType` | string | e.g. `text/plain`. |
| `enabled` | bool | |
| `notBefore`, `expiresOn` | string | ISO 8601, e.g. `2026-01-01T00:00:00Z`. |
| `tags` | object | |

Outputs: `version`, `id`, `versionlessId`, `createdOn`, `updatedOn`, `recoveryLevel`.

Changing `value` creates a new version; changing only the metadata updates the current version in
place. Key Vault refuses to return the value of a disabled or expired secret, so for those the
extension compares metadata only. If the template re-enables the secret, any pending `value` change
is applied in the same deployment.

### `Key`

| Property | Type | Notes |
| --- | --- | --- |
| `name` | string | **Required.** Identifier. |
| `keyType` | string | **Required.** `RSA`, `RSA-HSM`, `EC`, `EC-HSM`, `oct` or `oct-HSM`. |
| `keyOps` | string[] | e.g. `sign`, `verify`, `wrapKey`, `unwrapKey`. |
| `keySize` | int | Required for RSA and oct keys. |
| `curve` | string | Required for EC keys. |
| `enabled`, `exportable` | bool | `exportable` requires a `releasePolicy`. |
| `notBefore`, `expiresOn` | string | ISO 8601. |
| `releasePolicy` | object | `{ json, immutable }`. |
| `rotationPolicy` | object | `{ expireAfter, notifyBeforeExpiry, automatic: { timeAfterCreation, timeBeforeExpiry } }`. |
| `tags` | object | |

Outputs: `version`, `id`, `versionlessId`, `n`, `e`, `x`, `y`, `publicKeyPem`, `publicKeyOpenSsh`,
`createdOn`, `updatedOn`, `recoveryLevel`.

Key material is immutable, so changing `keyType`, `keySize`, `curve`, `exportable` or
`releasePolicy` creates a new key version. `keyOps`, `enabled`, `notBefore`, `expiresOn`, `tags` and
`rotationPolicy` are updated in place.

### `Certificate`

Supply either `import` (to upload an existing certificate) or the policy properties (to have Key
Vault generate one) — not both.

| Property | Type | Notes |
| --- | --- | --- |
| `name` | string | **Required.** Identifier. |
| `import` | object | `{ contents, password }`. `contents` is a base64-encoded PFX or PEM. |
| `issuer` | object | `{ name, certificateType, certificateTransparency }`. `name` is `Self`, `Unknown`, or a `CertificateIssuer`. |
| `key` | object | `{ exportable, keyType, keySize, reuseKey, curve }`. |
| `secret` | object | `{ contentType }`. |
| `x509Properties` | object | `{ subject, validityInMonths, ekus, keyUsage, subjectAlternativeNames }`, where `subjectAlternativeNames` is `{ dnsNames, emails, upns }`. At least one of `subject` or `subjectAlternativeNames` is required when generating. |
| `lifetimeActions` | array | `{ action: { actionType }, trigger: { daysBeforeExpiry \| lifetimePercentage } }`. The two trigger forms are mutually exclusive. |
| `attributes` | object | `{ enabled }`. |
| `tags` | object | |

Outputs: `version`, `id`, `versionlessId`, `secretId`, `versionlessSecretId`, `keyId`,
`certificateData` (lower-case hex), `certificateDataBase64`, `thumbprint` (upper-case hex), and
`certificateAttributes` (`enabled`, `created`, `updated`, `expires`, `notBefore`, `recoveryLevel`).

### `CertificateIssuer`

| Property | Type | Notes |
| --- | --- | --- |
| `name` | string | **Required.** Identifier. |
| `providerName` | string | **Required.** `DigiCert`, `GlobalSign`, `OneCertV2-PrivateCA`, `OneCertV2-PublicCA` or `SslAdminV2`. |
| `orgId`, `accountId` | string | |
| `password` | string | Write-only and secure. Must be supplied on every deployment — the issuer is written as a whole and Key Vault never returns the stored password. |
| `enabled` | bool | |
| `admins` | array | `{ emailAddress, firstName, lastName, phone }`. |

Outputs: `id`, `createdOn`, `updatedOn`.

### `CertificateContacts`

Key Vault stores one contact list per vault, so this resource owns the whole list — declaring it
replaces any contacts already configured.

| Property | Type | Notes |
| --- | --- | --- |
| `contacts` | array | **Required.** `{ email, name, phone }`. |

### Managed HSM resources

Managed HSM resources use `managedHsmUri` rather than `vaultUri`, and never fall back to the vault
endpoint.

`ManagedHsmKey` mirrors `Key`, minus the release policy and the public key outputs, which the HSM
does not expose. Note that its identifier outputs are named the other way round from `Key`, matching
how the HSM addresses keys: `id` is version-less and `versionedId` carries the version.

`ManagedHsmKeyRotationPolicy` is a separate resource rather than a property of the key. It requires
`keyName` and `expireAfter` (minimum `P28D`), plus exactly one of `timeAfterCreation` or
`timeBeforeExpiry`; `notifyBeforeExpiry` is optional. A rotation policy cannot be removed, only
replaced, so deleting the resource resets it to the service default of "never expire, never rotate".

`ManagedHsmRoleDefinition` and `ManagedHsmRoleAssignment` manage the HSM's own local RBAC system —
not Azure RBAC. Both are identified by `scope` (e.g. `/` or `/keys`) and a GUID `name`.

| Resource | Properties |
| --- | --- |
| `ManagedHsmRoleDefinition` | `roleName`, `description`, `assignableScopes`, and `permissions` (`{ actions, notActions, dataActions, notDataActions }`). Outputs `id` and `roleType`. |
| `ManagedHsmRoleAssignment` | `roleDefinitionId` and `principalId`, both **required**. Outputs `id`. |

Role assignments are immutable. Redeploying an identical assignment is a no-op, but changing the
principal or role definition is rejected rather than silently replacing an access grant — delete it
first.

## Known gaps

These parts of the Key Vault data plane are deliberately not implemented:

- **Managed storage accounts and SAS token definitions.** There is no supported modern .NET data
  plane SDK for these (no `Azure.Security.KeyVault.Storage` package exists), and the feature itself
  is on a deprecation path.
- **Crypto operations** (encrypt/decrypt/wrap/sign). These are operations rather than resources, so
  they do not fit the resource model, and the extension SDK does not yet expose Bicep functions.
- **ARM-style resource IDs.** Some tools expose a `resourceId` alongside the data plane URI. That
  requires the vault's subscription and resource group, which are not discoverable from a data plane
  endpoint alone. Use `id` / `versionlessId` instead.

## Build + Test Locally

### Build and test

```sh
dotnet build
dotnet test
```

### Rebuild the extension
These commands publish the extension to the local file system, and updates the sample bicepconfig to point to the local extension.
```sh
./scripts/publish.sh ./bin/bicep-ext-keyvault
jq '.extensions.keyvault="../bin/bicep-ext-keyvault"' ./samples/bicepconfig.json > ./samples/bicepconfig.new.json
mv ./samples/bicepconfig.new.json ./samples/bicepconfig.json
```

### Test the extension
Run the deployment.
```sh
bicep local-deploy ./samples/basic/main.bicepparam
```

To enable verbose tracing, run the following beforehand.
```sh
export BICEP_TRACING_ENABLED=true
```

## Releasing

Releases are cut manually so that versioning stays under explicit control — pushing to `main` does
not publish anything. To release, run the **Release** workflow from the Actions tab (or with
`gh workflow run release.yml -f version=0.2.0`) and supply the exact version to publish.

The workflow validates the version, builds and tests, publishes
`br:ghcr.io/anthony-c-martin/bicep-ext-keyvault:<version>` and then pushes a `v`-prefixed git tag
(`v0.2.0`) and GitHub Release. Note that the OCI artifact is tagged with the bare version, while the
git tag carries the `v` prefix. The workflow refuses to run if the tag already exists, so published
versions are never replaced; releases must be cut from `main`.

The version supplied to the workflow is stamped into the binary via `-p:Version=`, and is what the
extension reports to Bicep. Local builds use the placeholder `0.0.1-dev` version from
[`Bicep.Extension.KeyVault.csproj`](./src/Bicep.Extension.KeyVault/Bicep.Extension.KeyVault.csproj).

### First time setup
To configure this repository's GitHub branch protection and collaborators, login with the `gh` CLI and run:

```powershell
./scripts/setup.ps1
```

The script obtains a token from `GITHUB_TOKEN` or `gh auth token` and deploys
[`scripts/repo/main.bicepparam`](./scripts/repo/main.bicepparam).

## Building other extensions

This repo is also intended to demonstrate how to build + publish an end-to-end Bicep extension in C#. Feel free to copy, rename and modify it to prototype building an extension to extend other services.