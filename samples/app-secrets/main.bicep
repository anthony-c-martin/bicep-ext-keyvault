/*
  Seeds an application's configuration secrets into a Key Vault.

  Demonstrates:
    - declaring many secrets from a single list, using a loop
    - separating non-sensitive metadata from the secret values themselves
    - setting an expiry so that stale secrets are visible to rotation tooling
    - purging on delete, which is what you usually want for a throwaway dev vault
*/

targetScope = 'local'

@description('The URI of the Key Vault to seed, e.g. https://myvault.vault.azure.net/.')
param vaultUri string

@description('The application these secrets belong to. Applied as a tag.')
param application string

@description('Deployment environment. Applied as a tag, and controls whether secrets are purged on delete.')
@allowed(['dev', 'test', 'prod'])
param environment string

@description('Non-sensitive metadata describing each secret.')
param secretDefinitions secretDefinition[]

@description('The secret values, keyed by secret name. Keep these in a key vault reference or a CI secret store rather than in source control.')
@secure()
param secretValues object

@description('Metadata for a single application secret.')
type secretDefinition = {
  @description('The name of the secret in Key Vault.')
  name: string

  @description('The MIME type of the value, e.g. text/plain or application/json.')
  contentType: string

  @description('''
  The UTC expiry, in ISO 8601 format.
  Prefer a fixed date over utcNow(): a value that changes on every run makes the secret look
  like it has drifted, so every deployment would rewrite its metadata.
  ''')
  expiresOn: string
}

extension keyvault with {
  vaultUri: vaultUri

  // Dev vaults are recreated constantly, and soft-deleted secrets block a name from being
  // reused. Purging on delete keeps redeployment frictionless. Never do this in production:
  // it discards your only recovery path.
  purgeOnDelete: environment == 'dev'

  // If a secret was previously deleted but not purged, recover it rather than failing.
  recoverSoftDeleted: true
}

resource applicationSecrets 'Secret' = [
  for definition in secretDefinitions: {
    name: definition.name
    // The value does come from a @secure() parameter, but the linter cannot track that through
    // an index expression, so it has to be told this is intentional.
    #disable-next-line use-secure-value-for-secure-inputs
    value: secretValues[definition.name]
    contentType: definition.contentType
    expiresOn: definition.expiresOn
    tags: {
      application: application
      environment: environment
      managedBy: 'bicep'
    }
  }
]

@description('Version-less URIs for the seeded secrets. Bind applications to these so they always read the current version.')
output secretUris array = [
  for (definition, index) in secretDefinitions: {
    name: definition.name
    uri: applicationSecrets[index].versionlessId
  }
]
