/*
  Replicates a secret across several Key Vaults from a single deployment.

  Demonstrates:
    - overriding the extension's vaultUri on individual resources
    - fanning the same value out to a list of regional vaults

  This is the pattern to reach for when an application runs in several regions and each region
  reads from its own vault, or when you promote configuration from a staging vault to production.
*/

targetScope = 'local'

@description('The vault that acts as the source of truth. Used as the extension default.')
param primaryVaultUri string

@description('Additional vaults to replicate the shared secret into, e.g. one per region.')
param replicaVaultUris string[]

@description('The name of the secret to replicate.')
param secretName string

@description('The value to replicate.')
@secure()
param secretValue string

extension keyvault with {
  // Resources that do not specify their own vaultUri land here.
  vaultUri: primaryVaultUri
}

@description('The authoritative copy, written to the vault configured on the extension.')
resource primary 'Secret' = {
  name: secretName
  value: secretValue
  contentType: 'text/plain'
  tags: {
    role: 'primary'
  }
}

@description('''
A copy in each replica vault. Setting vaultUri on the resource overrides the extension
configuration, so one deployment can span any number of vaults.
''')
resource replicas 'Secret' = [
  for replicaVaultUri in replicaVaultUris: {
    vaultUri: replicaVaultUri
    name: secretName
    value: secretValue
    contentType: 'text/plain'
    tags: {
      role: 'replica'
      replicatedFrom: primaryVaultUri
    }
  }
]

@description('The version-less URI of the authoritative copy.')
output primaryUri string = primary.versionlessId

@description('The version-less URI of each replica.')
output replicaUris array = [for (uri, index) in replicaVaultUris: replicas[index].versionlessId]
