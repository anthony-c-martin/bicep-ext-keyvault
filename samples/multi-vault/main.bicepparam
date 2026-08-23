/*
  Set primaryVaultUri and replicaVaultUris to vaults you have access to, then run this sample.

  You need Set permission on every vault listed.
*/

using 'main.bicep'

param primaryVaultUri = 'https://anttestkv2.vault.azure.net/'

param replicaVaultUris = [
  'https://anttestkv2-westus.vault.azure.net/'
  'https://anttestkv2-westeurope.vault.azure.net/'
]

param secretName = 'shared-signing-secret'
param secretValue = 'dummy_secret'
