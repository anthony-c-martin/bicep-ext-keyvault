/*
  Set vaultUri to a Key Vault you have access to, then run this sample.

  Creating keys requires the Key Vault Crypto Officer role, and the rotation policy additionally
  requires permission to set rotation policies.
*/

using 'main.bicep'

param vaultUri = 'https://anttestkv2.vault.azure.net/'
param application = 'contoso-web'
