/*
  This sample will deploy a secret and a certificate to a KeyVault of your choosing.
  Set the vaultUri parameter to the URI fo a KeyVault you have access to.
  Set the secretVal parameter to the value of the secret you want to deploy.
  See main.bicep to view or modify the KeyVault resources being deployed.
*/

using 'main.bicep'

param vaultUri = 'https://anttestkv2.vault.azure.net/'
param secretVal = 'dummy_secret'
