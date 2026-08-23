/*
  Set vaultUri to a Key Vault you have access to, then run this sample.

  In a real pipeline the values in secretValues would come from a secure source (a CI secret
  store, or another Key Vault) rather than being written inline.
*/

using 'main.bicep'

param vaultUri = 'https://anttestkv2.vault.azure.net/'
param application = 'contoso-web'
param environment = 'dev'

param secretDefinitions = [
  {
    name: 'database-connection-string'
    contentType: 'text/plain'
    expiresOn: '2027-01-01T00:00:00Z'
  }
  {
    name: 'payments-api-key'
    contentType: 'text/plain'
    expiresOn: '2026-07-01T00:00:00Z'
  }
  {
    name: 'feature-flags'
    contentType: 'application/json'
    expiresOn: '2027-01-01T00:00:00Z'
  }
]

param secretValues = {
  'database-connection-string': 'Server=tcp:contoso.database.windows.net;Database=app;'
  'payments-api-key': 'dummy-api-key'
  'feature-flags': '{"newCheckout":true}'
}
