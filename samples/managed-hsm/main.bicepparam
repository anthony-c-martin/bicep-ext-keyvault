/*
  Set managedHsmUri to a Managed HSM you have access to, and principalId to the object ID of the
  identity that should be allowed to sign.

  You need the HSM Crypto User role to create the key, and permission to manage role definitions
  and assignments to create the role. Note that a Managed HSM must be activated (its security
  domain downloaded) before any data plane operation will succeed.
*/

using 'main.bicep'

param managedHsmUri = 'https://contoso-hsm.managedhsm.azure.net/'
param principalId = '00000000-0000-0000-0000-000000000000'
param application = 'contoso-payments'
