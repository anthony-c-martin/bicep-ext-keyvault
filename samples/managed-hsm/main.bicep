/*
  Provisions a signing key in a Managed HSM and grants an application permission to use it.

  Demonstrates:
    - creating an HSM-backed key
    - a rotation policy, which for Managed HSM is a separate resource rather than a key property
    - the Managed HSM's own local RBAC system, which is distinct from Azure RBAC

  A Managed HSM is a dedicated, single-tenant appliance and is billed accordingly. Use the
  'encryption-keys' sample instead if a standard vault meets your requirements.
*/

targetScope = 'local'

@description('The URI of the Managed HSM, e.g. https://myhsm.managedhsm.azure.net/.')
param managedHsmUri string

@description('The object ID of the identity that will use the key, e.g. an application\'s managed identity.')
param principalId string

@description('Applied as a tag to the key.')
param application string

extension keyvault with {
  managedHsmUri: managedHsmUri
}

@description('An HSM-backed signing key. The private key is generated inside the HSM and can never be exported.')
resource signingKey 'ManagedHsmKey' = {
  name: 'payment-signing-key'
  keyType: 'RSA-HSM'
  keySize: 3072
  keyOps: ['sign', 'verify']

  tags: {
    application: application
    purpose: 'signing'
  }
}

@description('''
Rotates the key automatically. Unlike a standard vault key, where rotation is a property of the
key, Managed HSM models the rotation policy as its own resource.
''')
resource rotationPolicy 'ManagedHsmKeyRotationPolicy' = {
  keyName: signingKey.name

  // Must be at least P28D.
  expireAfter: 'P1Y'
  notifyBeforeExpiry: 'P30D'

  // Exactly one of timeBeforeExpiry or timeAfterCreation.
  timeBeforeExpiry: 'P60D'
}

@description('''
A custom role granting only the ability to sign with a key, and to read its public half.
Managed HSM has its own RBAC system: these roles are defined and assigned on the HSM itself, and
are invisible to Azure RBAC.
''')
resource signerRole 'ManagedHsmRoleDefinition' = {
  // Role definitions and assignments are identified by a GUID. Deriving it deterministically
  // keeps the deployment idempotent.
  name: guid(managedHsmUri, 'payment-signer')
  scope: '/keys'
  roleName: 'Payment key signer'
  description: 'Signs payment payloads. Cannot export, delete or re-wrap keys.'

  permissions: [
    {
      dataActions: [
        'Microsoft.KeyVault/managedHsm/keys/sign/action'
        'Microsoft.KeyVault/managedHsm/keys/read/action'
      ]
    }
  ]
}

@description('Grants the application the signing role. Role assignments are immutable: to point one at a different principal, delete it first.')
resource signerAssignment 'ManagedHsmRoleAssignment' = {
  name: guid(managedHsmUri, 'payment-signer', principalId)
  scope: '/keys'
  roleDefinitionId: signerRole.id
  principalId: principalId
}

@description('The version-less key URI. Note that for Managed HSM keys this is "id"; the versioned form is "versionedId".')
output signingKeyUri string = signingKey.id

@description('The current version of the signing key.')
output signingKeyVersionedUri string = signingKey.versionedId
