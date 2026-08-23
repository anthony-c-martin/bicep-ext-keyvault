/*
  Creates the cryptographic keys an application needs: a customer-managed key for encrypting
  data at rest, and a signing key for issuing tokens.

  Demonstrates:
    - RSA and elliptic curve keys, and scoping each to only the operations it needs
    - an automatic rotation policy
    - consuming the generated public key, which never leaves Key Vault in private form
*/

targetScope = 'local'

@description('The URI of the Key Vault to create the keys in, e.g. https://myvault.vault.azure.net/.')
param vaultUri string

@description('Applied as a tag to every key.')
param application string

extension keyvault with {
  vaultUri: vaultUri
}

@description('''
A customer-managed key (CMK) for encrypting data at rest.
Only wrap/unwrap are granted: services encrypt their own data encryption key with this key, and
never use it to encrypt data directly.
''')
resource encryptionKey 'Key' = {
  name: 'cmk-data-at-rest'
  keyType: 'RSA'
  keySize: 3072
  keyOps: ['wrapKey', 'unwrapKey']

  // Rotate automatically well before expiry, and raise an event in time for someone to react if
  // rotation fails.
  rotationPolicy: {
    expireAfter: 'P1Y'
    notifyBeforeExpiry: 'P30D'
    automatic: {
      timeBeforeExpiry: 'P60D'
    }
  }

  tags: {
    application: application
    purpose: 'encryption'
  }
}

@description('''
An elliptic curve key for signing tokens. EC keys are smaller and faster than RSA at an
equivalent strength, which suits high-volume signing.
''')
resource signingKey 'Key' = {
  name: 'jwt-signing-key'
  keyType: 'EC'
  curve: 'P-256'
  keyOps: ['sign', 'verify']

  tags: {
    application: application
    purpose: 'signing'
  }
}

@description('''
Bind Azure services that support customer-managed keys to this version-less URI.
They will then pick up new versions automatically as the rotation policy rotates the key; a
versioned URI would pin them to the key that exists today.
''')
output encryptionKeyUri string = encryptionKey.versionlessId

@description('The current version of the encryption key, for services that require a pinned version.')
output encryptionKeyVersionedUri string = encryptionKey.id

@description('The signing key\'s public half, for verifiers that validate tokens offline.')
output signingPublicKeyPem string = signingKey.publicKeyPem

@description('The same public key in OpenSSH format.')
output signingPublicKeyOpenSsh string = signingKey.publicKeyOpenSsh
