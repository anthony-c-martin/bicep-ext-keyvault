/*
  The three ways to get a certificate into Key Vault.

  Demonstrates:
    - a self-signed certificate, for local and test environments
    - a certificate issued by a public CA, renewed automatically
    - importing a certificate you already hold as a PFX

  The import is optional: leave pfxBase64 empty and that resource is skipped, so the sample runs
  as-is.
*/

targetScope = 'local'

@description('The URI of the Key Vault to create the certificates in.')
param vaultUri string

@description('The DNS name to issue certificates for.')
param dnsName string

@description('Addresses notified when a certificate is about to expire or fails to renew.')
param contactEmails string[]

@description('Set to false unless you have a certificate authority account configured. The CA-issued certificate is skipped when false.')
param useCertificateAuthority bool = false

@description('The certificate authority to request certificates from.')
@allowed(['DigiCert', 'GlobalSign', 'OneCertV2-PrivateCA', 'OneCertV2-PublicCA', 'SslAdminV2'])
param certificateAuthority string = 'DigiCert'

@description('The organization ID registered with the certificate authority.')
param certificateAuthorityOrgId string = ''

@description('The account ID registered with the certificate authority.')
param certificateAuthorityAccountId string = ''

@description('The password for the certificate authority account. Must be supplied on every deployment: Key Vault never returns it.')
@secure()
param certificateAuthorityPassword string = ''

@description('A base64-encoded PFX to import. Leave empty to skip the import example.')
@secure()
param pfxBase64 string = ''

@description('The password protecting the PFX, if it has one.')
@secure()
param pfxPassword string = ''

extension keyvault with {
  vaultUri: vaultUri
}

@description('The name the certificate authority account is registered under.')
var issuerName = 'production-ca'

@description('''
Certificate contacts are notified by any EmailContacts lifetime action, and by Key Vault when an
automatic renewal fails. Key Vault keeps a single list per vault, so this resource replaces
whatever is already configured.
''')
resource contacts 'CertificateContacts' = {
  contacts: [
    for email in contactEmails: {
      email: email
    }
  ]
}

@description('''
A self-signed certificate. Fine for development and internal testing; browsers and clients will
not trust it without explicitly importing it.
''')
resource selfSigned 'Certificate' = {
  name: 'dev-${replace(dnsName, '.', '-')}'

  issuer: {
    name: 'Self'
  }

  key: {
    keyType: 'RSA'
    keySize: 2048
    exportable: true
    reuseKey: false
  }

  secret: {
    // PKCS#12 yields a PFX; use application/x-pem-file if you need PEM.
    contentType: 'application/x-pkcs12'
  }

  x509Properties: {
    subject: 'CN=${dnsName}'
    validityInMonths: 12
    keyUsage: ['digitalSignature', 'keyEncipherment']
    ekus: ['1.3.6.1.5.5.7.3.1'] // Server authentication.
    subjectAlternativeNames: {
      dnsNames: [dnsName]
    }
  }

  tags: {
    environment: 'dev'
  }
}

@description('Registers the certificate authority account that issues the production certificate.')
resource issuer 'CertificateIssuer' = if (useCertificateAuthority) {
  name: issuerName
  providerName: certificateAuthority
  orgId: certificateAuthorityOrgId
  accountId: certificateAuthorityAccountId
  password: certificateAuthorityPassword

  admins: [
    for email in contactEmails: {
      emailAddress: email
    }
  ]
}

@description('''
A certificate issued by the registered authority, renewed automatically 30 days before it
expires. Key Vault drives the renewal, so nothing has to run on a schedule.
''')
resource caIssued 'Certificate' = if (useCertificateAuthority) {
  name: 'prod-${replace(dnsName, '.', '-')}'

  // Both resources share the same condition, so the issuer is always present when this is
  // deployed. The dependency is declared explicitly because referencing a conditional resource's
  // properties would otherwise look like it might be null.
  dependsOn: [issuer]

  issuer: {
    name: issuerName
  }

  key: {
    keyType: 'RSA'
    keySize: 2048
    exportable: false
    reuseKey: false
  }

  secret: {
    contentType: 'application/x-pkcs12'
  }

  x509Properties: {
    subject: 'CN=${dnsName}'
    validityInMonths: 12
    keyUsage: ['digitalSignature', 'keyEncipherment']
    ekus: ['1.3.6.1.5.5.7.3.1']
    subjectAlternativeNames: {
      dnsNames: [dnsName]
    }
  }

  lifetimeActions: [
    {
      action: {
        actionType: 'AutoRenew'
      }
      trigger: {
        // Either daysBeforeExpiry or lifetimePercentage, never both.
        daysBeforeExpiry: 30
      }
    }
    {
      action: {
        actionType: 'EmailContacts'
      }
      trigger: {
        lifetimePercentage: 80
      }
    }
  ]

  tags: {
    environment: 'prod'
  }
}

@description('''
Imports a certificate issued elsewhere. An imported certificate carries its own key and validity,
so it cannot also specify policy properties - supply import on its own.
''')
resource imported 'Certificate' = if (!empty(pfxBase64)) {
  name: 'imported-${replace(dnsName, '.', '-')}'

  import: {
    contents: pfxBase64
    password: pfxPassword
  }

  tags: {
    source: 'imported'
  }
}

@description('The SHA-1 thumbprint of the self-signed certificate.')
output selfSignedThumbprint string = selfSigned.thumbprint

@description('When the self-signed certificate expires.')
output selfSignedExpires string = selfSigned.certificateAttributes.expires

@description('''
The Key Vault secret holding the self-signed certificate's private key and chain.
App Service and Application Gateway bind to a URI like this rather than to the certificate itself.
''')
output selfSignedSecretUri string = selfSigned.versionlessSecretId
