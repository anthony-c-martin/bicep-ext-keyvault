targetScope = 'local'

param vaultUri string

@secure()
param secretVal string

extension keyvault with {
  vaultUri: vaultUri
}

resource secret 'Secret' = {
  name: 'mysecret'
  value: secretVal
  contentType: 'text/plain'
  tags: {
    environment: 'demo'
  }
}

resource key 'Key' = {
  name: 'mykey'
  keyType: 'RSA'
  keySize: 2048
  keyOps: ['sign', 'verify', 'wrapKey', 'unwrapKey']
  rotationPolicy: {
    expireAfter: 'P90D'
    notifyBeforeExpiry: 'P29D'
    automatic: {
      timeBeforeExpiry: 'P30D'
    }
  }
}

resource contacts 'CertificateContacts' = {
  contacts: [
    {
      email: 'admin@contoso.com'
      name: 'Certificate Admin'
    }
  ]
}

resource cert 'Certificate' = {
  name: 'mycert'
  issuer: {
    name: 'Self'
  }
  key: {
    exportable: true
    keySize: 2048
    keyType: 'RSA'
    reuseKey: true
  }
  secret: {
    contentType: 'application/x-pkcs12'
  }
  lifetimeActions: [
    {
      action: {
        actionType: 'AutoRenew'
      }
      trigger: {
        daysBeforeExpiry: 30
      }
    }
  ]
  x509Properties: {
    ekus: ['1.3.6.1.5.5.7.3.1']
    keyUsage: [
      'cRLSign'
      'dataEncipherment'
      'digitalSignature'
      'keyAgreement'
      'keyCertSign'
      'keyEncipherment'
    ]
    subjectAlternativeNames: {
      dnsNames: ['internal.contoso.com', 'domain.hello.world']
    }
    subject: 'CN=hello-world'
    validityInMonths: 12
  }
}

@description('Use the version-less id to always resolve the current version of the secret.')
output secretUri string = secret.versionlessId

@description('The public half of the generated key, ready to drop into an authorized_keys file.')
output keyPublicKeyOpenSsh string = key.publicKeyOpenSsh

output certificateThumbprint string = cert.thumbprint
output certificateExpires string = cert.certificateAttributes.expires
