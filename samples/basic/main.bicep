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
