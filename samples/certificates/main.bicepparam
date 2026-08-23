/*
  Set vaultUri to a Key Vault you have access to, then run this sample. As written it creates
  certificate contacts and one self-signed certificate.

  To also request a certificate from a public CA, set useCertificateAuthority to true and fill in
  the account details your certificate authority gave you.

  To also import an existing certificate, set pfxBase64 to the base64-encoded PFX, e.g.
    base64 -i ./certificate.pfx
*/

using 'main.bicep'

param vaultUri = 'https://anttestkv2.vault.azure.net/'
param dnsName = 'app.contoso.com'
param contactEmails = ['platform-team@contoso.com']

param useCertificateAuthority = false
