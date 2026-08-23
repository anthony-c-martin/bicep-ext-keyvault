using Azure.Bicep.Types.Concrete;
using Bicep.Local.Extension.Types.Attributes;

namespace Bicep.Extension.KeyVault;

public class CertificateIdentifiers
{
    [TypeProperty("The URI of the Key Vault holding the certificate. Defaults to the 'vaultUri' supplied in the extension configuration.", ObjectTypePropertyFlags.Identifier)]
    public string? VaultUri { get; set; }

    [TypeProperty("The name of the certificate in KeyVault.", ObjectTypePropertyFlags.Identifier | ObjectTypePropertyFlags.Required)]
    public required string Name { get; set; }
}

public class CertificateKeyProperties
{
    [TypeProperty("Whether the key is exportable.")]
    public bool? Exportable { get; set; }

    [TypeProperty("The type of key. One of 'RSA', 'RSA-HSM', 'EC', 'EC-HSM' or 'oct'.")]
    public string? KeyType { get; set; }

    [TypeProperty("The size of the key. Required for RSA keys, e.g. 2048, 3072 or 4096.")]
    public int? KeySize { get; set; }

    [TypeProperty("Whether to reuse the key when the certificate is renewed.")]
    public bool? ReuseKey { get; set; }

    [TypeProperty("The curve type for elliptic curve keys. One of 'P-256', 'P-256K', 'P-384' or 'P-521'.")]
    public string? Curve { get; set; }
}

public class CertificateSecretProperties
{
    [TypeProperty("The content type of the secret backing the certificate. Either 'application/x-pkcs12' or 'application/x-pem-file'.")]
    public string? ContentType { get; set; }
}

public class SubjectAlternativeNames
{
    [TypeProperty("Email addresses in the certificate.")]
    public string[]? Emails { get; set; }

    [TypeProperty("DNS names in the certificate.")]
    public string[]? DnsNames { get; set; }

    [TypeProperty("User principal names in the certificate.")]
    public string[]? Upns { get; set; }
}

public class X509Properties
{
    [TypeProperty("The subject name of the certificate, e.g. 'CN=contoso.com'.")]
    public string? Subject { get; set; }

    [TypeProperty("Enhanced key usage extensions, as OIDs, e.g. '1.3.6.1.5.5.7.3.1'.")]
    public string[]? Ekus { get; set; }

    [TypeProperty("Subject alternative names.")]
    public SubjectAlternativeNames? SubjectAlternativeNames { get; set; }

    [TypeProperty("Key usage extensions, e.g. 'digitalSignature'.")]
    public string[]? KeyUsage { get; set; }

    [TypeProperty("Validity period in months.")]
    public int? ValidityInMonths { get; set; }
}

public class LifetimeActionTrigger
{
    [TypeProperty("Percentage of the certificate lifetime at which to trigger the action. Must be between 1 and 99, and cannot be combined with 'daysBeforeExpiry'.")]
    public int? LifetimePercentage { get; set; }

    [TypeProperty("Days before expiry at which to trigger the action. Cannot be combined with 'lifetimePercentage'.")]
    public int? DaysBeforeExpiry { get; set; }
}

public class LifetimeActionAction
{
    [TypeProperty("The type of action to perform. Either 'AutoRenew' or 'EmailContacts'.", ObjectTypePropertyFlags.Required)]
    public required string ActionType { get; set; }
}

public class LifetimeAction
{
    [TypeProperty("The trigger for the lifetime action.", ObjectTypePropertyFlags.Required)]
    public required LifetimeActionTrigger Trigger { get; set; }

    [TypeProperty("The action to perform.", ObjectTypePropertyFlags.Required)]
    public required LifetimeActionAction Action { get; set; }
}

public class CertificateIssuerParameters
{
    [TypeProperty("The name of the issuer. Use 'Self' for a self-signed certificate, 'Unknown' for a certificate signed by an external CA, or the name of a 'CertificateIssuer' resource.", ObjectTypePropertyFlags.Required)]
    public required string Name { get; set; }

    [TypeProperty("The type of certificate to request from the issuer.")]
    public string? CertificateType { get; set; }

    [TypeProperty("Whether certificate transparency is enabled.")]
    public bool? CertificateTransparency { get; set; }
}

public class CertificateAttributes
{
    [TypeProperty("Whether the certificate is enabled.")]
    public bool? Enabled { get; set; }
}

public class CertificateImport
{
    [TypeProperty("The base64-encoded contents of the certificate to import. May be a PFX or a PEM bundle.", ObjectTypePropertyFlags.Required, isSecure: true)]
    public required string Contents { get; set; }

    [TypeProperty("The password protecting the certificate contents, if any.", ObjectTypePropertyFlags.None, isSecure: true)]
    public string? Password { get; set; }
}

public class CertificateAttributeOutputs
{
    [TypeProperty("Whether the certificate is enabled.", ObjectTypePropertyFlags.ReadOnly)]
    public bool? Enabled { get; set; }

    [TypeProperty("The UTC date/time at which the certificate was created, in ISO 8601 format.", ObjectTypePropertyFlags.ReadOnly)]
    public string? Created { get; set; }

    [TypeProperty("The UTC date/time at which the certificate was last updated, in ISO 8601 format.", ObjectTypePropertyFlags.ReadOnly)]
    public string? Updated { get; set; }

    [TypeProperty("The UTC date/time at which the certificate expires, in ISO 8601 format.", ObjectTypePropertyFlags.ReadOnly)]
    public string? Expires { get; set; }

    [TypeProperty("The UTC date/time before which the certificate cannot be used, in ISO 8601 format.", ObjectTypePropertyFlags.ReadOnly)]
    public string? NotBefore { get; set; }

    [TypeProperty("The deletion recovery level currently in effect for the certificate.", ObjectTypePropertyFlags.ReadOnly)]
    public string? RecoveryLevel { get; set; }
}

[ResourceType("Certificate")]
public class Certificate : CertificateIdentifiers
{
    [TypeProperty("An existing certificate to import. Mutually exclusive with the policy properties ('key', 'secret', 'x509Properties', 'issuer', 'lifetimeActions').")]
    public CertificateImport? Import { get; set; }

    [TypeProperty("Key properties for the certificate.")]
    public CertificateKeyProperties? Key { get; set; }

    [TypeProperty("Secret properties for the certificate.")]
    public CertificateSecretProperties? Secret { get; set; }

    [TypeProperty("X.509 certificate properties.")]
    public X509Properties? X509Properties { get; set; }

    [TypeProperty("Lifetime actions for the certificate.")]
    public LifetimeAction[]? LifetimeActions { get; set; }

    [TypeProperty("Certificate issuer information.")]
    public CertificateIssuerParameters? Issuer { get; set; }

    [TypeProperty("Certificate attributes.")]
    public CertificateAttributes? Attributes { get; set; }

    [TypeProperty("Tags to apply to the certificate.")]
    public Dictionary<string, string>? Tags { get; set; }

    [TypeProperty("The version of the certificate.", ObjectTypePropertyFlags.ReadOnly)]
    public string? Version { get; set; }

    [TypeProperty("The versioned URI of the certificate.", ObjectTypePropertyFlags.ReadOnly)]
    public string? Id { get; set; }

    [TypeProperty("The URI of the certificate, without a version. Use this to always resolve the latest version.", ObjectTypePropertyFlags.ReadOnly)]
    public string? VersionlessId { get; set; }

    [TypeProperty("The versioned URI of the KeyVault secret backing the certificate.", ObjectTypePropertyFlags.ReadOnly)]
    public string? SecretId { get; set; }

    [TypeProperty("The URI of the KeyVault secret backing the certificate, without a version.", ObjectTypePropertyFlags.ReadOnly)]
    public string? VersionlessSecretId { get; set; }

    [TypeProperty("The versioned URI of the KeyVault key backing the certificate.", ObjectTypePropertyFlags.ReadOnly)]
    public string? KeyId { get; set; }

    [TypeProperty("The raw DER-encoded certificate, as a lower-case hexadecimal string.", ObjectTypePropertyFlags.ReadOnly)]
    public string? CertificateData { get; set; }

    [TypeProperty("The raw DER-encoded certificate, as a base64-encoded string.", ObjectTypePropertyFlags.ReadOnly)]
    public string? CertificateDataBase64 { get; set; }

    [TypeProperty("The X.509 SHA-1 thumbprint of the certificate, as an upper-case hexadecimal string.", ObjectTypePropertyFlags.ReadOnly)]
    public string? Thumbprint { get; set; }

    [TypeProperty("Read-only attributes of the certificate as reported by KeyVault.", ObjectTypePropertyFlags.ReadOnly)]
    public CertificateAttributeOutputs? CertificateAttributes { get; set; }
}
