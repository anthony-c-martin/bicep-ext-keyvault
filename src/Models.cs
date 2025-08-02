using System.Text.Json.Serialization;
using Azure.Bicep.Types.Concrete;
using Bicep.Local.Extension.Types.Attributes;

namespace Bicep.Extension.KeyVault;

public class Configuration
{
    [TypeProperty("The URI of the Key Vault.", ObjectTypePropertyFlags.Required)]
    public required string VaultUri { get; set; }
}

public class SecretIdentifiers
{
    [TypeProperty("The name of the secret in KeyVault.", ObjectTypePropertyFlags.Identifier | ObjectTypePropertyFlags.Required)]
    public required string Name { get; set; }
}

[ResourceType("Secret")]
public class Secret : SecretIdentifiers
{
    [TypeProperty("The value of the secret in KeyVault.", ObjectTypePropertyFlags.Required | ObjectTypePropertyFlags.WriteOnly)]
    public required string Value { get; set; }
}

public class CertificateIdentifiers
{
    [TypeProperty("The name of the certificate in KeyVault.", ObjectTypePropertyFlags.Identifier | ObjectTypePropertyFlags.Required)]
    public required string Name { get; set; }
}

public class CertificateKeyProperties
{
    [TypeProperty("Whether the key is exportable.")]
    public bool Exportable { get; set; }

    [TypeProperty("The type of key.")]
    public string? KeyType { get; set; }

    [TypeProperty("The size of the key.")]
    public int KeySize { get; set; }

    [TypeProperty("Whether to reuse the key.")]
    public bool ReuseKey { get; set; }

    [TypeProperty("The curve type for elliptic curve keys.")]
    public string? Curve { get; set; }
}

public class CertificateSecretProperties
{
    [TypeProperty("The content type of the secret.")]
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
    [TypeProperty("The subject name of the certificate.")]
    public string? Subject { get; set; }

    [TypeProperty("Enhanced key usage extensions.")]
    public string[]? Ekus { get; set; }

    [TypeProperty("Subject alternative names.")]
    public SubjectAlternativeNames? SubjectAlternativeNames { get; set; }

    [TypeProperty("Key usage extensions.")]
    public string[]? KeyUsage { get; set; }

    [TypeProperty("Validity period in months.")]
    public int ValidityInMonths { get; set; }
}

public class LifetimeActionTrigger
{
    [TypeProperty("Percentage of lifetime at which to trigger the action.")]
    public int LifetimePercentage { get; set; }

    [TypeProperty("Days before expiry to trigger the action.")]
    public int DaysBeforeExpiry { get; set; }
}

public class LifetimeActionAction
{
    [TypeProperty("The type of action to perform.")]
    public string? ActionType { get; set; }
}

public class LifetimeAction
{
    [TypeProperty("The trigger for the lifetime action.")]
    public LifetimeActionTrigger? Trigger { get; set; }

    [TypeProperty("The action to perform.")]
    public LifetimeActionAction? Action { get; set; }
}

public class CertificateIssuer
{
    [TypeProperty("The name of the issuer.")]
    public string? Name { get; set; }

    [TypeProperty("The type of certificate.")]
    public string? CertificateType { get; set; }

    [TypeProperty("Whether certificate transparency is enabled.")]
    public bool CertificateTransparency { get; set; }
}

public class CertificateAttributes
{
    [TypeProperty("Whether the certificate is enabled.")]
    public bool Enabled { get; set; }
}

[ResourceType("Certificate")]
public class Certificate : CertificateIdentifiers
{
    [TypeProperty("Key properties for the certificate.")]
    public CertificateKeyProperties? Key { get; set; }

    [TypeProperty("Secret properties for the certificate.")]
    public CertificateSecretProperties? Secret { get; set; }

    [TypeProperty("X.509 certificate properties.")]
    public X509Properties? X509Properties { get; set; }

    [TypeProperty("Lifetime actions for the certificate.")]
    public LifetimeAction[]? LifetimeActions { get; set; }

    [TypeProperty("Certificate issuer information.")]
    public CertificateIssuer? Issuer { get; set; }

    [TypeProperty("Certificate attributes.")]
    public CertificateAttributes? Attributes { get; set; }
}