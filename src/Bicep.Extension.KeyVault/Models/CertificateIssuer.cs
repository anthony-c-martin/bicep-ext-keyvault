using Azure.Bicep.Types.Concrete;
using Bicep.Local.Extension.Types.Attributes;

namespace Bicep.Extension.KeyVault;

public class CertificateIssuerIdentifiers
{
    [TypeProperty("The URI of the Key Vault holding the issuer. Defaults to the 'vaultUri' supplied in the extension configuration.", ObjectTypePropertyFlags.Identifier)]
    public string? VaultUri { get; set; }

    [TypeProperty("The name of the certificate issuer in KeyVault.", ObjectTypePropertyFlags.Identifier | ObjectTypePropertyFlags.Required)]
    public required string Name { get; set; }
}

public class CertificateIssuerAdmin
{
    [TypeProperty("The email address of the administrator.", ObjectTypePropertyFlags.Required)]
    public required string EmailAddress { get; set; }

    [TypeProperty("The first name of the administrator.")]
    public string? FirstName { get; set; }

    [TypeProperty("The last name of the administrator.")]
    public string? LastName { get; set; }

    [TypeProperty("The phone number of the administrator.")]
    public string? Phone { get; set; }
}

[ResourceType("CertificateIssuer")]
public class CertificateIssuer : CertificateIssuerIdentifiers
{
    [TypeProperty("The name of the certificate authority provider. One of 'DigiCert', 'GlobalSign', 'OneCertV2-PrivateCA', 'OneCertV2-PublicCA' or 'SslAdminV2'.", ObjectTypePropertyFlags.Required)]
    public required string ProviderName { get; set; }

    [TypeProperty("The organization ID registered with the certificate authority.")]
    public string? OrgId { get; set; }

    [TypeProperty("The account ID registered with the certificate authority.")]
    public string? AccountId { get; set; }

    [TypeProperty("The password for the account registered with the certificate authority. This must be supplied on every deployment: the issuer is written as a whole, and KeyVault never returns the stored password.", ObjectTypePropertyFlags.WriteOnly, isSecure: true)]
    public string? Password { get; set; }

    [TypeProperty("Whether the issuer is enabled.")]
    public bool? Enabled { get; set; }

    [TypeProperty("The administrators registered with the certificate authority.")]
    public CertificateIssuerAdmin[]? Admins { get; set; }

    [TypeProperty("The URI of the certificate issuer.", ObjectTypePropertyFlags.ReadOnly)]
    public string? Id { get; set; }

    [TypeProperty("The UTC date/time at which the issuer was created, in ISO 8601 format.", ObjectTypePropertyFlags.ReadOnly)]
    public string? CreatedOn { get; set; }

    [TypeProperty("The UTC date/time at which the issuer was last updated, in ISO 8601 format.", ObjectTypePropertyFlags.ReadOnly)]
    public string? UpdatedOn { get; set; }
}
