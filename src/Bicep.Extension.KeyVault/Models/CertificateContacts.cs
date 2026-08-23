using Azure.Bicep.Types.Concrete;
using Bicep.Local.Extension.Types.Attributes;

namespace Bicep.Extension.KeyVault;

public class CertificateContactsIdentifiers
{
    [TypeProperty("The URI of the Key Vault holding the contacts. Defaults to the 'vaultUri' supplied in the extension configuration.", ObjectTypePropertyFlags.Identifier)]
    public string? VaultUri { get; set; }
}

public class CertificateContact
{
    [TypeProperty("The email address of the contact.", ObjectTypePropertyFlags.Required)]
    public required string Email { get; set; }

    [TypeProperty("The name of the contact.")]
    public string? Name { get; set; }

    [TypeProperty("The phone number of the contact.")]
    public string? Phone { get; set; }
}

/// <summary>
/// The certificate contacts for a vault. KeyVault stores contacts as a single list per vault, so
/// this resource owns the whole list: declaring it replaces any contacts already configured.
/// </summary>
[ResourceType("CertificateContacts")]
public class CertificateContacts : CertificateContactsIdentifiers
{
    [TypeProperty("The contacts notified by certificate lifetime actions. This replaces the full set of contacts configured on the vault.", ObjectTypePropertyFlags.Required)]
    public required CertificateContact[] Contacts { get; set; }
}
