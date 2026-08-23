using Azure.Bicep.Types.Concrete;
using Bicep.Local.Extension.Types.Attributes;

namespace Bicep.Extension.KeyVault;

public class SecretIdentifiers
{
    [TypeProperty("The URI of the Key Vault holding the secret. Defaults to the 'vaultUri' supplied in the extension configuration.", ObjectTypePropertyFlags.Identifier)]
    public string? VaultUri { get; set; }

    [TypeProperty("The name of the secret in KeyVault.", ObjectTypePropertyFlags.Identifier | ObjectTypePropertyFlags.Required)]
    public required string Name { get; set; }
}

[ResourceType("Secret")]
public class Secret : SecretIdentifiers
{
    [TypeProperty("The value of the secret in KeyVault. Changing this creates a new version of the secret.", ObjectTypePropertyFlags.Required | ObjectTypePropertyFlags.WriteOnly, isSecure: true)]
    public string? Value { get; set; }

    [TypeProperty("The content type of the secret, e.g. 'text/plain'.")]
    public string? ContentType { get; set; }

    [TypeProperty("Whether the secret is enabled.")]
    public bool? Enabled { get; set; }

    [TypeProperty("The UTC date/time before which the secret cannot be used, in ISO 8601 format, e.g. '2025-01-01T00:00:00Z'.")]
    public string? NotBefore { get; set; }

    [TypeProperty("The UTC date/time at which the secret expires, in ISO 8601 format, e.g. '2026-01-01T00:00:00Z'.")]
    public string? ExpiresOn { get; set; }

    [TypeProperty("Tags to apply to the secret.")]
    public Dictionary<string, string>? Tags { get; set; }

    [TypeProperty("The version of the secret.", ObjectTypePropertyFlags.ReadOnly)]
    public string? Version { get; set; }

    [TypeProperty("The versioned URI of the secret.", ObjectTypePropertyFlags.ReadOnly)]
    public string? Id { get; set; }

    [TypeProperty("The URI of the secret, without a version. Use this to always resolve the latest version.", ObjectTypePropertyFlags.ReadOnly)]
    public string? VersionlessId { get; set; }

    [TypeProperty("The UTC date/time at which the secret was created, in ISO 8601 format.", ObjectTypePropertyFlags.ReadOnly)]
    public string? CreatedOn { get; set; }

    [TypeProperty("The UTC date/time at which the secret was last updated, in ISO 8601 format.", ObjectTypePropertyFlags.ReadOnly)]
    public string? UpdatedOn { get; set; }

    [TypeProperty("The deletion recovery level currently in effect for the secret.", ObjectTypePropertyFlags.ReadOnly)]
    public string? RecoveryLevel { get; set; }
}
