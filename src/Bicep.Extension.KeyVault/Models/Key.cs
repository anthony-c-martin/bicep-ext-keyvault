using Azure.Bicep.Types.Concrete;
using Bicep.Local.Extension.Types.Attributes;

namespace Bicep.Extension.KeyVault;

public class KeyIdentifiers
{
    [TypeProperty("The URI of the Key Vault holding the key. Defaults to the 'vaultUri' supplied in the extension configuration.", ObjectTypePropertyFlags.Identifier)]
    public string? VaultUri { get; set; }

    [TypeProperty("The name of the key in KeyVault.", ObjectTypePropertyFlags.Identifier | ObjectTypePropertyFlags.Required)]
    public required string Name { get; set; }
}

public class KeyReleasePolicy
{
    [TypeProperty("The release policy, as a JSON string.", ObjectTypePropertyFlags.Required)]
    public required string Json { get; set; }

    [TypeProperty("Whether the release policy is immutable. An immutable policy cannot be changed once set.")]
    public bool? Immutable { get; set; }
}

public class KeyRotationPolicyAutomatic
{
    [TypeProperty("Rotate the key this long after it was created, as an ISO 8601 duration, e.g. 'P90D'. Cannot be combined with 'timeBeforeExpiry'.")]
    public string? TimeAfterCreation { get; set; }

    [TypeProperty("Rotate the key this long before it expires, as an ISO 8601 duration, e.g. 'P30D'. Cannot be combined with 'timeAfterCreation'.")]
    public string? TimeBeforeExpiry { get; set; }
}

public class KeyRotationPolicy
{
    [TypeProperty("How long a newly rotated key remains valid, as an ISO 8601 duration, e.g. 'P90D'. Must be at least 'P28D'.")]
    public string? ExpireAfter { get; set; }

    [TypeProperty("How long before expiry to raise a notification event, as an ISO 8601 duration, e.g. 'P29D'.")]
    public string? NotifyBeforeExpiry { get; set; }

    [TypeProperty("Configures automatic rotation. When omitted, the key is not rotated automatically.")]
    public KeyRotationPolicyAutomatic? Automatic { get; set; }
}

[ResourceType("Key")]
public class Key : KeyIdentifiers
{
    [TypeProperty("The type of key to create. One of 'RSA', 'RSA-HSM', 'EC', 'EC-HSM', 'oct' or 'oct-HSM'.", ObjectTypePropertyFlags.Required)]
    public required string KeyType { get; set; }

    [TypeProperty("The permitted JSON web key operations, e.g. 'sign', 'verify', 'encrypt', 'decrypt', 'wrapKey', 'unwrapKey'.")]
    public string[]? KeyOps { get; set; }

    [TypeProperty("The size of the key in bits. Required for 'RSA', 'RSA-HSM', 'oct' and 'oct-HSM' keys, e.g. 2048, 3072 or 4096.")]
    public int? KeySize { get; set; }

    [TypeProperty("The elliptic curve name. Required for 'EC' and 'EC-HSM' keys. One of 'P-256', 'P-256K', 'P-384' or 'P-521'.")]
    public string? Curve { get; set; }

    [TypeProperty("Whether the key is enabled.")]
    public bool? Enabled { get; set; }

    [TypeProperty("Whether the private key can be exported. Requires a release policy.")]
    public bool? Exportable { get; set; }

    [TypeProperty("The UTC date/time before which the key cannot be used, in ISO 8601 format, e.g. '2025-01-01T00:00:00Z'.")]
    public string? NotBefore { get; set; }

    [TypeProperty("The UTC date/time at which the key expires, in ISO 8601 format, e.g. '2026-01-01T00:00:00Z'.")]
    public string? ExpiresOn { get; set; }

    [TypeProperty("The policy rules under which the key can be exported.")]
    public KeyReleasePolicy? ReleasePolicy { get; set; }

    [TypeProperty("The key rotation policy.")]
    public KeyRotationPolicy? RotationPolicy { get; set; }

    [TypeProperty("Tags to apply to the key.")]
    public Dictionary<string, string>? Tags { get; set; }

    [TypeProperty("The version of the key.", ObjectTypePropertyFlags.ReadOnly)]
    public string? Version { get; set; }

    [TypeProperty("The versioned URI of the key.", ObjectTypePropertyFlags.ReadOnly)]
    public string? Id { get; set; }

    [TypeProperty("The URI of the key, without a version. Use this to always resolve the latest version.", ObjectTypePropertyFlags.ReadOnly)]
    public string? VersionlessId { get; set; }

    [TypeProperty("The RSA modulus, as a base64url-encoded string.", ObjectTypePropertyFlags.ReadOnly)]
    public string? N { get; set; }

    [TypeProperty("The RSA public exponent, as a base64url-encoded string.", ObjectTypePropertyFlags.ReadOnly)]
    public string? E { get; set; }

    [TypeProperty("The elliptic curve X component, as a base64url-encoded string.", ObjectTypePropertyFlags.ReadOnly)]
    public string? X { get; set; }

    [TypeProperty("The elliptic curve Y component, as a base64url-encoded string.", ObjectTypePropertyFlags.ReadOnly)]
    public string? Y { get; set; }

    [TypeProperty("The PEM-encoded public key. Only populated for RSA and EC keys.", ObjectTypePropertyFlags.ReadOnly)]
    public string? PublicKeyPem { get; set; }

    [TypeProperty("The OpenSSH-encoded public key. Only populated for RSA and EC keys.", ObjectTypePropertyFlags.ReadOnly)]
    public string? PublicKeyOpenSsh { get; set; }

    [TypeProperty("The UTC date/time at which the key was created, in ISO 8601 format.", ObjectTypePropertyFlags.ReadOnly)]
    public string? CreatedOn { get; set; }

    [TypeProperty("The UTC date/time at which the key was last updated, in ISO 8601 format.", ObjectTypePropertyFlags.ReadOnly)]
    public string? UpdatedOn { get; set; }

    [TypeProperty("The deletion recovery level currently in effect for the key.", ObjectTypePropertyFlags.ReadOnly)]
    public string? RecoveryLevel { get; set; }
}
