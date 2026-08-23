using Azure.Bicep.Types.Concrete;
using Bicep.Local.Extension.Types.Attributes;

namespace Bicep.Extension.KeyVault;

public class ManagedHsmKeyIdentifiers
{
    [TypeProperty("The URI of the Managed HSM holding the key. Defaults to the 'managedHsmUri' supplied in the extension configuration.", ObjectTypePropertyFlags.Identifier)]
    public string? ManagedHsmUri { get; set; }

    [TypeProperty("The name of the key in the Managed HSM.", ObjectTypePropertyFlags.Identifier | ObjectTypePropertyFlags.Required)]
    public required string Name { get; set; }
}

[ResourceType("ManagedHsmKey")]
public class ManagedHsmKey : ManagedHsmKeyIdentifiers
{
    [TypeProperty("The type of key to create. One of 'RSA-HSM', 'EC-HSM' or 'oct-HSM'.", ObjectTypePropertyFlags.Required)]
    public required string KeyType { get; set; }

    [TypeProperty("The permitted JSON web key operations, e.g. 'sign', 'verify', 'wrapKey', 'unwrapKey'.")]
    public string[]? KeyOps { get; set; }

    [TypeProperty("The size of the key in bits. Required for 'RSA-HSM' and 'oct-HSM' keys.")]
    public int? KeySize { get; set; }

    [TypeProperty("The elliptic curve name. Required for 'EC-HSM' keys. One of 'P-256', 'P-256K', 'P-384' or 'P-521'.")]
    public string? Curve { get; set; }

    [TypeProperty("Whether the key is enabled.")]
    public bool? Enabled { get; set; }

    [TypeProperty("The UTC date/time before which the key cannot be used, in ISO 8601 format.")]
    public string? NotBefore { get; set; }

    [TypeProperty("The UTC date/time at which the key expires, in ISO 8601 format.")]
    public string? ExpiresOn { get; set; }

    [TypeProperty("Tags to apply to the key.")]
    public Dictionary<string, string>? Tags { get; set; }

    [TypeProperty("The version of the key.", ObjectTypePropertyFlags.ReadOnly)]
    public string? Version { get; set; }

    [TypeProperty("The versioned URI of the key.", ObjectTypePropertyFlags.ReadOnly)]
    public string? VersionedId { get; set; }

    [TypeProperty("The URI of the key, without a version.", ObjectTypePropertyFlags.ReadOnly)]
    public string? Id { get; set; }

    [TypeProperty("The UTC date/time at which the key was created, in ISO 8601 format.", ObjectTypePropertyFlags.ReadOnly)]
    public string? CreatedOn { get; set; }

    [TypeProperty("The UTC date/time at which the key was last updated, in ISO 8601 format.", ObjectTypePropertyFlags.ReadOnly)]
    public string? UpdatedOn { get; set; }

    [TypeProperty("The deletion recovery level currently in effect for the key.", ObjectTypePropertyFlags.ReadOnly)]
    public string? RecoveryLevel { get; set; }
}

public class ManagedHsmKeyRotationPolicyIdentifiers
{
    [TypeProperty("The URI of the Managed HSM holding the key. Defaults to the 'managedHsmUri' supplied in the extension configuration.", ObjectTypePropertyFlags.Identifier)]
    public string? ManagedHsmUri { get; set; }

    [TypeProperty("The name of the Managed HSM key the rotation policy applies to.", ObjectTypePropertyFlags.Identifier | ObjectTypePropertyFlags.Required)]
    public required string KeyName { get; set; }
}

[ResourceType("ManagedHsmKeyRotationPolicy")]
public class ManagedHsmKeyRotationPolicy : ManagedHsmKeyRotationPolicyIdentifiers
{
    [TypeProperty("How long a newly rotated key remains valid, as an ISO 8601 duration. Must be at least 'P28D'.", ObjectTypePropertyFlags.Required)]
    public required string ExpireAfter { get; set; }

    [TypeProperty("Rotate the key this long after it was created, as an ISO 8601 duration. Exactly one of 'timeAfterCreation' or 'timeBeforeExpiry' must be supplied.")]
    public string? TimeAfterCreation { get; set; }

    [TypeProperty("Rotate the key this long before it expires, as an ISO 8601 duration. Exactly one of 'timeAfterCreation' or 'timeBeforeExpiry' must be supplied.")]
    public string? TimeBeforeExpiry { get; set; }

    [TypeProperty("How long before expiry to raise a notification event, as an ISO 8601 duration.")]
    public string? NotifyBeforeExpiry { get; set; }

    [TypeProperty("The URI of the key the rotation policy applies to.", ObjectTypePropertyFlags.ReadOnly)]
    public string? Id { get; set; }
}

public class ManagedHsmRoleDefinitionIdentifiers
{
    [TypeProperty("The URI of the Managed HSM. Defaults to the 'managedHsmUri' supplied in the extension configuration.", ObjectTypePropertyFlags.Identifier)]
    public string? ManagedHsmUri { get; set; }

    [TypeProperty("The scope the role definition applies to, e.g. '/' or '/keys'.", ObjectTypePropertyFlags.Identifier | ObjectTypePropertyFlags.Required)]
    public required string Scope { get; set; }

    [TypeProperty("The name of the role definition. Must be a GUID.", ObjectTypePropertyFlags.Identifier | ObjectTypePropertyFlags.Required)]
    public required string Name { get; set; }
}

public class ManagedHsmPermission
{
    [TypeProperty("Control plane actions allowed by the role.")]
    public string[]? Actions { get; set; }

    [TypeProperty("Control plane actions denied by the role.")]
    public string[]? NotActions { get; set; }

    [TypeProperty("Data plane actions allowed by the role, e.g. 'Microsoft.KeyVault/managedHsm/keys/read/action'.")]
    public string[]? DataActions { get; set; }

    [TypeProperty("Data plane actions denied by the role.")]
    public string[]? NotDataActions { get; set; }
}

[ResourceType("ManagedHsmRoleDefinition")]
public class ManagedHsmRoleDefinition : ManagedHsmRoleDefinitionIdentifiers
{
    [TypeProperty("The display name of the role.")]
    public string? RoleName { get; set; }

    [TypeProperty("A description of the role.")]
    public string? Description { get; set; }

    [TypeProperty("The permissions granted by the role.")]
    public ManagedHsmPermission[]? Permissions { get; set; }

    [TypeProperty("The scopes the role can be assigned at. Defaults to the role definition's own scope.")]
    public string[]? AssignableScopes { get; set; }

    [TypeProperty("The fully qualified ID of the role definition.", ObjectTypePropertyFlags.ReadOnly)]
    public string? Id { get; set; }

    [TypeProperty("The type of the role. Either 'AKVBuiltInRole' or 'CustomRole'.", ObjectTypePropertyFlags.ReadOnly)]
    public string? RoleType { get; set; }
}

public class ManagedHsmRoleAssignmentIdentifiers
{
    [TypeProperty("The URI of the Managed HSM. Defaults to the 'managedHsmUri' supplied in the extension configuration.", ObjectTypePropertyFlags.Identifier)]
    public string? ManagedHsmUri { get; set; }

    [TypeProperty("The scope the role assignment applies to, e.g. '/' or '/keys'.", ObjectTypePropertyFlags.Identifier | ObjectTypePropertyFlags.Required)]
    public required string Scope { get; set; }

    [TypeProperty("The name of the role assignment. Must be a GUID.", ObjectTypePropertyFlags.Identifier | ObjectTypePropertyFlags.Required)]
    public required string Name { get; set; }
}

[ResourceType("ManagedHsmRoleAssignment")]
public class ManagedHsmRoleAssignment : ManagedHsmRoleAssignmentIdentifiers
{
    [TypeProperty("The ID of the role definition to assign.", ObjectTypePropertyFlags.Required)]
    public required string RoleDefinitionId { get; set; }

    [TypeProperty("The object ID of the user, group or service principal to assign the role to.", ObjectTypePropertyFlags.Required)]
    public required string PrincipalId { get; set; }

    [TypeProperty("The fully qualified ID of the role assignment.", ObjectTypePropertyFlags.ReadOnly)]
    public string? Id { get; set; }
}
