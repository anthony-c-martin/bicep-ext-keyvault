using System.Text.Json;
using System.Text.Json.Nodes;
using Azure;
using Azure.Security.KeyVault.Keys;
using SdkKeyReleasePolicy = Azure.Security.KeyVault.Keys.KeyReleasePolicy;
using SdkKeyRotationPolicy = Azure.Security.KeyVault.Keys.KeyRotationPolicy;

namespace Bicep.Extension.KeyVault.Handlers;

/// <summary>
/// A normalised description of a key, so that the vault and Managed HSM key handlers can share the
/// creation, comparison and projection logic that differs only in which endpoint it targets.
/// </summary>
internal sealed record KeyDefinition
{
    public required string Name { get; init; }

    public required string KeyType { get; init; }

    public string[]? KeyOps { get; init; }

    public int? KeySize { get; init; }

    public string? Curve { get; init; }

    public bool? Enabled { get; init; }

    public bool? Exportable { get; init; }

    public string? NotBefore { get; init; }

    public string? ExpiresOn { get; init; }

    public KeyReleasePolicy? ReleasePolicy { get; init; }

    public Dictionary<string, string>? Tags { get; init; }
}

internal static class KeyOperations
{
    public static async Task<KeyVaultKey> CreateOrUpdateAsync(
        KeyClient client,
        Configuration configuration,
        KeyDefinition definition,
        CancellationToken cancellationToken)
    {
        var existing = await TryGetKeyAsync(client, definition.Name, cancellationToken);

        // Key material is immutable: changing the type, size or curve requires a new version.
        // Everything else can be updated in place, so avoid minting versions needlessly.
        if (existing is null || !MaterialMatches(existing, definition))
        {
            return await CreateAsync(client, configuration, definition, cancellationToken);
        }

        if (MetadataMatches(existing, definition))
        {
            return existing;
        }

        ApplyMetadata(definition, existing.Properties);
        var keyOperations = definition.KeyOps?.Select(value => new KeyOperation(value));
        await client.UpdateKeyPropertiesAsync(existing.Properties, keyOperations, cancellationToken);

        return await client.GetKeyAsync(definition.Name, cancellationToken: cancellationToken);
    }

    public static async Task<KeyVaultKey?> TryGetKeyAsync(KeyClient client, string name, CancellationToken cancellationToken)
    {
        try
        {
            return await client.GetKeyAsync(name, cancellationToken: cancellationToken);
        }
        catch (RequestFailedException exception) when (exception.Status == 404)
        {
            return null;
        }
    }

    public static async Task DeleteAsync(KeyClient client, Configuration configuration, string name, CancellationToken cancellationToken)
    {
        try
        {
            var operation = await client.StartDeleteKeyAsync(name, cancellationToken);

            if (configuration.PurgeOnDelete == true)
            {
                await operation.WaitForCompletionAsync(cancellationToken);
                await client.PurgeDeletedKeyAsync(name, cancellationToken);
            }
        }
        catch (RequestFailedException exception) when (exception.Status == 404)
        {
            // Already gone; deletion is idempotent.
        }
    }

    public static KeyDefinition ToDefinition(KeyVaultKey key) => new()
    {
        Name = key.Name,
        KeyType = key.KeyType.ToString(),
        KeyOps = Conversions.ToArray(key.KeyOperations.Select(operation => operation.ToString())),
        KeySize = key.Properties.KeySize,
        Curve = key.Key.CurveName?.ToString(),
        Enabled = key.Properties.Enabled,
        Exportable = key.Properties.Exportable,
        NotBefore = Conversions.ToIso8601(key.Properties.NotBefore),
        ExpiresOn = Conversions.ToIso8601(key.Properties.ExpiresOn),
        Tags = Conversions.ToTags(key.Properties.Tags),
    };

    /// <summary>
    /// Applies the rotation policy, if one was requested. KeyVault has no way to remove a policy,
    /// so an absent policy means "leave whatever is configured alone".
    /// </summary>
    public static async Task ApplyRotationPolicyAsync(
        KeyClient client,
        string name,
        string? expireAfter,
        string? notifyBeforeExpiry,
        string? timeAfterCreation,
        string? timeBeforeExpiry,
        CancellationToken cancellationToken)
    {
        if (timeAfterCreation is not null && timeBeforeExpiry is not null)
        {
            throw new KeyVaultExtensionException(
                "ConflictingProperties",
                "A key rotation policy must specify either 'timeAfterCreation' or 'timeBeforeExpiry', but not both.",
                nameof(KeyRotationPolicyAutomatic));
        }

        var policy = new SdkKeyRotationPolicy { ExpiresIn = expireAfter };

        if (timeAfterCreation is not null || timeBeforeExpiry is not null)
        {
            policy.LifetimeActions.Add(new KeyRotationLifetimeAction(KeyRotationPolicyAction.Rotate)
            {
                TimeAfterCreate = timeAfterCreation,
                TimeBeforeExpiry = timeBeforeExpiry,
            });
        }

        if (notifyBeforeExpiry is not null)
        {
            policy.LifetimeActions.Add(new KeyRotationLifetimeAction(KeyRotationPolicyAction.Notify)
            {
                TimeBeforeExpiry = notifyBeforeExpiry,
            });
        }

        await client.UpdateKeyRotationPolicyAsync(name, policy, cancellationToken);
    }

    private static async Task<KeyVaultKey> CreateAsync(
        KeyClient client,
        Configuration configuration,
        KeyDefinition definition,
        CancellationToken cancellationToken)
    {
        try
        {
            return await CreateCoreAsync(client, definition, cancellationToken);
        }
        catch (RequestFailedException exception) when (exception.Status == 409 && configuration.RecoverSoftDeleted == true)
        {
            var recovery = await client.StartRecoverDeletedKeyAsync(definition.Name, cancellationToken);
            await recovery.WaitForCompletionAsync(cancellationToken);

            return await CreateCoreAsync(client, definition, cancellationToken);
        }
    }

    private static async Task<KeyVaultKey> CreateCoreAsync(KeyClient client, KeyDefinition definition, CancellationToken cancellationToken)
    {
        var keyType = new KeyType(definition.KeyType);
        var hardwareProtected = definition.KeyType.EndsWith("-HSM", StringComparison.OrdinalIgnoreCase);

        if (keyType == KeyType.Rsa || keyType == KeyType.RsaHsm)
        {
            var options = new CreateRsaKeyOptions(definition.Name, hardwareProtected) { KeySize = definition.KeySize };
            ApplyCommon(definition, options);

            return await client.CreateRsaKeyAsync(options, cancellationToken);
        }

        if (keyType == KeyType.Ec || keyType == KeyType.EcHsm)
        {
            var options = new CreateEcKeyOptions(definition.Name, hardwareProtected)
            {
                // Cast explicitly: KeyCurveName defines an implicit conversion from string, so a
                // bare 'null' here would bind to that conversion and throw.
                CurveName = definition.Curve is { } curve ? new KeyCurveName(curve) : (KeyCurveName?)null,
            };
            ApplyCommon(definition, options);

            return await client.CreateEcKeyAsync(options, cancellationToken);
        }

        if (keyType == KeyType.Oct || keyType == KeyType.OctHsm)
        {
            var options = new CreateOctKeyOptions(definition.Name, hardwareProtected) { KeySize = definition.KeySize };
            ApplyCommon(definition, options);

            return await client.CreateOctKeyAsync(options, cancellationToken);
        }

        throw new KeyVaultExtensionException(
            "InvalidKeyType",
            $"The key type '{definition.KeyType}' is not supported. Expected one of 'RSA', 'RSA-HSM', 'EC', 'EC-HSM', 'oct' or 'oct-HSM'.",
            nameof(KeyDefinition.KeyType));
    }

    private static void ApplyCommon(KeyDefinition definition, CreateKeyOptions options)
    {
        options.Enabled = definition.Enabled;
        options.Exportable = definition.Exportable;
        options.NotBefore = Conversions.ToDateTimeOffset(definition.NotBefore, nameof(KeyDefinition.NotBefore));
        options.ExpiresOn = Conversions.ToDateTimeOffset(definition.ExpiresOn, nameof(KeyDefinition.ExpiresOn));
        options.ReleasePolicy = ToReleasePolicy(definition.ReleasePolicy);

        foreach (var value in definition.KeyOps ?? [])
        {
            options.KeyOperations.Add(new KeyOperation(value));
        }

        foreach (var (key, value) in definition.Tags ?? [])
        {
            options.Tags[key] = value;
        }
    }

    private static SdkKeyReleasePolicy? ToReleasePolicy(KeyReleasePolicy? releasePolicy)
        => releasePolicy is null
            ? null
            : new SdkKeyReleasePolicy(BinaryData.FromString(releasePolicy.Json)) { Immutable = releasePolicy.Immutable };

    private static bool MaterialMatches(KeyVaultKey actual, KeyDefinition desired)
        => string.Equals(actual.KeyType.ToString(), desired.KeyType, StringComparison.OrdinalIgnoreCase) &&
            Conversions.ValueMatches(actual.Properties.KeySize, desired.KeySize) &&
            Conversions.ValueMatches(actual.Key.CurveName?.ToString(), desired.Curve) &&
            // Exportability and the release policy that gates it are fixed when the key is
            // created, so changing either has to mint a new version rather than be patched.
            Conversions.ValueMatches(actual.Properties.Exportable, desired.Exportable) &&
            ReleasePolicyMatches(actual.Properties.ReleasePolicy, desired.ReleasePolicy);

    internal static bool ReleasePolicyMatches(SdkKeyReleasePolicy? actual, KeyReleasePolicy? desired)
    {
        if (desired is null)
        {
            return true;
        }

        if (actual?.EncodedPolicy is null || !Conversions.ValueMatches(actual.Immutable, desired.Immutable))
        {
            return false;
        }

        // Compare the policy structurally: the service reformats the JSON it is given.
        try
        {
            return JsonNode.DeepEquals(
                JsonNode.Parse(actual.EncodedPolicy.ToString()),
                JsonNode.Parse(desired.Json));
        }
        catch (JsonException)
        {
            throw new KeyVaultExtensionException(
                "InvalidReleasePolicy",
                "The value supplied for 'releasePolicy.json' is not valid JSON.",
                nameof(KeyReleasePolicy.Json));
        }
    }

    private static bool MetadataMatches(KeyVaultKey actual, KeyDefinition desired)
        => Conversions.ValueMatches(actual.Properties.Enabled, desired.Enabled) &&
            Conversions.DateMatches(actual.Properties.NotBefore, desired.NotBefore, nameof(KeyDefinition.NotBefore)) &&
            Conversions.DateMatches(actual.Properties.ExpiresOn, desired.ExpiresOn, nameof(KeyDefinition.ExpiresOn)) &&
            Conversions.SequenceMatches(actual.KeyOperations.Select(operation => operation.ToString()), desired.KeyOps) &&
            Conversions.TagsMatch(actual.Properties.Tags, desired.Tags);

    private static void ApplyMetadata(KeyDefinition definition, KeyProperties destination)
    {
        destination.Enabled = definition.Enabled;
        destination.NotBefore = Conversions.ToDateTimeOffset(definition.NotBefore, nameof(KeyDefinition.NotBefore));
        destination.ExpiresOn = Conversions.ToDateTimeOffset(definition.ExpiresOn, nameof(KeyDefinition.ExpiresOn));

        if (definition.Tags is { } tags)
        {
            destination.Tags.Clear();
            foreach (var (key, value) in tags)
            {
                destination.Tags[key] = value;
            }
        }
    }
}
