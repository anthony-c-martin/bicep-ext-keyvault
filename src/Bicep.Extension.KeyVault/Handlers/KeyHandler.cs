using Azure.Security.KeyVault.Keys;

namespace Bicep.Extension.KeyVault.Handlers;

public class KeyHandler : KeyVaultResourceHandler<Key, KeyIdentifiers>
{
    protected override Uri ResolveEndpoint(KeyIdentifiers identifiers, Configuration configuration)
    {
        var endpoint = ResolveEndpoint(identifiers.VaultUri, configuration.VaultUri, nameof(Key.VaultUri), nameof(Configuration.VaultUri));
        identifiers.VaultUri = endpoint.AbsoluteUri;

        return endpoint;
    }

    protected override async Task<ResourceResponse> CreateOrUpdate(ResourceRequest request, CancellationToken cancellationToken)
    {
        var properties = request.Properties;
        var vaultUri = ResolveEndpoint(properties, request.Config);
        var client = KeyVaultClients.Keys(vaultUri);

        var key = await KeyOperations.CreateOrUpdateAsync(client, request.Config, ToDefinition(properties), cancellationToken);

        if (properties.RotationPolicy is { } rotationPolicy)
        {
            await KeyOperations.ApplyRotationPolicyAsync(
                client,
                properties.Name,
                rotationPolicy.ExpireAfter,
                rotationPolicy.NotifyBeforeExpiry,
                rotationPolicy.Automatic?.TimeAfterCreation,
                rotationPolicy.Automatic?.TimeBeforeExpiry,
                cancellationToken);
        }

        ApplyOutputs(properties, vaultUri, key);

        return GetResponse(request);
    }

    protected override async Task<ResourceResponse> Get(ReferenceRequest request, CancellationToken cancellationToken)
    {
        var identifiers = request.Identifiers;
        var vaultUri = ResolveEndpoint(identifiers, request.Config);
        var client = KeyVaultClients.Keys(vaultUri);

        var key = await KeyOperations.TryGetKeyAsync(client, identifiers.Name, cancellationToken)
            ?? throw new KeyVaultExtensionException("ResourceNotFound", $"The key '{identifiers.Name}' was not found in vault '{vaultUri}'.", nameof(KeyIdentifiers.Name));

        var definition = KeyOperations.ToDefinition(key);
        var properties = new Key
        {
            VaultUri = identifiers.VaultUri,
            Name = identifiers.Name,
            KeyType = definition.KeyType,
            KeyOps = definition.KeyOps,
            KeySize = definition.KeySize,
            Curve = definition.Curve,
            Enabled = definition.Enabled,
            Exportable = definition.Exportable,
            NotBefore = definition.NotBefore,
            ExpiresOn = definition.ExpiresOn,
            Tags = definition.Tags,
            ReleasePolicy = key.Properties.ReleasePolicy is { } releasePolicy
                ? new KeyReleasePolicy
                {
                    Json = releasePolicy.EncodedPolicy.ToString(),
                    Immutable = releasePolicy.Immutable,
                }
                : null,
        };

        ApplyOutputs(properties, vaultUri, key);

        return GetResponse(request, properties);
    }

    protected override async Task<ResourceResponse> Delete(ReferenceRequest request, CancellationToken cancellationToken)
    {
        var identifiers = request.Identifiers;
        var vaultUri = ResolveEndpoint(identifiers, request.Config);

        await KeyOperations.DeleteAsync(KeyVaultClients.Keys(vaultUri), request.Config, identifiers.Name, cancellationToken);

        return GetResponse(request, null);
    }

    protected override KeyIdentifiers GetIdentifiers(Key properties)
        => new()
        {
            VaultUri = properties.VaultUri,
            Name = properties.Name,
        };

    private static KeyDefinition ToDefinition(Key properties) => new()
    {
        Name = properties.Name,
        KeyType = properties.KeyType,
        KeyOps = properties.KeyOps,
        KeySize = properties.KeySize,
        Curve = properties.Curve,
        Enabled = properties.Enabled,
        Exportable = properties.Exportable,
        NotBefore = properties.NotBefore,
        ExpiresOn = properties.ExpiresOn,
        ReleasePolicy = properties.ReleasePolicy,
        Tags = properties.Tags,
    };

    private static void ApplyOutputs(Key properties, Uri vaultUri, KeyVaultKey key)
    {
        properties.Version = key.Properties.Version;
        properties.Id = key.Id?.AbsoluteUri;
        properties.VersionlessId = Conversions.ToVersionlessId(vaultUri, "keys", properties.Name);
        properties.CreatedOn = Conversions.ToIso8601(key.Properties.CreatedOn);
        properties.UpdatedOn = Conversions.ToIso8601(key.Properties.UpdatedOn);
        properties.RecoveryLevel = key.Properties.RecoveryLevel;

        properties.N = Conversions.ToBase64Url(key.Key.N);
        properties.E = Conversions.ToBase64Url(key.Key.E);
        properties.X = Conversions.ToBase64Url(key.Key.X);
        properties.Y = Conversions.ToBase64Url(key.Key.Y);
        properties.PublicKeyPem = PublicKeyEncoding.ToPem(key.Key);
        properties.PublicKeyOpenSsh = PublicKeyEncoding.ToOpenSsh(key.Key);
    }
}
