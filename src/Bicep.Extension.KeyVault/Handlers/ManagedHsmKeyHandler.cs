using Azure.Security.KeyVault.Keys;

namespace Bicep.Extension.KeyVault.Handlers;

public class ManagedHsmKeyHandler : KeyVaultResourceHandler<ManagedHsmKey, ManagedHsmKeyIdentifiers>
{
    protected override Uri ResolveEndpoint(ManagedHsmKeyIdentifiers identifiers, Configuration configuration)
    {
        var endpoint = ResolveEndpoint(identifiers.ManagedHsmUri, configuration.ManagedHsmUri, nameof(ManagedHsmKey.ManagedHsmUri), nameof(Configuration.ManagedHsmUri));
        identifiers.ManagedHsmUri = endpoint.AbsoluteUri;

        return endpoint;
    }

    protected override async Task<ResourceResponse> CreateOrUpdate(ResourceRequest request, CancellationToken cancellationToken)
    {
        var properties = request.Properties;
        var hsmUri = ResolveEndpoint(properties, request.Config);
        var client = KeyVaultClients.Keys(hsmUri);

        var key = await KeyOperations.CreateOrUpdateAsync(client, request.Config, ToDefinition(properties), cancellationToken);

        ApplyOutputs(properties, hsmUri, key);

        return GetResponse(request);
    }

    protected override async Task<ResourceResponse> Get(ReferenceRequest request, CancellationToken cancellationToken)
    {
        var identifiers = request.Identifiers;
        var hsmUri = ResolveEndpoint(identifiers, request.Config);
        var client = KeyVaultClients.Keys(hsmUri);

        var key = await KeyOperations.TryGetKeyAsync(client, identifiers.Name, cancellationToken)
            ?? throw new KeyVaultExtensionException("ResourceNotFound", $"The key '{identifiers.Name}' was not found in Managed HSM '{hsmUri}'.", nameof(ManagedHsmKeyIdentifiers.Name));

        var definition = KeyOperations.ToDefinition(key);
        var properties = new ManagedHsmKey
        {
            ManagedHsmUri = identifiers.ManagedHsmUri,
            Name = identifiers.Name,
            KeyType = definition.KeyType,
            KeyOps = definition.KeyOps,
            KeySize = definition.KeySize,
            Curve = definition.Curve,
            Enabled = definition.Enabled,
            NotBefore = definition.NotBefore,
            ExpiresOn = definition.ExpiresOn,
            Tags = definition.Tags,
        };

        ApplyOutputs(properties, hsmUri, key);

        return GetResponse(request, properties);
    }

    protected override async Task<ResourceResponse> Delete(ReferenceRequest request, CancellationToken cancellationToken)
    {
        var identifiers = request.Identifiers;
        var hsmUri = ResolveEndpoint(identifiers, request.Config);

        await KeyOperations.DeleteAsync(KeyVaultClients.Keys(hsmUri), request.Config, identifiers.Name, cancellationToken);

        return GetResponse(request, null);
    }

    protected override ManagedHsmKeyIdentifiers GetIdentifiers(ManagedHsmKey properties)
        => new()
        {
            ManagedHsmUri = properties.ManagedHsmUri,
            Name = properties.Name,
        };

    private static KeyDefinition ToDefinition(ManagedHsmKey properties) => new()
    {
        Name = properties.Name,
        KeyType = properties.KeyType,
        KeyOps = properties.KeyOps,
        KeySize = properties.KeySize,
        Curve = properties.Curve,
        Enabled = properties.Enabled,
        NotBefore = properties.NotBefore,
        ExpiresOn = properties.ExpiresOn,
        Tags = properties.Tags,
    };

    private static void ApplyOutputs(ManagedHsmKey properties, Uri hsmUri, KeyVaultKey key)
    {
        properties.Version = key.Properties.Version;
        properties.VersionedId = key.Id?.AbsoluteUri;
        properties.Id = Conversions.ToVersionlessId(hsmUri, "keys", properties.Name);
        properties.CreatedOn = Conversions.ToIso8601(key.Properties.CreatedOn);
        properties.UpdatedOn = Conversions.ToIso8601(key.Properties.UpdatedOn);
        properties.RecoveryLevel = key.Properties.RecoveryLevel;
    }
}

public class ManagedHsmKeyRotationPolicyHandler : KeyVaultResourceHandler<ManagedHsmKeyRotationPolicy, ManagedHsmKeyRotationPolicyIdentifiers>
{
    protected override Uri ResolveEndpoint(ManagedHsmKeyRotationPolicyIdentifiers identifiers, Configuration configuration)
    {
        var endpoint = ResolveEndpoint(identifiers.ManagedHsmUri, configuration.ManagedHsmUri, nameof(ManagedHsmKeyRotationPolicy.ManagedHsmUri), nameof(Configuration.ManagedHsmUri));
        identifiers.ManagedHsmUri = endpoint.AbsoluteUri;

        return endpoint;
    }

    protected override async Task<ResourceResponse> CreateOrUpdate(ResourceRequest request, CancellationToken cancellationToken)
    {
        var properties = request.Properties;
        var hsmUri = ResolveEndpoint(properties, request.Config);
        var client = KeyVaultClients.Keys(hsmUri);

        if (properties.TimeAfterCreation is null && properties.TimeBeforeExpiry is null)
        {
            throw new KeyVaultExtensionException(
                "MissingProperty",
                "A key rotation policy must specify either 'timeAfterCreation' or 'timeBeforeExpiry'.",
                nameof(ManagedHsmKeyRotationPolicy.TimeAfterCreation));
        }

        await KeyOperations.ApplyRotationPolicyAsync(
            client,
            properties.KeyName,
            properties.ExpireAfter,
            properties.NotifyBeforeExpiry,
            properties.TimeAfterCreation,
            properties.TimeBeforeExpiry,
            cancellationToken);

        properties.Id = Conversions.ToVersionlessId(hsmUri, "keys", properties.KeyName);

        return GetResponse(request);
    }

    protected override async Task<ResourceResponse> Get(ReferenceRequest request, CancellationToken cancellationToken)
    {
        var identifiers = request.Identifiers;
        var hsmUri = ResolveEndpoint(identifiers, request.Config);
        var client = KeyVaultClients.Keys(hsmUri);

        var policy = await client.GetKeyRotationPolicyAsync(identifiers.KeyName, cancellationToken);
        var rotate = policy.Value.LifetimeActions?.FirstOrDefault(action => action.Action == KeyRotationPolicyAction.Rotate);
        var notify = policy.Value.LifetimeActions?.FirstOrDefault(action => action.Action == KeyRotationPolicyAction.Notify);

        var properties = new ManagedHsmKeyRotationPolicy
        {
            ManagedHsmUri = identifiers.ManagedHsmUri,
            KeyName = identifiers.KeyName,
            ExpireAfter = policy.Value.ExpiresIn ?? string.Empty,
            TimeAfterCreation = rotate?.TimeAfterCreate,
            TimeBeforeExpiry = rotate?.TimeBeforeExpiry,
            NotifyBeforeExpiry = notify?.TimeBeforeExpiry,
            Id = Conversions.ToVersionlessId(hsmUri, "keys", identifiers.KeyName),
        };

        return GetResponse(request, properties);
    }

    protected override async Task<ResourceResponse> Delete(ReferenceRequest request, CancellationToken cancellationToken)
    {
        var identifiers = request.Identifiers;
        var hsmUri = ResolveEndpoint(identifiers, request.Config);
        var client = KeyVaultClients.Keys(hsmUri);

        // A rotation policy cannot be removed, only replaced. Resetting it to the service default
        // of "never expire, never rotate" is the closest equivalent to deletion.
        try
        {
            await client.UpdateKeyRotationPolicyAsync(identifiers.KeyName, new Azure.Security.KeyVault.Keys.KeyRotationPolicy(), cancellationToken);
        }
        catch (Azure.RequestFailedException exception) when (IsNotFound(exception))
        {
            // The key itself is already gone, so its policy is too.
        }

        return GetResponse(request, null);
    }

    protected override ManagedHsmKeyRotationPolicyIdentifiers GetIdentifiers(ManagedHsmKeyRotationPolicy properties)
        => new()
        {
            ManagedHsmUri = properties.ManagedHsmUri,
            KeyName = properties.KeyName,
        };
}
