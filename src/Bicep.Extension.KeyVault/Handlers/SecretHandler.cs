using Azure;
using Azure.Security.KeyVault.Secrets;

namespace Bicep.Extension.KeyVault.Handlers;

public class SecretHandler : KeyVaultResourceHandler<Secret, SecretIdentifiers>
{
    protected override Uri ResolveEndpoint(SecretIdentifiers identifiers, Configuration configuration)
    {
        var endpoint = ResolveEndpoint(identifiers.VaultUri, configuration.VaultUri, nameof(Secret.VaultUri), nameof(Configuration.VaultUri));
        identifiers.VaultUri = endpoint.AbsoluteUri;

        return endpoint;
    }

    protected override async Task<ResourceResponse> CreateOrUpdate(ResourceRequest request, CancellationToken cancellationToken)
    {
        var properties = request.Properties;
        var vaultUri = ResolveEndpoint(properties, request.Config);
        var client = KeyVaultClients.Secrets(vaultUri);

        if (properties.Value is not { } value)
        {
            throw new KeyVaultExtensionException("MissingValue", "The 'value' property is required when creating or updating a secret.", nameof(Secret.Value));
        }

        var existing = await TryGetSecretAsync(client, properties.Name, cancellationToken);
        SecretProperties current;

        if (existing is null)
        {
            current = (await SetSecretAsync(client, request.Config, BuildSecret(properties, value), cancellationToken)).Properties;
        }
        else if (!existing.ValueIsReadable)
        {
            // A disabled or expired secret refuses value reads, so the value cannot be compared.
            // Apply any metadata change first - which typically re-enables it - then look again so
            // that a pending value change still lands in the same deployment.
            current = existing.Properties;

            if (!MetadataMatches(current, properties))
            {
                ApplyProperties(properties, current);
                current = await client.UpdateSecretPropertiesAsync(current, cancellationToken);

                var reread = await TryGetSecretAsync(client, properties.Name, cancellationToken);
                if (reread is { ValueIsReadable: true } && !string.Equals(reread.Value, value, StringComparison.Ordinal))
                {
                    current = (await SetSecretAsync(client, request.Config, BuildSecret(properties, value), cancellationToken)).Properties;
                }
            }
        }
        // KeyVault secrets are append-only: a value can only be changed by adding a version. Only
        // do so when the value actually differs, otherwise every deployment would mint a version.
        else if (!string.Equals(existing.Value, value, StringComparison.Ordinal))
        {
            current = (await SetSecretAsync(client, request.Config, BuildSecret(properties, value), cancellationToken)).Properties;
        }
        else if (!MetadataMatches(existing.Properties, properties))
        {
            ApplyProperties(properties, existing.Properties);
            current = await client.UpdateSecretPropertiesAsync(existing.Properties, cancellationToken);
        }
        else
        {
            current = existing.Properties;
        }

        ApplyOutputs(properties, vaultUri, current);

        return GetResponse(request);
    }

    protected override async Task<ResourceResponse> Get(ReferenceRequest request, CancellationToken cancellationToken)
    {
        var identifiers = request.Identifiers;
        var vaultUri = ResolveEndpoint(identifiers, request.Config);
        var client = KeyVaultClients.Secrets(vaultUri);

        var existing = await TryGetSecretAsync(client, identifiers.Name, cancellationToken)
            ?? throw new KeyVaultExtensionException("ResourceNotFound", $"The secret '{identifiers.Name}' was not found in vault '{vaultUri}'.", nameof(SecretIdentifiers.Name));

        var properties = new Secret
        {
            VaultUri = identifiers.VaultUri,
            Name = identifiers.Name,
            ContentType = existing.Properties.ContentType,
            Enabled = existing.Properties.Enabled,
            NotBefore = Conversions.ToIso8601(existing.Properties.NotBefore),
            ExpiresOn = Conversions.ToIso8601(existing.Properties.ExpiresOn),
            Tags = Conversions.ToTags(existing.Properties.Tags),
        };

        ApplyOutputs(properties, vaultUri, existing.Properties);

        // 'value' is write-only, so it is deliberately not reported back.
        return GetResponse(request, properties);
    }

    protected override async Task<ResourceResponse> Delete(ReferenceRequest request, CancellationToken cancellationToken)
    {
        var identifiers = request.Identifiers;
        var vaultUri = ResolveEndpoint(identifiers, request.Config);
        var client = KeyVaultClients.Secrets(vaultUri);

        try
        {
            var operation = await client.StartDeleteSecretAsync(identifiers.Name, cancellationToken);

            if (request.Config.PurgeOnDelete == true)
            {
                await operation.WaitForCompletionAsync(cancellationToken);
                await client.PurgeDeletedSecretAsync(identifiers.Name, cancellationToken);
            }
        }
        catch (RequestFailedException exception) when (IsNotFound(exception))
        {
            // Already gone; deletion is idempotent.
        }

        return GetResponse(request, null);
    }

    protected override SecretIdentifiers GetIdentifiers(Secret properties)
        => new()
        {
            VaultUri = properties.VaultUri,
            Name = properties.Name,
        };

    private static async Task<KeyVaultSecret> SetSecretAsync(SecretClient client, Configuration configuration, KeyVaultSecret secret, CancellationToken cancellationToken)
    {
        try
        {
            return await client.SetSecretAsync(secret, cancellationToken);
        }
        catch (RequestFailedException exception) when (exception.Status == 409 && configuration.RecoverSoftDeleted == true)
        {
            var recovery = await client.StartRecoverDeletedSecretAsync(secret.Name, cancellationToken);
            await recovery.WaitForCompletionAsync(cancellationToken);

            return await client.SetSecretAsync(secret, cancellationToken);
        }
    }

    private static async Task<ExistingSecret?> TryGetSecretAsync(SecretClient client, string name, CancellationToken cancellationToken)
    {
        try
        {
            var secret = await client.GetSecretAsync(name, cancellationToken: cancellationToken);

            return new ExistingSecret(secret.Value.Properties, secret.Value.Value, ValueIsReadable: true);
        }
        catch (RequestFailedException exception) when (IsNotFound(exception))
        {
            return null;
        }
        catch (RequestFailedException exception) when (exception.Status == 403)
        {
            // KeyVault forbids reading the value of a disabled or expired secret, but still allows
            // its metadata to be listed. Fall back to that so the secret is not mistaken for one
            // that does not exist. A genuine authorization failure fails the listing too, in which
            // case the original error is the useful one, so let it propagate.
            var properties = await GetLatestPropertiesAsync(client, name, cancellationToken);

            if (properties is null)
            {
                throw;
            }

            return new ExistingSecret(properties, null, ValueIsReadable: false);
        }
    }

    private static async Task<SecretProperties?> GetLatestPropertiesAsync(SecretClient client, string name, CancellationToken cancellationToken)
    {
        try
        {
            SecretProperties? latest = null;

            await foreach (var version in client.GetPropertiesOfSecretVersionsAsync(name, cancellationToken))
            {
                if (latest is null || version.CreatedOn > latest.CreatedOn)
                {
                    latest = version;
                }
            }

            return latest;
        }
        catch (RequestFailedException)
        {
            return null;
        }
    }

    private static KeyVaultSecret BuildSecret(Secret properties, string value)
    {
        var secret = new KeyVaultSecret(properties.Name, value);
        ApplyProperties(properties, secret.Properties);

        return secret;
    }

    /// <summary>
    /// A secret that exists in the vault. <paramref name="Value"/> is only populated when KeyVault
    /// permitted reading it, which it does not for disabled or expired secrets.
    /// </summary>
    private sealed record ExistingSecret(SecretProperties Properties, string? Value, bool ValueIsReadable);

    private static void ApplyProperties(Secret source, SecretProperties destination)
    {
        destination.ContentType = source.ContentType;
        destination.Enabled = source.Enabled;
        destination.NotBefore = Conversions.ToDateTimeOffset(source.NotBefore, nameof(Secret.NotBefore));
        destination.ExpiresOn = Conversions.ToDateTimeOffset(source.ExpiresOn, nameof(Secret.ExpiresOn));

        if (source.Tags is { } tags)
        {
            destination.Tags.Clear();
            foreach (var (key, value) in tags)
            {
                destination.Tags[key] = value;
            }
        }
    }

    private static bool MetadataMatches(SecretProperties actual, Secret desired)
        => Conversions.ValueMatches(actual.ContentType, desired.ContentType) &&
            Conversions.ValueMatches(actual.Enabled, desired.Enabled) &&
            Conversions.DateMatches(actual.NotBefore, desired.NotBefore, nameof(Secret.NotBefore)) &&
            Conversions.DateMatches(actual.ExpiresOn, desired.ExpiresOn, nameof(Secret.ExpiresOn)) &&
            Conversions.TagsMatch(actual.Tags, desired.Tags);

    private static void ApplyOutputs(Secret properties, Uri vaultUri, SecretProperties source)
    {
        properties.Version = source.Version;
        properties.Id = source.Id?.AbsoluteUri;
        properties.VersionlessId = Conversions.ToVersionlessId(vaultUri, "secrets", properties.Name);
        properties.CreatedOn = Conversions.ToIso8601(source.CreatedOn);
        properties.UpdatedOn = Conversions.ToIso8601(source.UpdatedOn);
        properties.RecoveryLevel = source.RecoveryLevel;
    }
}
