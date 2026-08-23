using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Azure;
using Azure.Security.KeyVault.Certificates;
using SdkLifetimeAction = Azure.Security.KeyVault.Certificates.LifetimeAction;
using SdkSubjectAlternativeNames = Azure.Security.KeyVault.Certificates.SubjectAlternativeNames;

namespace Bicep.Extension.KeyVault.Handlers;

public class CertificateHandler : KeyVaultResourceHandler<Certificate, CertificateIdentifiers>
{
    protected override Uri ResolveEndpoint(CertificateIdentifiers identifiers, Configuration configuration)
    {
        var endpoint = ResolveEndpoint(identifiers.VaultUri, configuration.VaultUri, nameof(Certificate.VaultUri), nameof(Configuration.VaultUri));
        identifiers.VaultUri = endpoint.AbsoluteUri;

        return endpoint;
    }

    protected override async Task<ResourceResponse> CreateOrUpdate(ResourceRequest request, CancellationToken cancellationToken)
    {
        var properties = request.Properties;
        var vaultUri = ResolveEndpoint(properties, request.Config);
        var client = KeyVaultClients.Certificates(vaultUri);

        Validate(properties);

        var existing = await TryGetCertificateAsync(client, properties.Name, cancellationToken);
        var certificate = properties.Import is { } import
            ? await ImportAsync(client, request.Config, properties, import, existing, cancellationToken)
            : await GenerateAsync(client, request.Config, properties, existing, cancellationToken);

        var current = certificate.Properties;
        if (!MetadataMatches(current, properties))
        {
            ApplyMetadata(properties, current);
            current = (await client.UpdateCertificatePropertiesAsync(current, cancellationToken)).Value.Properties;
        }

        ApplyOutputs(properties, vaultUri, certificate, current);

        return GetResponse(request);
    }

    protected override async Task<ResourceResponse> Get(ReferenceRequest request, CancellationToken cancellationToken)
    {
        var identifiers = request.Identifiers;
        var vaultUri = ResolveEndpoint(identifiers, request.Config);
        var client = KeyVaultClients.Certificates(vaultUri);

        var existing = await TryGetCertificateAsync(client, identifiers.Name, cancellationToken)
            ?? throw new KeyVaultExtensionException("ResourceNotFound", $"The certificate '{identifiers.Name}' was not found in vault '{vaultUri}'.", nameof(CertificateIdentifiers.Name));

        var properties = new Certificate
        {
            VaultUri = identifiers.VaultUri,
            Name = identifiers.Name,
            Tags = Conversions.ToTags(existing.Properties.Tags),
            Attributes = new CertificateAttributes
            {
                Enabled = existing.Properties.Enabled,
            },
        };

        if (existing.Policy is { } policy)
        {
            ApplyPolicy(properties, policy);
        }

        ApplyOutputs(properties, vaultUri, existing, existing.Properties);

        return GetResponse(request, properties);
    }

    protected override async Task<ResourceResponse> Delete(ReferenceRequest request, CancellationToken cancellationToken)
    {
        var identifiers = request.Identifiers;
        var vaultUri = ResolveEndpoint(identifiers, request.Config);
        var client = KeyVaultClients.Certificates(vaultUri);

        try
        {
            var operation = await client.StartDeleteCertificateAsync(identifiers.Name, cancellationToken);

            if (request.Config.PurgeOnDelete == true)
            {
                await operation.WaitForCompletionAsync(cancellationToken);
                await client.PurgeDeletedCertificateAsync(identifiers.Name, cancellationToken);
            }
        }
        catch (RequestFailedException exception) when (IsNotFound(exception))
        {
            // Already gone; deletion is idempotent.
        }

        return GetResponse(request, null);
    }

    protected override CertificateIdentifiers GetIdentifiers(Certificate properties)
        => new()
        {
            VaultUri = properties.VaultUri,
            Name = properties.Name,
        };

    internal static void Validate(Certificate properties)
    {
        if (properties.Import is not null &&
            (properties.Key is not null || properties.Secret is not null || properties.X509Properties is not null ||
             properties.Issuer is not null || properties.LifetimeActions is not null))
        {
            throw new KeyVaultExtensionException(
                "ConflictingProperties",
                "'import' cannot be combined with the certificate policy properties ('key', 'secret', 'x509Properties', 'issuer', 'lifetimeActions'). Supply one or the other.",
                nameof(Certificate.Import));
        }

        foreach (var action in properties.LifetimeActions ?? [])
        {
            if (action.Trigger.LifetimePercentage is not null && action.Trigger.DaysBeforeExpiry is not null)
            {
                throw new KeyVaultExtensionException(
                    "ConflictingProperties",
                    "A lifetime action trigger must specify either 'lifetimePercentage' or 'daysBeforeExpiry', but not both.",
                    nameof(LifetimeAction.Trigger));
            }

            if (action.Trigger.LifetimePercentage is null && action.Trigger.DaysBeforeExpiry is null)
            {
                throw new KeyVaultExtensionException(
                    "MissingProperty",
                    "A lifetime action trigger must specify either 'lifetimePercentage' or 'daysBeforeExpiry'.",
                    nameof(LifetimeAction.Trigger));
            }
        }
    }

    private static async Task<KeyVaultCertificateWithPolicy> GenerateAsync(
        CertificateClient client,
        Configuration configuration,
        Certificate properties,
        KeyVaultCertificateWithPolicy? existing,
        CancellationToken cancellationToken)
    {
        var policy = BuildPolicy(properties);

        // Creating a certificate always mints a new version, so only do so when the requested
        // policy actually differs from what the vault already holds.
        if (existing is { Policy: { } existingPolicy } && PolicyMatches(existingPolicy, properties))
        {
            return existing;
        }

        var operation = await StartCreateCertificateAsync(client, configuration, properties, policy, cancellationToken);
        await operation.WaitForCompletionAsync(cancellationToken);

        return await client.GetCertificateAsync(properties.Name, cancellationToken);
    }

    private static async Task<CertificateOperation> StartCreateCertificateAsync(
        CertificateClient client,
        Configuration configuration,
        Certificate properties,
        CertificatePolicy policy,
        CancellationToken cancellationToken)
    {
        var enabled = properties.Attributes?.Enabled;
        var tags = properties.Tags;

        try
        {
            return await client.StartCreateCertificateAsync(properties.Name, policy, enabled, tags, cancellationToken);
        }
        catch (RequestFailedException exception) when (exception.Status == 409 && configuration.RecoverSoftDeleted == true)
        {
            var recovery = await client.StartRecoverDeletedCertificateAsync(properties.Name, cancellationToken);
            await recovery.WaitForCompletionAsync(cancellationToken);

            return await client.StartCreateCertificateAsync(properties.Name, policy, enabled, tags, cancellationToken);
        }
    }

    private static async Task<KeyVaultCertificateWithPolicy> ImportAsync(
        CertificateClient client,
        Configuration configuration,
        Certificate properties,
        CertificateImport import,
        KeyVaultCertificateWithPolicy? existing,
        CancellationToken cancellationToken)
    {
        byte[] contents;
        try
        {
            contents = Convert.FromBase64String(import.Contents);
        }
        catch (FormatException)
        {
            throw new KeyVaultExtensionException(
                "InvalidCertificateContents",
                "The 'import.contents' property must be a base64-encoded PFX or PEM certificate.",
                nameof(CertificateImport.Contents));
        }

        // Importing always mints a new version, so compare thumbprints first. When the contents
        // cannot be parsed locally we fall through and import, which is never incorrect - only
        // more work than strictly necessary.
        if (existing is not null &&
            TryGetThumbprint(contents, import.Password) is { } thumbprint &&
            existing.Properties.X509Thumbprint is { Length: > 0 } existingThumbprint &&
            thumbprint.AsSpan().SequenceEqual(existingThumbprint))
        {
            return existing;
        }

        var options = new ImportCertificateOptions(properties.Name, contents)
        {
            Password = import.Password,
            Enabled = properties.Attributes?.Enabled,
        };

        foreach (var (key, value) in properties.Tags ?? [])
        {
            options.Tags[key] = value;
        }

        try
        {
            return await client.ImportCertificateAsync(options, cancellationToken);
        }
        catch (RequestFailedException exception) when (exception.Status == 409 && configuration.RecoverSoftDeleted == true)
        {
            var recovery = await client.StartRecoverDeletedCertificateAsync(properties.Name, cancellationToken);
            await recovery.WaitForCompletionAsync(cancellationToken);

            return await client.ImportCertificateAsync(options, cancellationToken);
        }
    }

    private static byte[]? TryGetThumbprint(byte[] contents, string? password)
    {
        try
        {
            using var certificate = X509CertificateLoader.LoadPkcs12(contents, password);
            return certificate.GetCertHash();
        }
        catch (CryptographicException)
        {
            // Not a PFX - fall through and try the other supported encodings.
        }

        try
        {
            using var certificate = X509CertificateLoader.LoadCertificate(contents);
            return certificate.GetCertHash();
        }
        catch (CryptographicException)
        {
            return null;
        }
    }

    private static async Task<KeyVaultCertificateWithPolicy?> TryGetCertificateAsync(CertificateClient client, string name, CancellationToken cancellationToken)
    {
        try
        {
            return await client.GetCertificateAsync(name, cancellationToken);
        }
        catch (RequestFailedException exception) when (IsNotFound(exception))
        {
            return null;
        }
    }

    internal static CertificatePolicy BuildPolicy(Certificate properties)
    {
        var subject = properties.X509Properties?.Subject;
        var subjectAlternativeNames = BuildSubjectAlternativeNames(properties.X509Properties?.SubjectAlternativeNames);

        // KeyVault requires a subject, subject alternative names, or both. The SDK models that as
        // three separate constructors rather than nullable arguments.
        var policy = (subject, subjectAlternativeNames) switch
        {
            ({ } value, { } sans) => new CertificatePolicy(properties.Issuer?.Name ?? WellKnownIssuerNames.Self, value, sans),
            ({ } value, null) => new CertificatePolicy(properties.Issuer?.Name ?? WellKnownIssuerNames.Self, value),
            (null, { } sans) => new CertificatePolicy(properties.Issuer?.Name ?? WellKnownIssuerNames.Self, sans),
            _ => throw new KeyVaultExtensionException(
                "MissingProperty",
                "'x509Properties.subject' or 'x509Properties.subjectAlternativeNames' is required when generating a certificate, e.g. subject 'CN=contoso.com'.",
                nameof(X509Properties.Subject)),
        };

        policy.Exportable = properties.Key?.Exportable;
        // The explicit nullable casts matter: these SDK types define an implicit conversion from
        // string, so a bare 'null' in a conditional binds to that conversion and throws instead of
        // producing an unset value.
        policy.KeyType = properties.Key?.KeyType is { } keyType ? new CertificateKeyType(keyType) : (CertificateKeyType?)null;
        policy.KeySize = properties.Key?.KeySize;
        policy.ReuseKey = properties.Key?.ReuseKey;
        policy.KeyCurveName = properties.Key?.Curve is { } curve ? new CertificateKeyCurveName(curve) : (CertificateKeyCurveName?)null;
        policy.ContentType = properties.Secret?.ContentType is { } contentType ? new CertificateContentType(contentType) : (CertificateContentType?)null;
        policy.ValidityInMonths = properties.X509Properties?.ValidityInMonths;
        policy.CertificateType = properties.Issuer?.CertificateType;
        policy.CertificateTransparency = properties.Issuer?.CertificateTransparency;
        policy.Enabled = properties.Attributes?.Enabled;

        AddRange(properties.X509Properties?.Ekus, policy.EnhancedKeyUsage);
        AddRange(properties.X509Properties?.KeyUsage, policy.KeyUsage, value => new CertificateKeyUsage(value));
        AddRange(properties.LifetimeActions, policy.LifetimeActions, action => new SdkLifetimeAction(new CertificatePolicyAction(action.Action.ActionType))
        {
            DaysBeforeExpiry = action.Trigger.DaysBeforeExpiry,
            LifetimePercentage = action.Trigger.LifetimePercentage,
        });

        return policy;
    }

    private static SdkSubjectAlternativeNames? BuildSubjectAlternativeNames(SubjectAlternativeNames? source)
    {
        if (source is null || (source.Emails is null && source.DnsNames is null && source.Upns is null))
        {
            return null;
        }

        var result = new SdkSubjectAlternativeNames();
        AddRange(source.Emails, result.Emails);
        AddRange(source.DnsNames, result.DnsNames);
        AddRange(source.Upns, result.UserPrincipalNames);

        return result;
    }

    private static void AddRange<TIn, TOut>(IEnumerable<TIn>? source, ICollection<TOut> destination, Func<TIn, TOut> transform)
    {
        foreach (var value in source ?? [])
        {
            destination.Add(transform(value));
        }
    }

    private static void AddRange<T>(IEnumerable<T>? source, ICollection<T> destination)
        => AddRange(source, destination, value => value);

    /// <summary>
    /// Determines whether the vault's current policy already satisfies what was requested. Only
    /// properties the user actually specified are compared, so server-assigned defaults never look
    /// like drift.
    /// </summary>
    private static bool PolicyMatches(CertificatePolicy actual, Certificate desired)
    {
        if (!Conversions.ValueMatches(actual.IssuerName, desired.Issuer?.Name) ||
            !Conversions.ValueMatches(actual.CertificateType, desired.Issuer?.CertificateType) ||
            !Conversions.ValueMatches(actual.CertificateTransparency, desired.Issuer?.CertificateTransparency))
        {
            return false;
        }

        if (!Conversions.ValueMatches(actual.Exportable, desired.Key?.Exportable) ||
            !Conversions.ValueMatches(actual.KeyType?.ToString(), desired.Key?.KeyType) ||
            !Conversions.ValueMatches(actual.KeySize, desired.Key?.KeySize) ||
            !Conversions.ValueMatches(actual.ReuseKey, desired.Key?.ReuseKey) ||
            !Conversions.ValueMatches(actual.KeyCurveName?.ToString(), desired.Key?.Curve))
        {
            return false;
        }

        if (!Conversions.ValueMatches(actual.ContentType?.ToString(), desired.Secret?.ContentType))
        {
            return false;
        }

        if (!Conversions.ValueMatches(actual.Subject, desired.X509Properties?.Subject) ||
            !Conversions.ValueMatches(actual.ValidityInMonths, desired.X509Properties?.ValidityInMonths) ||
            !Conversions.SequenceMatches(actual.EnhancedKeyUsage, desired.X509Properties?.Ekus) ||
            !Conversions.SequenceMatches(actual.KeyUsage?.Select(usage => usage.ToString()), desired.X509Properties?.KeyUsage))
        {
            return false;
        }

        if (desired.X509Properties?.SubjectAlternativeNames is { } sans &&
            (!Conversions.SequenceMatches(actual.SubjectAlternativeNames?.Emails, sans.Emails) ||
             !Conversions.SequenceMatches(actual.SubjectAlternativeNames?.DnsNames, sans.DnsNames) ||
             !Conversions.SequenceMatches(actual.SubjectAlternativeNames?.UserPrincipalNames, sans.Upns)))
        {
            return false;
        }

        return LifetimeActionsMatch(actual.LifetimeActions, desired.LifetimeActions);
    }

    private static bool LifetimeActionsMatch(IList<SdkLifetimeAction>? actual, LifetimeAction[]? desired)
    {
        if (desired is null)
        {
            return true;
        }

        var actualActions = actual ?? [];
        if (actualActions.Count != desired.Length)
        {
            return false;
        }

        foreach (var action in desired)
        {
            var match = actualActions.FirstOrDefault(candidate =>
                string.Equals(candidate.Action.ToString(), action.Action.ActionType, StringComparison.Ordinal) &&
                Conversions.ValueMatches(candidate.DaysBeforeExpiry, action.Trigger.DaysBeforeExpiry) &&
                Conversions.ValueMatches(candidate.LifetimePercentage, action.Trigger.LifetimePercentage));

            if (match is null)
            {
                return false;
            }
        }

        return true;
    }

    private static bool MetadataMatches(CertificateProperties actual, Certificate desired)
        => Conversions.ValueMatches(actual.Enabled, desired.Attributes?.Enabled) &&
            Conversions.TagsMatch(actual.Tags, desired.Tags);

    private static void ApplyMetadata(Certificate source, CertificateProperties destination)
    {
        destination.Enabled = source.Attributes?.Enabled;

        if (source.Tags is { } tags)
        {
            destination.Tags.Clear();
            foreach (var (key, value) in tags)
            {
                destination.Tags[key] = value;
            }
        }
    }

    private static void ApplyPolicy(Certificate properties, CertificatePolicy policy)
    {
        properties.Issuer = new CertificateIssuerParameters
        {
            Name = policy.IssuerName ?? WellKnownIssuerNames.Self,
            CertificateType = policy.CertificateType,
            CertificateTransparency = policy.CertificateTransparency,
        };

        properties.Key = new CertificateKeyProperties
        {
            Exportable = policy.Exportable,
            KeyType = policy.KeyType?.ToString(),
            KeySize = policy.KeySize,
            ReuseKey = policy.ReuseKey,
            Curve = policy.KeyCurveName?.ToString(),
        };

        properties.Secret = new CertificateSecretProperties
        {
            ContentType = policy.ContentType?.ToString(),
        };

        properties.X509Properties = new X509Properties
        {
            Subject = policy.Subject,
            ValidityInMonths = policy.ValidityInMonths,
            Ekus = Conversions.ToArray(policy.EnhancedKeyUsage),
            KeyUsage = Conversions.ToArray(policy.KeyUsage?.Select(usage => usage.ToString())),
            SubjectAlternativeNames = policy.SubjectAlternativeNames is { } sans
                ? new SubjectAlternativeNames
                {
                    Emails = Conversions.ToArray(sans.Emails),
                    DnsNames = Conversions.ToArray(sans.DnsNames),
                    Upns = Conversions.ToArray(sans.UserPrincipalNames),
                }
                : null,
        };

        properties.LifetimeActions = policy.LifetimeActions?.Select(action => new LifetimeAction
        {
            Action = new LifetimeActionAction { ActionType = action.Action.ToString() },
            Trigger = new LifetimeActionTrigger
            {
                DaysBeforeExpiry = action.DaysBeforeExpiry,
                LifetimePercentage = action.LifetimePercentage,
            },
        }).ToArray();
    }

    private static void ApplyOutputs(Certificate properties, Uri vaultUri, KeyVaultCertificateWithPolicy certificate, CertificateProperties source)
    {
        properties.Version = source.Version;
        properties.Id = certificate.Id?.AbsoluteUri;
        properties.VersionlessId = Conversions.ToVersionlessId(vaultUri, "certificates", properties.Name);
        properties.SecretId = certificate.SecretId?.AbsoluteUri;
        properties.VersionlessSecretId = Conversions.ToVersionlessId(vaultUri, "secrets", properties.Name);
        properties.KeyId = certificate.KeyId?.AbsoluteUri;

        if (certificate.Cer is { Length: > 0 } cer)
        {
            properties.CertificateData = Conversions.ToHexLower(cer);
            properties.CertificateDataBase64 = Convert.ToBase64String(cer);
        }

        if (source.X509Thumbprint is { Length: > 0 } thumbprint)
        {
            properties.Thumbprint = Conversions.ToHexUpper(thumbprint);
        }

        properties.CertificateAttributes = new CertificateAttributeOutputs
        {
            Enabled = source.Enabled,
            Created = Conversions.ToIso8601(source.CreatedOn),
            Updated = Conversions.ToIso8601(source.UpdatedOn),
            Expires = Conversions.ToIso8601(source.ExpiresOn),
            NotBefore = Conversions.ToIso8601(source.NotBefore),
            RecoveryLevel = source.RecoveryLevel,
        };
    }
}
