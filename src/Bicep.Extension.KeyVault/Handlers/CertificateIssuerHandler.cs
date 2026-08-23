using Azure;
using Azure.Security.KeyVault.Certificates;
using SdkCertificateIssuer = Azure.Security.KeyVault.Certificates.CertificateIssuer;

namespace Bicep.Extension.KeyVault.Handlers;

public class CertificateIssuerHandler : KeyVaultResourceHandler<CertificateIssuer, CertificateIssuerIdentifiers>
{
    protected override Uri ResolveEndpoint(CertificateIssuerIdentifiers identifiers, Configuration configuration)
    {
        var endpoint = ResolveEndpoint(identifiers.VaultUri, configuration.VaultUri, nameof(CertificateIssuer.VaultUri), nameof(Configuration.VaultUri));
        identifiers.VaultUri = endpoint.AbsoluteUri;

        return endpoint;
    }

    protected override async Task<ResourceResponse> CreateOrUpdate(ResourceRequest request, CancellationToken cancellationToken)
    {
        var properties = request.Properties;
        var vaultUri = ResolveEndpoint(properties, request.Config);
        var client = KeyVaultClients.Certificates(vaultUri);

        var issuer = new SdkCertificateIssuer(properties.Name, properties.ProviderName)
        {
            AccountId = properties.AccountId,
            OrganizationId = properties.OrgId,
            Enabled = properties.Enabled,
        };

        // Use CreateIssuerAsync (PUT) rather than UpdateIssuerAsync (PATCH): PATCH cannot create a
        // new issuer, and it silently ignores removed properties. PUT gives true desired-state
        // semantics, at the cost of requiring the password on every deployment.
        if (properties.Password is { } password)
        {
            issuer.Password = password;
        }

        foreach (var admin in properties.Admins ?? [])
        {
            issuer.AdministratorContacts.Add(new AdministratorContact
            {
                Email = admin.EmailAddress,
                FirstName = admin.FirstName,
                LastName = admin.LastName,
                Phone = admin.Phone,
            });
        }

        var current = await client.CreateIssuerAsync(issuer, cancellationToken);

        ApplyOutputs(properties, current.Value);

        return GetResponse(request);
    }

    protected override async Task<ResourceResponse> Get(ReferenceRequest request, CancellationToken cancellationToken)
    {
        var identifiers = request.Identifiers;
        var vaultUri = ResolveEndpoint(identifiers, request.Config);
        var client = KeyVaultClients.Certificates(vaultUri);

        SdkCertificateIssuer issuer;
        try
        {
            issuer = await client.GetIssuerAsync(identifiers.Name, cancellationToken);
        }
        catch (RequestFailedException exception) when (IsNotFound(exception))
        {
            throw new KeyVaultExtensionException("ResourceNotFound", $"The certificate issuer '{identifiers.Name}' was not found in vault '{vaultUri}'.", nameof(CertificateIssuerIdentifiers.Name));
        }

        var properties = new CertificateIssuer
        {
            VaultUri = identifiers.VaultUri,
            Name = identifiers.Name,
            ProviderName = issuer.Provider ?? string.Empty,
            OrgId = issuer.OrganizationId,
            AccountId = issuer.AccountId,
            Enabled = issuer.Enabled,
            Admins = issuer.AdministratorContacts?.Select(contact => new CertificateIssuerAdmin
            {
                EmailAddress = contact.Email ?? string.Empty,
                FirstName = contact.FirstName,
                LastName = contact.LastName,
                Phone = contact.Phone,
            }).ToArray(),
        };

        ApplyOutputs(properties, issuer);

        // 'password' is write-only and never returned by KeyVault.
        return GetResponse(request, properties);
    }

    protected override async Task<ResourceResponse> Delete(ReferenceRequest request, CancellationToken cancellationToken)
    {
        var identifiers = request.Identifiers;
        var vaultUri = ResolveEndpoint(identifiers, request.Config);
        var client = KeyVaultClients.Certificates(vaultUri);

        try
        {
            await client.DeleteIssuerAsync(identifiers.Name, cancellationToken);
        }
        catch (RequestFailedException exception) when (IsNotFound(exception))
        {
            // Already gone; deletion is idempotent.
        }

        return GetResponse(request, null);
    }

    protected override CertificateIssuerIdentifiers GetIdentifiers(CertificateIssuer properties)
        => new()
        {
            VaultUri = properties.VaultUri,
            Name = properties.Name,
        };

    private static void ApplyOutputs(CertificateIssuer properties, SdkCertificateIssuer issuer)
    {
        properties.Id = issuer.Id?.AbsoluteUri;
        properties.CreatedOn = Conversions.ToIso8601(issuer.CreatedOn);
        properties.UpdatedOn = Conversions.ToIso8601(issuer.UpdatedOn);
    }
}
