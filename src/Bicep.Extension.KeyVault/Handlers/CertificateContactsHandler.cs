using Azure;
using SdkCertificateContact = Azure.Security.KeyVault.Certificates.CertificateContact;

namespace Bicep.Extension.KeyVault.Handlers;

public class CertificateContactsHandler : KeyVaultResourceHandler<CertificateContacts, CertificateContactsIdentifiers>
{
    protected override Uri ResolveEndpoint(CertificateContactsIdentifiers identifiers, Configuration configuration)
    {
        var endpoint = ResolveEndpoint(identifiers.VaultUri, configuration.VaultUri, nameof(CertificateContacts.VaultUri), nameof(Configuration.VaultUri));
        identifiers.VaultUri = endpoint.AbsoluteUri;

        return endpoint;
    }

    protected override async Task<ResourceResponse> CreateOrUpdate(ResourceRequest request, CancellationToken cancellationToken)
    {
        var properties = request.Properties;
        var vaultUri = ResolveEndpoint(properties, request.Config);
        var client = KeyVaultClients.Certificates(vaultUri);

        var contacts = properties.Contacts.Select(contact => new SdkCertificateContact
        {
            Email = contact.Email,
            Name = contact.Name,
            Phone = contact.Phone,
        });

        await client.SetContactsAsync(contacts, cancellationToken);

        return GetResponse(request);
    }

    protected override async Task<ResourceResponse> Get(ReferenceRequest request, CancellationToken cancellationToken)
    {
        var identifiers = request.Identifiers;
        var vaultUri = ResolveEndpoint(identifiers, request.Config);
        var client = KeyVaultClients.Certificates(vaultUri);

        IEnumerable<SdkCertificateContact> contacts;
        try
        {
            contacts = (await client.GetContactsAsync(cancellationToken)).Value;
        }
        catch (RequestFailedException exception) when (IsNotFound(exception))
        {
            throw new KeyVaultExtensionException("ResourceNotFound", $"No certificate contacts are configured on vault '{vaultUri}'.", nameof(CertificateContacts.Contacts));
        }

        var properties = new CertificateContacts
        {
            VaultUri = identifiers.VaultUri,
            Contacts = contacts.Select(contact => new CertificateContact
            {
                Email = contact.Email ?? string.Empty,
                Name = contact.Name,
                Phone = contact.Phone,
            }).ToArray(),
        };

        return GetResponse(request, properties);
    }

    protected override async Task<ResourceResponse> Delete(ReferenceRequest request, CancellationToken cancellationToken)
    {
        var identifiers = request.Identifiers;
        var vaultUri = ResolveEndpoint(identifiers, request.Config);
        var client = KeyVaultClients.Certificates(vaultUri);

        try
        {
            await client.DeleteContactsAsync(cancellationToken);
        }
        catch (RequestFailedException exception) when (IsNotFound(exception))
        {
            // Already gone; deletion is idempotent.
        }

        return GetResponse(request, null);
    }

    protected override CertificateContactsIdentifiers GetIdentifiers(CertificateContacts properties)
        => new()
        {
            VaultUri = properties.VaultUri,
        };
}
