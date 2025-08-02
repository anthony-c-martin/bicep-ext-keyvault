using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Bicep.Local.Extension.Host.Handlers;

namespace Bicep.Extension.KeyVault.Handlers;

public class SecretHandler : TypedResourceHandler<Secret, SecretIdentifiers, Configuration>
{
    protected override async Task<ResourceResponse> CreateOrUpdate(ResourceRequest request, CancellationToken cancellationToken)
    {
        var client = new SecretClient(new Uri(request.Config.VaultUri), new DefaultAzureCredential());
        await client.SetSecretAsync(request.Properties.Name, request.Properties.Value);

        return GetResponse(request);

    }

    protected override SecretIdentifiers GetIdentifiers(Secret properties)
        => new()
        {
            Name = properties.Name,
        };
}
