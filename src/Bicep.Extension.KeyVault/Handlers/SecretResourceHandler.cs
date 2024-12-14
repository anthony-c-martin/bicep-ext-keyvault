// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
using System.Text.Json.Nodes;
using Bicep.Local.Extension.Protocol;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;

namespace Bicep.Extension.KeyVault.Handlers;

public class SecretResourceHandler : IResourceHandler
{
    public string ResourceType => "Secret";

    private record Identifiers(
        string Name);

    private record Properties(
        string Name,
        string Value);

    private static Properties GetProperties(JsonObject properties)
        => new(
            properties["name"]!.GetValue<string>(),
            properties["value"]!.GetValue<string>());

    private static JsonObject GetIdentifiersObject(string name)
        => new()
        {
            ["name"] = name,
        };

    public Task<LocalExtensibilityOperationResponse> Delete(ResourceReference request, CancellationToken cancellationToken)
        => throw new NotImplementedException();

    public Task<LocalExtensibilityOperationResponse> Get(ResourceReference request, CancellationToken cancellationToken)
        => throw new NotImplementedException();

    public Task<LocalExtensibilityOperationResponse> Preview(ResourceSpecification request, CancellationToken cancellationToken)
        => throw new NotImplementedException();

    public async Task<LocalExtensibilityOperationResponse> CreateOrUpdate(ResourceSpecification request, CancellationToken cancellationToken)
    {
        var vaultUri = request.Config!["vaultUri"]!.GetValue<string>();
        var properties = GetProperties(request.Properties);
        
        var client = new SecretClient(new Uri(vaultUri), new DefaultAzureCredential());
        var secret = await client.SetSecretAsync(properties.Name, properties.Value);

        return new(
            new(request.Type, request.ApiVersion, "Succeeded", GetIdentifiersObject(properties.Name), request.Config, request.Properties!),
            null);
    }
}
