// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
using System.Text.Json.Nodes;
using Bicep.Local.Extension.Protocol;

namespace Bicep.Extension.KeyVault.Handlers;

public class SecretResourceHandler : IResourceHandler
{
    public override string ResourceType => "Secret";

    private static (string keyVault, string name) GetIdentifiers(JsonObject properties)
    {
        return new(
            properties["keyVault"]!.GetValue<string>(),
            properties["name"]!.GetValue<string>());
    }

    private static JsonObject GetIdentifiersObject(string keyVault, string name)
        => new()
        {
            ["keyVault"] = owner,
            ["name"] = name,
        };

    public Task<LocalExtensibilityOperationResponse> Delete(ResourceReference request, CancellationToken cancellationToken)
        => throw new NotImplementedException();

    public async Task<LocalExtensibilityOperationResponse> Get(ResourceReference request, CancellationToken cancellationToken)
    {
        var (keyVault, name) = GetIdentifiers(request.Identifiers);

        var response = await client.Connection.Get<object>(ApiUrls.RepoCollaborator(owner, name, user), null);
        var body = JsonNode.Parse(response.Body.ToString()!) as JsonObject;

        return new(
            new(request.Type, request.ApiVersion, "Succeeded", request.Identifiers, request.Config, body!),
            null);
    }

    public async Task<LocalExtensibilityOperationResponse> Preview(ResourceSpecification request, CancellationToken cancellationToken)
    {
        await Task.Yield();
        var (keyVault, name) = GetIdentifiers(request.Properties);

        return new(
            new(request.Type, request.ApiVersion, "Succeeded", GetIdentifiersObject(owner, name, user), request.Config, GetIdentifiersObject(owner, name, user)),
            null);
    }

    public async Task<LocalExtensibilityOperationResponse> CreateOrUpdate(ResourceSpecification request, CancellationToken cancellationToken)
    {
        var (keyVault, name) = GetIdentifiers(request.Properties);

        var response = await client.Connection.Put<object>(ApiUrls.RepoCollaborator(owner, name, user), null);
        var body = JsonNode.Parse(response.Body.ToString()!) as JsonObject;

        return new(
            new(request.Type, request.ApiVersion, "Succeeded", GetIdentifiersObject(owner, name, user), request.Config, body!),
            null);
    }
}
