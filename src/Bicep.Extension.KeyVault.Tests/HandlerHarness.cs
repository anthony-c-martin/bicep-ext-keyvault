using System.Text.Json;
using Bicep.Local.Extension.Host.Handlers;
using Bicep.Local.Rpc;

namespace Bicep.Extension.KeyVault.Tests;

/// <summary>
/// Helpers for invoking resource handlers through their public <see cref="IResourceHandler"/> entry
/// point, mirroring how the Bicep local-deploy host calls them (JSON in, JSON out).
/// </summary>
public static class HandlerHarness
{
    // The Bicep host exchanges properties/config as camelCase JSON.
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web);

    public static Task<LocalExtensibilityOperationResponse> PreviewAsync(
        IResourceHandler handler,
        string type,
        object properties,
        string vaultUri = "https://test-vault.vault.azure.net/",
        CancellationToken cancellationToken = default)
    {
        var spec = new ResourceSpecification
        {
            Type = type,
            Config = JsonSerializer.Serialize(new { vaultUri }, SerializerOptions),
            Properties = JsonSerializer.Serialize(properties, SerializerOptions),
        };

        return handler.Preview(spec, cancellationToken);
    }

    public static JsonElement ResourceProperties(this LocalExtensibilityOperationResponse response)
    {
        Assert.IsNull(response.ErrorData);
        Assert.IsNotNull(response.Resource);
        return JsonSerializer.Deserialize<JsonElement>(response.Resource.Properties);
    }
}
