using Azure;
using Bicep.Local.Extension.Host.Handlers;
using Bicep.Local.Rpc;

namespace Bicep.Extension.KeyVault.Handlers;

/// <summary>
/// Shared plumbing for every KeyVault resource: endpoint resolution, error translation and a
/// preview that validates configuration without touching the network.
/// </summary>
public abstract class KeyVaultResourceHandler<TProperties, TIdentifiers> : TypedResourceHandler<TProperties, TIdentifiers, Configuration>
    where TProperties : class, TIdentifiers
    where TIdentifiers : class
{
    /// <summary>
    /// Resolves the data plane endpoint for the resource, preferring the resource's own override
    /// over the extension configuration. Implementations must write the resolved value back onto
    /// <paramref name="identifiers"/> so that the identifiers reported to Bicep are always fully
    /// qualified, regardless of where the endpoint came from.
    /// </summary>
    protected abstract Uri ResolveEndpoint(TIdentifiers identifiers, Configuration configuration);

    protected override Task<ResourceResponse> Preview(ResourceRequest request, CancellationToken cancellationToken)
    {
        // Resolve eagerly so that a missing or malformed endpoint is reported at preview time,
        // and so the previewed identifiers match what a deployment would produce.
        ResolveEndpoint(request.Properties, request.Config);

        return Task.FromResult(GetResponse(request));
    }

    protected static Uri ResolveEndpoint(string? resourceValue, string? configurationValue, string propertyName, string configurationName)
    {
        var value = resourceValue ?? configurationValue;

        if (string.IsNullOrWhiteSpace(value))
        {
            throw new KeyVaultExtensionException(
                "MissingEndpoint",
                $"No endpoint was supplied. Set '{configurationName}' in the extension configuration, or set '{propertyName}' on the resource.",
                propertyName);
        }

        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp))
        {
            throw new KeyVaultExtensionException(
                "InvalidEndpoint",
                $"The value '{value}' supplied for '{propertyName}' is not a valid absolute URI. Expected a value such as 'https://myvault.vault.azure.net/'.",
                propertyName);
        }

        // KeyVault identifiers are built by appending to the endpoint, which requires a trailing
        // slash for Uri composition to preserve the whole path.
        return uri.AbsolutePath.EndsWith('/') ? uri : new Uri(uri + "/");
    }

    protected static Guid ParseGuid(string value, string propertyName)
        => Guid.TryParse(value, out var parsed)
            ? parsed
            : throw new KeyVaultExtensionException(
                "InvalidGuid",
                $"The value '{value}' supplied for '{propertyName}' is not a valid GUID.",
                propertyName);

    protected static bool IsNotFound(RequestFailedException exception)
        => exception.Status == 404;

    protected override Task<LocalExtensibilityOperationResponse> WrapExceptionsAsync(Func<Task<LocalExtensibilityOperationResponse>> func)
        // Translate our own failures into the host's structured error contract before the base
        // implementation collapses everything unrecognised into a generic RPC error.
        => base.WrapExceptionsAsync(async () =>
        {
            try
            {
                return await func();
            }
            catch (KeyVaultExtensionException exception)
            {
                throw new ResourceErrorException(exception.Code, exception.Message, exception.Target);
            }
            catch (RequestFailedException exception)
            {
                throw new ResourceErrorException(exception.ErrorCode ?? "RequestFailed", exception.Message);
            }
        });
}
