using System.Collections.Concurrent;
using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Administration;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Secrets;

namespace Bicep.Extension.KeyVault;

/// <summary>
/// Caches data plane clients, and the credential they share, per endpoint. Constructing a
/// <see cref="DefaultAzureCredential"/> re-runs the whole credential discovery chain, so creating
/// one per operation is needlessly expensive.
/// </summary>
public static class KeyVaultClients
{
    private static readonly Lazy<TokenCredential> SharedCredential = new(() => new DefaultAzureCredential());

    private static readonly ConcurrentDictionary<Uri, SecretClient> SecretClients = new();
    private static readonly ConcurrentDictionary<Uri, KeyClient> KeyClients = new();
    private static readonly ConcurrentDictionary<Uri, CertificateClient> CertificateClients = new();
    private static readonly ConcurrentDictionary<Uri, KeyVaultAccessControlClient> AccessControlClients = new();

    public static SecretClient Secrets(Uri endpoint)
        => SecretClients.GetOrAdd(endpoint, uri => new SecretClient(uri, SharedCredential.Value));

    public static KeyClient Keys(Uri endpoint)
        => KeyClients.GetOrAdd(endpoint, uri => new KeyClient(uri, SharedCredential.Value));

    public static CertificateClient Certificates(Uri endpoint)
        => CertificateClients.GetOrAdd(endpoint, uri => new CertificateClient(uri, SharedCredential.Value));

    public static KeyVaultAccessControlClient AccessControl(Uri endpoint)
        => AccessControlClients.GetOrAdd(endpoint, uri => new KeyVaultAccessControlClient(uri, SharedCredential.Value));
}
