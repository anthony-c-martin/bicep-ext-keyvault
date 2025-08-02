using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Bicep.Local.Extension.Host.Handlers;

namespace Bicep.Extension.KeyVault.Handlers;

public class CertificateHandler : TypedResourceHandler<Certificate, CertificateIdentifiers, Configuration>
{
    private static void CopyToCollection<TIn, TOut>(IEnumerable<TIn>? input, ICollection<TOut> output, Func<TIn, TOut> transform)
    {
        if (input is { })
        {
            foreach (var value in input)
            {
                output.Add(transform(value));
            }
        }
    }

    private static void CopyToCollection<T>(IEnumerable<T>? input, ICollection<T> output)
        => CopyToCollection(input, output, x => x);

    protected override async Task<ResourceResponse> CreateOrUpdate(ResourceRequest request, CancellationToken cancellationToken)
    {
        static Azure.Security.KeyVault.Certificates.SubjectAlternativeNames GetSans(SubjectAlternativeNames input)
        {
            Azure.Security.KeyVault.Certificates.SubjectAlternativeNames output = new();
            CopyToCollection(input.Emails, output.Emails);
            CopyToCollection(input.DnsNames, output.DnsNames);
            CopyToCollection(input.Upns, output.UserPrincipalNames);

            return output;
        }

        var client = new CertificateClient(new Uri(request.Config.VaultUri), new DefaultAzureCredential());

        var policy = new CertificatePolicy(
            issuerName: request.Properties.Issuer?.Name ?? "Self",
            subject: request.Properties.X509Properties?.Subject ?? "CN=DefaultPolicy",
            subjectAlternativeNames: request.Properties.X509Properties?.SubjectAlternativeNames is { } sans ? GetSans(sans) : null);

        policy.Exportable = request.Properties.Key?.Exportable;
        policy.KeyType = request.Properties.Key?.KeyType;
        policy.KeySize = request.Properties.Key?.KeySize;
        policy.ReuseKey = request.Properties.Key?.ReuseKey;
        policy.KeyCurveName = request.Properties.Key?.Curve is { } curve ? new(curve) : null;

        policy.ContentType = request.Properties.Secret?.ContentType;

        CopyToCollection(request.Properties.X509Properties?.Ekus, policy.EnhancedKeyUsage);
        CopyToCollection(request.Properties.X509Properties?.KeyUsage, policy.KeyUsage, x => new(x));
        policy.ValidityInMonths = request.Properties.X509Properties?.ValidityInMonths;

        CopyToCollection(request.Properties.LifetimeActions, policy.LifetimeActions, x => new(new(x.Action?.ActionType))
        {
            DaysBeforeExpiry = x.Trigger?.DaysBeforeExpiry,
            LifetimePercentage = x.Trigger?.LifetimePercentage,
        });

        policy.CertificateType = request.Properties.Issuer?.CertificateType;
        policy.CertificateTransparency = request.Properties.Issuer?.CertificateTransparency;

        policy.Enabled = request.Properties.Attributes?.Enabled;

        var operation = await client.StartCreateCertificateAsync(request.Properties.Name, policy, cancellationToken: cancellationToken);

        // You can await the completion of the create certificate operation.
        // You should run UpdateStatus in another thread or do other work like pumping messages between calls.
        while (!operation.HasCompleted)
        {
            await Task.Delay(2000, cancellationToken);
            await operation.UpdateStatusAsync(cancellationToken);
        }

        // TODO return information about the certificate
        var certificate = operation.Value;

        return GetResponse(request);
    }

    protected override CertificateIdentifiers GetIdentifiers(Certificate properties)
        => new()
        {
            Name = properties.Name,
        };
}
