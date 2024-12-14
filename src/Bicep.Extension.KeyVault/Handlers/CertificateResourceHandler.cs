// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
using System.Text.Json.Nodes;
using Bicep.Local.Extension.Protocol;
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using System.Text.Json;
using System.Reflection;

namespace Bicep.Extension.KeyVault.Handlers;

public class CertificateResourceHandler : IResourceHandler
{
    public string ResourceType => "Certificate";

    private record Identifiers(
        string Name);

    private record KeyProperties(
        bool? Exportable,
        string? KeyType,
        int? KeySize,
        bool? ReuseKey,
        string? Curve);

    private record SecretProperties(
        string? ContentType);

    private record SubjectAlternativeNames(
        string[]? Emails,
        string[]? DnsNames,
        string[]? Upns);

    private record X509Properties(
        string? Subject,
        string[]? Ekus,
        SubjectAlternativeNames? SubjectAlternativeNames,
        string[]? KeyUsage,
        int? ValidityInMonths);

    private record Trigger(
        int? LifetimePercentage,
        int? DaysBeforeExpiry);

    private record Action(
        string? ActionType);

    private record LifetimeAction(
        Trigger? Trigger,
        Action Action);

    private record Issuer(
        string? Name,
        string? CertificateType,
        bool? CertificateTransparency);

    private record CertificateAttributes(
        bool? Enabled);

    private record Properties(
        string Name,
        KeyProperties? Key,
        SecretProperties? Secret,
        X509Properties? X509Properties,
        LifetimeAction[]? LifetimeActions,
        Issuer? Issuer,
        CertificateAttributes? Attributes);

    private static Properties GetProperties(JsonObject properties)
        => properties.Deserialize<Properties>(new JsonSerializerOptions(JsonSerializerDefaults.Web))!;

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

    private static void CopyToCollection<TIn, TOut>(IEnumerable<TIn>? input, ICollection<TOut> output, Func<TIn, TOut> transform)
    {
        if (input is {}) {
            foreach (var value in input) {
                output.Add(transform(value));
            }
        }
    }

    private static void CopyToCollection<T>(IEnumerable<T>? input, ICollection<T> output)
        => CopyToCollection(input, output, x => x);

    public async Task<LocalExtensibilityOperationResponse> CreateOrUpdate(ResourceSpecification request, CancellationToken cancellationToken)
    {
        static Azure.Security.KeyVault.Certificates.SubjectAlternativeNames GetSans(SubjectAlternativeNames input)
        {
            Azure.Security.KeyVault.Certificates.SubjectAlternativeNames output = new();
            CopyToCollection(input.Emails, output.Emails);
            CopyToCollection(input.DnsNames, output.DnsNames);
            CopyToCollection(input.Upns, output.UserPrincipalNames);

            return output;
        }

        var vaultUri = request.Config!["vaultUri"]!.GetValue<string>();
        var properties = GetProperties(request.Properties);
        
        var client = new CertificateClient(new Uri(vaultUri), new DefaultAzureCredential());

        var policy = new CertificatePolicy(
            issuerName: properties.Issuer?.Name ?? "Self",
            subject: properties.X509Properties?.Subject ?? "CN=DefaultPolicy",
            subjectAlternativeNames: properties.X509Properties?.SubjectAlternativeNames is {} sans ? GetSans(sans) : null);

        policy.Exportable = properties.Key?.Exportable;
        policy.KeyType = properties.Key?.KeyType;
        policy.KeySize = properties.Key?.KeySize;
        policy.ReuseKey = properties.Key?.ReuseKey;
        policy.KeyCurveName = properties.Key?.Curve is {} curve ? new(curve) : null;

        policy.ContentType = properties.Secret?.ContentType;

        CopyToCollection(properties.X509Properties?.Ekus, policy.EnhancedKeyUsage);
        CopyToCollection(properties.X509Properties?.KeyUsage, policy.KeyUsage, x => new(x));
        policy.ValidityInMonths = properties.X509Properties?.ValidityInMonths;

        CopyToCollection(properties.LifetimeActions, policy.LifetimeActions, x => new(new(x.Action.ActionType))
        {
            DaysBeforeExpiry = x.Trigger?.DaysBeforeExpiry,
            LifetimePercentage = x.Trigger?.LifetimePercentage,
        });

        policy.CertificateType = properties.Issuer?.CertificateType;
        policy.CertificateTransparency = properties.Issuer?.CertificateTransparency;

        policy.Enabled = properties.Attributes?.Enabled;

        var operation = await client.StartCreateCertificateAsync(properties.Name, policy, cancellationToken: cancellationToken);

        // You can await the completion of the create certificate operation.
        // You should run UpdateStatus in another thread or do other work like pumping messages between calls.
        while (!operation.HasCompleted)
        {
            await Task.Delay(2000, cancellationToken);
            await operation.UpdateStatusAsync(cancellationToken);
        }

        // TODO return information about the certificate
        var certificate = operation.Value;

        return new(
            new(request.Type, request.ApiVersion, "Succeeded", GetIdentifiersObject(properties.Name), request.Config, request.Properties!),
            null);
    }
}
