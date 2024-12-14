// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Text;
using Azure.Bicep.Types;
using Azure.Bicep.Types.Concrete;
using Azure.Bicep.Types.Index;
using Azure.Bicep.Types.Serialization;

namespace Bicep.Types.KeyVault;

public static class TypeGenerator
{
    public static string GetString(Action<Stream> streamWriteFunc)
    {
        using var memoryStream = new MemoryStream();
        streamWriteFunc(memoryStream);

        return Encoding.UTF8.GetString(memoryStream.ToArray());
    }

    public static Dictionary<string, string> GenerateTypes()
    {
        var factory = new TypeFactory([]);

        var secureStringType = factory.Create(() => new StringType(sensitive: true));
        var stringType = factory.Create(() => new StringType());
        var stringArrayType = factory.Create(() => new ArrayType(factory.GetReference(stringType)));
        var boolType = factory.Create(() => new BooleanType());
        var intType = factory.Create(() => new IntegerType());

        var secretBodyType = factory.Create(() => new ObjectType("body", new Dictionary<string, ObjectTypeProperty>
        {
            ["name"] = new(factory.GetReference(stringType), ObjectTypePropertyFlags.Required | ObjectTypePropertyFlags.Identifier, "The name of the secret in KeyVault."),
            ["value"] = new(factory.GetReference(stringType), ObjectTypePropertyFlags.WriteOnly, "The value of the secret in KeyVault."),
        }, null));

        var secretType = factory.Create(() => new ResourceType(
            "Secret",
            ScopeType.Unknown,
            null,
            factory.GetReference(secretBodyType),
            ResourceFlags.None,
            null));

        var certificateBodyType = factory.Create(() => new ObjectType("body", new Dictionary<string, ObjectTypeProperty>
        {
            ["name"] = new(factory.GetReference(stringType), ObjectTypePropertyFlags.Required | ObjectTypePropertyFlags.Identifier, "The name of the certificate in KeyVault."),
            ["key"] = new(factory.GetReference(factory.Create(() => new ObjectType("key", new Dictionary<string, ObjectTypeProperty>
            {
                ["exportable"] = new(factory.GetReference(boolType), ObjectTypePropertyFlags.None, null),
                ["keyType"] = new(factory.GetReference(stringType), ObjectTypePropertyFlags.None, null),
                ["keySize"] = new(factory.GetReference(intType), ObjectTypePropertyFlags.None, null),
                ["reuseKey"] = new(factory.GetReference(boolType), ObjectTypePropertyFlags.None, null),
                ["curve"] = new(factory.GetReference(stringType), ObjectTypePropertyFlags.None, null),
            }, null))), ObjectTypePropertyFlags.None, null),
            ["secret"] = new(factory.GetReference(factory.Create(() => new ObjectType("secret", new Dictionary<string, ObjectTypeProperty>
            {
                ["contentType"] = new(factory.GetReference(stringType), ObjectTypePropertyFlags.None, null),
            }, null))), ObjectTypePropertyFlags.None, null),
            ["x509Properties"] = new(factory.GetReference(factory.Create(() => new ObjectType("x509Properties", new Dictionary<string, ObjectTypeProperty>
            {
                ["subject"] = new(factory.GetReference(stringType), ObjectTypePropertyFlags.None, null),
                ["ekus"] = new(factory.GetReference(stringArrayType), ObjectTypePropertyFlags.None, null),
                ["subjectAlternativeNames"] = new(factory.GetReference(factory.Create(() => new ObjectType("subjectAlternativeNames", new Dictionary<string, ObjectTypeProperty>
                {
                    ["emails"] = new(factory.GetReference(stringArrayType), ObjectTypePropertyFlags.None, null),
                    ["dnsNames"] = new(factory.GetReference(stringArrayType), ObjectTypePropertyFlags.None, null),
                    ["upns"] = new(factory.GetReference(stringArrayType), ObjectTypePropertyFlags.None, null),
                }, null))), ObjectTypePropertyFlags.None, null),
                ["keyUsage"] = new(factory.GetReference(stringArrayType), ObjectTypePropertyFlags.None, null),
                ["validityInMonths"] = new(factory.GetReference(intType), ObjectTypePropertyFlags.None, null),
            }, null))), ObjectTypePropertyFlags.None, null),
            ["lifetimeActions"] = new(factory.GetReference(factory.Create(() => new ArrayType(factory.GetReference(factory.Create(() => new ObjectType("lifetimeAction", new Dictionary<string, ObjectTypeProperty>
            {
                ["trigger"] = new(factory.GetReference(factory.Create(() => new ObjectType("trigger", new Dictionary<string, ObjectTypeProperty>
                {
                    ["lifetimePercentage"] = new(factory.GetReference(intType), ObjectTypePropertyFlags.None, null),
                    ["daysBeforeExpiry"] = new(factory.GetReference(intType), ObjectTypePropertyFlags.None, null),
                }, null))), ObjectTypePropertyFlags.None, null),
                ["action"] = new(factory.GetReference(factory.Create(() => new ObjectType("action", new Dictionary<string, ObjectTypeProperty>
                {
                    ["actionType"] = new(factory.GetReference(stringType), ObjectTypePropertyFlags.None, null),
                }, null))), ObjectTypePropertyFlags.None, null),
            }, null)))))), ObjectTypePropertyFlags.None, null),
            ["issuer"] = new(factory.GetReference(factory.Create(() => new ObjectType("issuer", new Dictionary<string, ObjectTypeProperty>
            {
                ["name"] = new(factory.GetReference(stringType), ObjectTypePropertyFlags.None, null),
                ["certificateType"] = new(factory.GetReference(stringType), ObjectTypePropertyFlags.None, null),
                ["certificateTransparency"] = new(factory.GetReference(boolType), ObjectTypePropertyFlags.None, null),
            }, null))), ObjectTypePropertyFlags.None, null),
            ["attributes"] = new(factory.GetReference(factory.Create(() => new ObjectType("attributes", new Dictionary<string, ObjectTypeProperty>
            {
                ["enabled"] = new(factory.GetReference(boolType), ObjectTypePropertyFlags.None, null),
            }, null))), ObjectTypePropertyFlags.None, null),
        }, null));

        var certificateType = factory.Create(() => new ResourceType(
            "Certificate",
            ScopeType.Unknown,
            null,
            factory.GetReference(certificateBodyType),
            ResourceFlags.None,
            null));

        var configurationType = factory.Create(() => new ObjectType("configuration", new Dictionary<string, ObjectTypeProperty>
        {
            ["vaultUri"] = new(factory.GetReference(stringType), ObjectTypePropertyFlags.Required, "The KeyVault URI."),
        }, null));

        var settings = new TypeSettings(
            name: "KeyVault",
            version: "0.0.1",
            isSingleton: false,
            configurationType: new CrossFileTypeReference("types.json", factory.GetIndex(configurationType)));

        var resourceTypes = new[] {
            secretType,
            certificateType,
        };

        var index = new TypeIndex(
            resourceTypes.ToDictionary(x => x.Name, x => new CrossFileTypeReference("types.json", factory.GetIndex(x))),
            new Dictionary<string, IReadOnlyDictionary<string, IReadOnlyList<CrossFileTypeReference>>>(),
            settings,
            null);

        return new Dictionary<string, string>{
            ["index.json"] = GetString(stream => TypeSerializer.SerializeIndex(stream, index)),
            ["types.json"] = GetString(stream => TypeSerializer.Serialize(stream, factory.GetTypes())),
        };
    }
}

/*
    private record KeyProperties(


    private record SecretProperties(
        string? ContentType);

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
*/