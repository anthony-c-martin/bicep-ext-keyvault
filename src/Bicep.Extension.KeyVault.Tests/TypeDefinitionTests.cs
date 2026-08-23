using System.Text.Json;
using Bicep.Local.Extension.Types;
using Microsoft.Extensions.DependencyInjection;

namespace Bicep.Extension.KeyVault.Tests;

/// <summary>
/// Generates the Bicep type definition exactly the way the extension host does, so that unsupported
/// property shapes, duplicate resource names and missing flags fail the build rather than a
/// deployment.
/// </summary>
[TestClass]
public sealed class TypeDefinitionTests
{
    private static TypeDefinition Generate()
    {
        var services = new ServiceCollection();
        services.AddBicepExtension()
            .WithDefaults("keyvault", "0.0.0-test", isSingleton: true)
            .WithTypeAssembly(typeof(Configuration).Assembly)
            .WithConfigurationType(typeof(Configuration));

        using var provider = services.BuildServiceProvider();

        return provider.GetRequiredService<ITypeDefinitionBuilder>().GenerateTypeDefinition();
    }

    private static JsonElement[] GenerateTypes()
        => JsonSerializer.Deserialize<JsonElement>(Generate().TypeFileContents.Values.Single()).EnumerateArray().ToArray();

    private static JsonElement ObjectType(JsonElement[] types, string name)
        => types.Single(type =>
            type.GetProperty("$type").GetString() == "ObjectType" &&
            type.TryGetProperty("name", out var typeName) &&
            typeName.GetString() == name);

    [TestMethod]
    public void All_resource_types_are_generated()
    {
        var index = JsonSerializer.Deserialize<JsonElement>(Generate().IndexFileContent);
        var resources = index.GetProperty("resources").EnumerateObject().Select(x => x.Name).Order().ToArray();

        CollectionAssert.AreEqual(
            new[]
            {
                "Certificate",
                "CertificateContacts",
                "CertificateIssuer",
                "Key",
                "ManagedHsmKey",
                "ManagedHsmKeyRotationPolicy",
                "ManagedHsmRoleAssignment",
                "ManagedHsmRoleDefinition",
                "Secret",
            },
            resources);
    }

    [TestMethod]
    public void Configuration_exposes_the_expected_settings()
    {
        var configuration = ObjectType(GenerateTypes(), nameof(Configuration));
        var properties = configuration.GetProperty("properties").EnumerateObject().Select(x => x.Name).Order().ToArray();

        CollectionAssert.AreEqual(
            new[] { "managedHsmUri", "purgeOnDelete", "recoverSoftDeleted", "vaultUri" },
            properties);
    }

    [TestMethod]
    public void Secret_value_is_required_write_only_and_sensitive()
    {
        var types = GenerateTypes();
        var value = ObjectType(types, nameof(Secret)).GetProperty("properties").GetProperty("value");

        // Required (1) | WriteOnly (4).
        Assert.AreEqual(5, value.GetProperty("flags").GetInt32());

        var valueType = types[int.Parse(value.GetProperty("type").GetProperty("$ref").GetString()!.TrimStart('#', '/'))];
        Assert.IsTrue(valueType.GetProperty("sensitive").GetBoolean(), "The secret value must be marked sensitive.");
    }

    [TestMethod]
    public void Outputs_are_read_only()
    {
        var types = GenerateTypes();

        foreach (var (typeName, propertyName) in new[]
        {
            (nameof(Secret), "versionlessId"),
            (nameof(Certificate), "thumbprint"),
            (nameof(Certificate), "certificateDataBase64"),
            (nameof(Key), "publicKeyPem"),
            (nameof(ManagedHsmRoleDefinition), "roleType"),
        })
        {
            var flags = ObjectType(types, typeName).GetProperty("properties").GetProperty(propertyName).GetProperty("flags").GetInt32();

            Assert.AreEqual(2, flags, $"'{typeName}.{propertyName}' should be read-only.");
        }
    }

    [TestMethod]
    public void Vault_uri_is_an_optional_identifier_on_every_vault_scoped_resource()
    {
        var types = GenerateTypes();

        foreach (var typeName in new[] { nameof(Secret), nameof(Key), nameof(Certificate), nameof(CertificateIssuer), nameof(CertificateContacts) })
        {
            var flags = ObjectType(types, typeName).GetProperty("properties").GetProperty("vaultUri").GetProperty("flags").GetInt32();

            // Identifier (16), without Required (1): it falls back to the extension configuration.
            Assert.AreEqual(16, flags, $"'{typeName}.vaultUri' should be an optional identifier.");
        }
    }
}
