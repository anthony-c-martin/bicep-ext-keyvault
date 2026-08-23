using Bicep.Extension.KeyVault.Handlers;

namespace Bicep.Extension.KeyVault.Tests;

/// <summary>
/// Covers how the data plane endpoint is resolved: a resource may override the extension
/// configuration, and the resolved value must always be reflected in the identifiers so that
/// subsequent reads and deletes target the same vault.
/// </summary>
[TestClass]
public sealed class EndpointResolutionTests
{
    [TestMethod]
    public async Task Vault_uri_falls_back_to_the_extension_configuration()
    {
        var response = await HandlerHarness.PreviewAsync(new SecretHandler(), "Secret", new
        {
            name = "my-secret",
            value = "super-secret-value",
        });

        Assert.AreEqual(HandlerHarness.TestVaultUri, response.ResourceIdentifiers().GetProperty("vaultUri").GetString());
    }

    [TestMethod]
    public async Task Resource_level_vault_uri_overrides_the_configuration()
    {
        var response = await HandlerHarness.PreviewAsync(new SecretHandler(), "Secret", new
        {
            name = "my-secret",
            value = "super-secret-value",
            vaultUri = "https://other-vault.vault.azure.net/",
        });

        Assert.AreEqual("https://other-vault.vault.azure.net/", response.ResourceIdentifiers().GetProperty("vaultUri").GetString());
    }

    [TestMethod]
    public async Task A_missing_trailing_slash_is_normalised()
    {
        var response = await HandlerHarness.PreviewAsync(new SecretHandler(), "Secret", new
        {
            name = "my-secret",
            value = "super-secret-value",
            vaultUri = "https://other-vault.vault.azure.net",
        });

        Assert.AreEqual("https://other-vault.vault.azure.net/", response.ResourceIdentifiers().GetProperty("vaultUri").GetString());
    }

    [TestMethod]
    public async Task A_missing_vault_uri_is_reported_at_preview_time()
    {
        var response = await HandlerHarness.PreviewAsync(
            new SecretHandler(),
            "Secret",
            new { name = "my-secret", value = "super-secret-value" },
            configuration: new { });

        Assert.AreEqual("MissingEndpoint", response.ErrorCode());
    }

    [TestMethod]
    public async Task A_malformed_vault_uri_is_reported_at_preview_time()
    {
        var response = await HandlerHarness.PreviewAsync(
            new SecretHandler(),
            "Secret",
            new { name = "my-secret", value = "super-secret-value" },
            vaultUri: "not-a-uri");

        Assert.AreEqual("InvalidEndpoint", response.ErrorCode());
    }

    [TestMethod]
    public async Task Managed_hsm_resources_resolve_the_managed_hsm_uri()
    {
        var response = await HandlerHarness.PreviewAsync(
            new ManagedHsmKeyHandler(),
            "ManagedHsmKey",
            new { name = "my-key", keyType = "RSA-HSM" },
            configuration: new { managedHsmUri = "https://my-hsm.managedhsm.azure.net/" });

        Assert.AreEqual("https://my-hsm.managedhsm.azure.net/", response.ResourceIdentifiers().GetProperty("managedHsmUri").GetString());
    }

    [TestMethod]
    public async Task Managed_hsm_resources_do_not_fall_back_to_the_vault_uri()
    {
        var response = await HandlerHarness.PreviewAsync(
            new ManagedHsmKeyHandler(),
            "ManagedHsmKey",
            new { name = "my-key", keyType = "RSA-HSM" });

        Assert.AreEqual("MissingEndpoint", response.ErrorCode());
    }

    [TestMethod]
    public async Task Certificate_contacts_are_identified_by_their_vault()
    {
        var response = await HandlerHarness.PreviewAsync(new CertificateContactsHandler(), "CertificateContacts", new
        {
            contacts = new[] { new { email = "admin@contoso.com", name = "Admin" } },
        });

        var identifiers = response.ResourceIdentifiers();
        Assert.AreEqual(HandlerHarness.TestVaultUri, identifiers.GetProperty("vaultUri").GetString());
    }
}
