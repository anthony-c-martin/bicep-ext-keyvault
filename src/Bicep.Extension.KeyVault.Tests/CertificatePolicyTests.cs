using Azure.Security.KeyVault.Certificates;
using Bicep.Extension.KeyVault.Handlers;

namespace Bicep.Extension.KeyVault.Tests;

/// <summary>
/// Covers the translation from the Bicep-facing certificate model to the KeyVault SDK's
/// <see cref="CertificatePolicy"/>. The important property is that properties the user did not
/// specify are left unset, rather than being sent to KeyVault as 0 / false.
/// </summary>
[TestClass]
public sealed class CertificatePolicyTests
{
    private static Certificate MinimalCertificate() => new()
    {
        Name = "my-certificate",
        X509Properties = new X509Properties { Subject = "CN=contoso.com" },
    };

    [TestMethod]
    public void BuildPolicy_leaves_unspecified_key_properties_unset()
    {
        var certificate = MinimalCertificate();
        certificate.Key = new CertificateKeyProperties { KeyType = "RSA" };

        var policy = CertificateHandler.BuildPolicy(certificate);

        Assert.AreEqual(CertificateKeyType.Rsa, policy.KeyType);
        Assert.IsNull(policy.KeySize, "keySize was not specified, so it must not be sent as 0.");
        Assert.IsNull(policy.Exportable, "exportable was not specified, so it must not be sent as false.");
        Assert.IsNull(policy.ReuseKey, "reuseKey was not specified, so it must not be sent as false.");
        Assert.IsNull(policy.KeyCurveName);
    }

    [TestMethod]
    public void BuildPolicy_leaves_unspecified_x509_properties_unset()
    {
        var policy = CertificateHandler.BuildPolicy(MinimalCertificate());

        Assert.AreEqual("CN=contoso.com", policy.Subject);
        Assert.IsNull(policy.ValidityInMonths, "validityInMonths was not specified, so it must not be sent as 0.");
        Assert.IsNull(policy.CertificateTransparency);
        Assert.IsNull(policy.Enabled);
        Assert.AreEqual(0, policy.EnhancedKeyUsage.Count);
        Assert.AreEqual(0, policy.KeyUsage.Count);
    }

    /// <summary>
    /// The two trigger forms are mutually exclusive, and lifetimePercentage must be 1-99. Sending
    /// an unspecified trigger as 0 alongside a specified one is rejected by KeyVault.
    /// </summary>
    [TestMethod]
    public void BuildPolicy_sends_only_the_specified_lifetime_action_trigger()
    {
        var certificate = MinimalCertificate();
        certificate.LifetimeActions =
        [
            new LifetimeAction
            {
                Action = new LifetimeActionAction { ActionType = "AutoRenew" },
                Trigger = new LifetimeActionTrigger { DaysBeforeExpiry = 30 },
            },
        ];

        var policy = CertificateHandler.BuildPolicy(certificate);

        var action = policy.LifetimeActions.Single();
        Assert.AreEqual(CertificatePolicyAction.AutoRenew, action.Action);
        Assert.AreEqual(30, action.DaysBeforeExpiry);
        Assert.IsNull(action.LifetimePercentage, "lifetimePercentage was not specified, so it must not be sent as 0.");
    }

    [TestMethod]
    public void BuildPolicy_maps_fully_specified_policy()
    {
        var certificate = new Certificate
        {
            Name = "my-certificate",
            Issuer = new CertificateIssuerParameters
            {
                Name = "DigiCert",
                CertificateType = "OV-SSL",
                CertificateTransparency = true,
            },
            Key = new CertificateKeyProperties
            {
                Exportable = true,
                KeyType = "RSA",
                KeySize = 4096,
                ReuseKey = true,
            },
            Secret = new CertificateSecretProperties { ContentType = "application/x-pkcs12" },
            X509Properties = new X509Properties
            {
                Subject = "CN=contoso.com",
                ValidityInMonths = 12,
                Ekus = ["1.3.6.1.5.5.7.3.1"],
                KeyUsage = ["digitalSignature", "keyEncipherment"],
                SubjectAlternativeNames = new SubjectAlternativeNames { DnsNames = ["contoso.com"] },
            },
        };

        var policy = CertificateHandler.BuildPolicy(certificate);

        Assert.AreEqual("DigiCert", policy.IssuerName);
        Assert.AreEqual("OV-SSL", policy.CertificateType);
        Assert.IsTrue(policy.CertificateTransparency);
        Assert.IsTrue(policy.Exportable);
        Assert.AreEqual(4096, policy.KeySize);
        Assert.IsTrue(policy.ReuseKey);
        Assert.AreEqual(CertificateContentType.Pkcs12, policy.ContentType);
        Assert.AreEqual(12, policy.ValidityInMonths);
        CollectionAssert.AreEqual(new[] { "1.3.6.1.5.5.7.3.1" }, policy.EnhancedKeyUsage.ToArray());
        CollectionAssert.AreEqual(
            new[] { CertificateKeyUsage.DigitalSignature, CertificateKeyUsage.KeyEncipherment },
            policy.KeyUsage.ToArray());
        CollectionAssert.AreEqual(new[] { "contoso.com" }, policy.SubjectAlternativeNames!.DnsNames.ToArray());
    }

    [TestMethod]
    public void BuildPolicy_supports_subject_alternative_names_without_a_subject()
    {
        var certificate = new Certificate
        {
            Name = "my-certificate",
            X509Properties = new X509Properties
            {
                SubjectAlternativeNames = new SubjectAlternativeNames { DnsNames = ["contoso.com"] },
            },
        };

        var policy = CertificateHandler.BuildPolicy(certificate);

        CollectionAssert.AreEqual(new[] { "contoso.com" }, policy.SubjectAlternativeNames!.DnsNames.ToArray());
    }

    [TestMethod]
    public void BuildPolicy_requires_a_subject_or_subject_alternative_names()
    {
        var certificate = new Certificate { Name = "my-certificate" };

        var exception = Assert.ThrowsExactly<KeyVaultExtensionException>(() => CertificateHandler.BuildPolicy(certificate));
        Assert.AreEqual("MissingProperty", exception.Code);
    }

    [TestMethod]
    public void Validate_rejects_a_trigger_specifying_both_forms()
    {
        var certificate = MinimalCertificate();
        certificate.LifetimeActions =
        [
            new LifetimeAction
            {
                Action = new LifetimeActionAction { ActionType = "AutoRenew" },
                Trigger = new LifetimeActionTrigger { DaysBeforeExpiry = 30, LifetimePercentage = 80 },
            },
        ];

        var exception = Assert.ThrowsExactly<KeyVaultExtensionException>(() => CertificateHandler.Validate(certificate));
        Assert.AreEqual("ConflictingProperties", exception.Code);
    }

    [TestMethod]
    public void Validate_rejects_a_trigger_specifying_neither_form()
    {
        var certificate = MinimalCertificate();
        certificate.LifetimeActions =
        [
            new LifetimeAction
            {
                Action = new LifetimeActionAction { ActionType = "AutoRenew" },
                Trigger = new LifetimeActionTrigger(),
            },
        ];

        var exception = Assert.ThrowsExactly<KeyVaultExtensionException>(() => CertificateHandler.Validate(certificate));
        Assert.AreEqual("MissingProperty", exception.Code);
    }

    [TestMethod]
    public void Validate_rejects_combining_import_with_policy_properties()
    {
        var certificate = MinimalCertificate();
        certificate.Import = new CertificateImport { Contents = "AAAA" };

        var exception = Assert.ThrowsExactly<KeyVaultExtensionException>(() => CertificateHandler.Validate(certificate));
        Assert.AreEqual("ConflictingProperties", exception.Code);
    }

    [TestMethod]
    public void Validate_accepts_a_valid_certificate()
    {
        var certificate = MinimalCertificate();
        certificate.LifetimeActions =
        [
            new LifetimeAction
            {
                Action = new LifetimeActionAction { ActionType = "EmailContacts" },
                Trigger = new LifetimeActionTrigger { LifetimePercentage = 80 },
            },
        ];

        CertificateHandler.Validate(certificate);
    }
}
