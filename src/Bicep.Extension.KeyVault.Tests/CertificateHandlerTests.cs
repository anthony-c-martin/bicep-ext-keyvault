using Bicep.Extension.KeyVault.Handlers;

namespace Bicep.Extension.KeyVault.Tests;

[TestClass]
public sealed class CertificateHandlerTests
{
    [TestMethod]
    public async Task Preview_uses_camel_case_properties()
    {
        var handler = new CertificateHandler();

        var response = await HandlerHarness.PreviewAsync(handler, "Certificate", new
        {
            name = "my-certificate",
            x509Properties = new
            {
                subject = "CN=example.com",
                dnsNames = new[] { "example.com", "www.example.com" },
            },
            attributes = new
            {
                enabled = true,
            },
        });

        var properties = response.ResourceProperties();
        Assert.AreEqual("my-certificate", properties.GetProperty("name").GetString());
        Assert.AreEqual("CN=example.com", properties.GetProperty("x509Properties").GetProperty("subject").GetString());
        Assert.IsTrue(properties.GetProperty("attributes").GetProperty("enabled").GetBoolean());
        Assert.IsFalse(properties.TryGetProperty("Name", out _));
    }
}
