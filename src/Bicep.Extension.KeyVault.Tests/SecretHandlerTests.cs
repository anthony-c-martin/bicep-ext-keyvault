using Bicep.Extension.KeyVault.Handlers;

namespace Bicep.Extension.KeyVault.Tests;

[TestClass]
public sealed class SecretHandlerTests
{
    [TestMethod]
    public async Task Preview_uses_camel_case_properties()
    {
        var handler = new SecretHandler();

        var response = await HandlerHarness.PreviewAsync(handler, "Secret", new
        {
            name = "my-secret",
            value = "super-secret-value",
        });

        var properties = response.ResourceProperties();
        Assert.AreEqual("my-secret", properties.GetProperty("name").GetString());
        Assert.AreEqual("super-secret-value", properties.GetProperty("value").GetString());
        Assert.IsFalse(properties.TryGetProperty("Name", out _));
    }
}
