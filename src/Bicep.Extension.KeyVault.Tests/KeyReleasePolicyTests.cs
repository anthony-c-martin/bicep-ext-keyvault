using Azure.Security.KeyVault.Keys;
using Bicep.Extension.KeyVault.Handlers;
using SdkKeyReleasePolicy = Azure.Security.KeyVault.Keys.KeyReleasePolicy;

namespace Bicep.Extension.KeyVault.Tests;

[TestClass]
public sealed class KeyReleasePolicyTests
{
    private static SdkKeyReleasePolicy Actual(string json, bool? immutable = null)
        => new(BinaryData.FromString(json)) { Immutable = immutable };

    [TestMethod]
    public void An_unspecified_policy_is_not_managed()
    {
        Assert.IsTrue(KeyOperations.ReleasePolicyMatches(null, null));
        Assert.IsTrue(KeyOperations.ReleasePolicyMatches(Actual("""{"version":"1.0.0"}"""), null));
    }

    [TestMethod]
    public void A_policy_is_compared_structurally_rather_than_textually()
    {
        // KeyVault reformats the JSON it is given, so whitespace and key ordering must not count
        // as drift.
        var actual = Actual("""{"version":"1.0.0","anyOf":[{"authority":"https://contoso.com"}]}""");
        var desired = new KeyReleasePolicy
        {
            Json = """
            {
              "anyOf": [ { "authority": "https://contoso.com" } ],
              "version": "1.0.0"
            }
            """,
        };

        Assert.IsTrue(KeyOperations.ReleasePolicyMatches(actual, desired));
    }

    [TestMethod]
    public void A_changed_policy_is_detected()
    {
        var actual = Actual("""{"version":"1.0.0"}""");
        var desired = new KeyReleasePolicy { Json = """{"version":"1.0.1"}""" };

        Assert.IsFalse(KeyOperations.ReleasePolicyMatches(actual, desired));
    }

    [TestMethod]
    public void A_changed_immutable_flag_is_detected()
    {
        var actual = Actual("""{"version":"1.0.0"}""", immutable: false);
        var desired = new KeyReleasePolicy { Json = """{"version":"1.0.0"}""", Immutable = true };

        Assert.IsFalse(KeyOperations.ReleasePolicyMatches(actual, desired));
    }

    [TestMethod]
    public void Adding_a_policy_to_a_key_without_one_is_detected()
    {
        var desired = new KeyReleasePolicy { Json = """{"version":"1.0.0"}""" };

        Assert.IsFalse(KeyOperations.ReleasePolicyMatches(null, desired));
    }

    [TestMethod]
    public void Malformed_policy_json_is_reported()
    {
        var actual = Actual("""{"version":"1.0.0"}""");
        var desired = new KeyReleasePolicy { Json = "not json" };

        var exception = Assert.ThrowsExactly<KeyVaultExtensionException>(() => KeyOperations.ReleasePolicyMatches(actual, desired));

        Assert.AreEqual("InvalidReleasePolicy", exception.Code);
    }
}
