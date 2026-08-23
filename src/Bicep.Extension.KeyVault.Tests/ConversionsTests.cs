namespace Bicep.Extension.KeyVault.Tests;

[TestClass]
public sealed class ConversionsTests
{
    [TestMethod]
    public void ToDateTimeOffset_returns_null_for_an_absent_value()
    {
        Assert.IsNull(Conversions.ToDateTimeOffset(null, "notBefore"));
        Assert.IsNull(Conversions.ToDateTimeOffset("  ", "notBefore"));
    }

    [TestMethod]
    public void ToDateTimeOffset_parses_an_iso8601_value()
    {
        var parsed = Conversions.ToDateTimeOffset("2026-01-02T03:04:05Z", "expiresOn");

        Assert.AreEqual(new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.Zero), parsed);
    }

    [TestMethod]
    public void ToDateTimeOffset_reports_a_malformed_value()
    {
        var exception = Assert.ThrowsExactly<KeyVaultExtensionException>(() => Conversions.ToDateTimeOffset("not-a-date", "expiresOn"));

        Assert.AreEqual("InvalidDateTime", exception.Code);
        Assert.AreEqual("expiresOn", exception.Target);
    }

    [TestMethod]
    public void ToIso8601_normalises_to_utc()
    {
        var value = new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.FromHours(2));

        Assert.AreEqual("2026-01-02T01:04:05Z", Conversions.ToIso8601(value));
    }

    [TestMethod]
    public void ToVersionlessId_appends_the_collection_and_name()
    {
        var id = Conversions.ToVersionlessId(new Uri("https://my-vault.vault.azure.net/"), "secrets", "my-secret");

        Assert.AreEqual("https://my-vault.vault.azure.net/secrets/my-secret", id);
    }

    [TestMethod]
    public void ToTags_collapses_an_empty_collection()
    {
        Assert.IsNull(Conversions.ToTags(null));
        Assert.IsNull(Conversions.ToTags(new Dictionary<string, string>()));
        Assert.AreEqual(1, Conversions.ToTags(new Dictionary<string, string> { ["a"] = "b" })!.Count);
    }

    [TestMethod]
    public void An_unspecified_desired_value_always_matches()
    {
        // Absent properties mean "not managed", so they must never be reported as drift.
        Assert.IsTrue(Conversions.ValueMatches((int?)2048, null));
        Assert.IsTrue(Conversions.ValueMatches("text/plain", null));
        Assert.IsTrue(Conversions.TagsMatch(new Dictionary<string, string> { ["a"] = "b" }, null));
        Assert.IsTrue(Conversions.SequenceMatches(["a"], null));
    }

    [TestMethod]
    public void A_specified_desired_value_is_compared()
    {
        Assert.IsFalse(Conversions.ValueMatches((int?)2048, 4096));
        Assert.IsTrue(Conversions.ValueMatches((int?)2048, 2048));
        Assert.IsFalse(Conversions.ValueMatches((int?)null, 4096));
    }

    [TestMethod]
    public void TagsMatch_requires_an_exact_set()
    {
        var actual = new Dictionary<string, string> { ["a"] = "1", ["b"] = "2" };

        Assert.IsTrue(Conversions.TagsMatch(actual, new Dictionary<string, string> { ["a"] = "1", ["b"] = "2" }));
        Assert.IsFalse(Conversions.TagsMatch(actual, new Dictionary<string, string> { ["a"] = "1" }));
        Assert.IsFalse(Conversions.TagsMatch(actual, new Dictionary<string, string> { ["a"] = "1", ["b"] = "3" }));
        Assert.IsFalse(Conversions.TagsMatch(null, new Dictionary<string, string> { ["a"] = "1" }));
        Assert.IsTrue(Conversions.TagsMatch(null, new Dictionary<string, string>()));
    }

    [TestMethod]
    public void SequenceMatches_ignores_ordering()
    {
        Assert.IsTrue(Conversions.SequenceMatches(["b", "a"], ["a", "b"]));
        Assert.IsFalse(Conversions.SequenceMatches(["a"], ["a", "b"]));
        Assert.IsTrue(Conversions.SequenceMatches(null, []));
    }

    [TestMethod]
    public void DateMatches_compares_instants_rather_than_representations()
    {
        var actual = new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.Zero);

        Assert.IsTrue(Conversions.DateMatches(actual, "2026-01-02T05:04:05+02:00", "expiresOn"));
        Assert.IsFalse(Conversions.DateMatches(actual, "2026-01-03T03:04:05Z", "expiresOn"));
        Assert.IsTrue(Conversions.DateMatches(actual, null, "expiresOn"));
        Assert.IsFalse(Conversions.DateMatches(null, "2026-01-02T03:04:05Z", "expiresOn"));
    }
}
