using System.Buffers.Text;
using System.Globalization;

namespace Bicep.Extension.KeyVault;

/// <summary>
/// Conversions between the string-based shapes Bicep understands and the CLR types used by the
/// KeyVault SDK.
/// </summary>
public static class Conversions
{
    private const string Iso8601Format = "yyyy-MM-dd'T'HH:mm:ss'Z'";

    /// <summary>
    /// Parses an ISO 8601 / RFC 3339 date-time. Returns <see langword="null"/> when the value was
    /// not supplied, so that unset properties are never sent to KeyVault.
    /// </summary>
    public static DateTimeOffset? ToDateTimeOffset(string? value, string propertyName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        if (!DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var parsed))
        {
            throw new KeyVaultExtensionException(
                "InvalidDateTime",
                $"The value '{value}' supplied for '{propertyName}' is not a valid ISO 8601 date/time. Expected a value such as '2026-01-01T00:00:00Z'.",
                propertyName);
        }

        return parsed;
    }

    public static string? ToIso8601(DateTimeOffset? value)
        => value?.ToUniversalTime().ToString(Iso8601Format, CultureInfo.InvariantCulture);

    /// <summary>
    /// Copies tags out of the SDK, collapsing an empty collection to <see langword="null"/> so that
    /// resources without tags don't report an empty object.
    /// </summary>
    public static Dictionary<string, string>? ToTags(IDictionary<string, string>? tags)
        => tags is { Count: > 0 } ? new Dictionary<string, string>(tags, StringComparer.Ordinal) : null;

    public static string[]? ToArray(IEnumerable<string>? values)
    {
        var array = values?.ToArray();
        return array is { Length: > 0 } ? array : null;
    }

    public static string ToHexLower(byte[] data) => Convert.ToHexStringLower(data);

    public static string ToHexUpper(byte[] data) => Convert.ToHexString(data);

    /// <summary>
    /// Encodes bytes as base64url (RFC 4648 §5), which is how JSON web key components are
    /// represented.
    /// </summary>
    public static string? ToBase64Url(byte[]? data)
        => data is null ? null : Base64Url.EncodeToString(data);

    /// <summary>
    /// Builds the version-less form of a data plane identifier, i.e. one that always resolves to
    /// the current version of the object.
    /// </summary>
    public static string ToVersionlessId(Uri endpoint, string collection, string name)
        => new Uri(endpoint, $"{collection}/{Uri.EscapeDataString(name)}").AbsoluteUri;

    /// <summary>
    /// Compares two sets of tags, treating a null or empty collection on either side as equivalent.
    /// </summary>
    public static bool TagsMatch(IDictionary<string, string>? actual, IReadOnlyDictionary<string, string>? desired)
    {
        if (desired is null)
        {
            return true;
        }

        var actualCount = actual?.Count ?? 0;
        if (actualCount != desired.Count)
        {
            return false;
        }

        foreach (var (key, value) in desired)
        {
            if (actual is null ||
                !actual.TryGetValue(key, out var actualValue) ||
                !string.Equals(actualValue, value, StringComparison.Ordinal))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Compares a desired sequence against the actual one. A null desired sequence means "not
    /// managed", and so always matches.
    /// </summary>
    public static bool SequenceMatches(IEnumerable<string>? actual, string[]? desired)
    {
        if (desired is null)
        {
            return true;
        }

        var actualSet = actual?.ToArray() ?? [];
        return actualSet.Length == desired.Length &&
            actualSet.OrderBy(x => x, StringComparer.Ordinal).SequenceEqual(desired.OrderBy(x => x, StringComparer.Ordinal), StringComparer.Ordinal);
    }

    /// <summary>
    /// Compares a desired value against the actual one. A null desired value means "not managed",
    /// and so always matches.
    /// </summary>
    public static bool ValueMatches<T>(T? actual, T? desired) where T : struct
        => desired is null || Nullable.Equals(actual, desired);

    public static bool ValueMatches(string? actual, string? desired)
        => desired is null || string.Equals(actual, desired, StringComparison.Ordinal);

    /// <summary>
    /// Compares an actual date-time against a desired ISO 8601 string.
    /// </summary>
    public static bool DateMatches(DateTimeOffset? actual, string? desired, string propertyName)
    {
        var parsed = ToDateTimeOffset(desired, propertyName);
        return parsed is null || (actual is not null && actual.Value.ToUniversalTime() == parsed.Value.ToUniversalTime());
    }
}
