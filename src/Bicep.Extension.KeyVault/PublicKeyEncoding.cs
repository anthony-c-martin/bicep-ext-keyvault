using System.Buffers.Binary;
using System.Security.Cryptography;
using Azure.Security.KeyVault.Keys;

namespace Bicep.Extension.KeyVault;

/// <summary>
/// Renders the public half of a KeyVault key in the formats consumers usually need: PEM
/// (SubjectPublicKeyInfo) and the OpenSSH authorized_keys encoding.
/// </summary>
public static class PublicKeyEncoding
{
    public static string? ToPem(JsonWebKey key)
    {
        try
        {
            if (IsRsa(key))
            {
                using var rsa = key.ToRSA();
                return rsa.ExportSubjectPublicKeyInfoPem();
            }

            if (IsEc(key))
            {
                using var ecdsa = key.ToECDsa();
                return ecdsa.ExportSubjectPublicKeyInfoPem();
            }
        }
        catch (Exception exception) when (
            exception is CryptographicException ||
            // secp256k1 (P-256K) is not supported by every platform's crypto stack.
            exception is NotSupportedException ||
            // Thrown when the vault withheld the public key material.
            exception is InvalidOperationException)
        {
            // Reporting no PEM is more useful than failing a deployment over an output.
        }

        return null;
    }

    public static string? ToOpenSsh(JsonWebKey key)
    {
        if (IsRsa(key))
        {
            if (key.E is not { Length: > 0 } exponent || key.N is not { Length: > 0 } modulus)
            {
                return null;
            }

            var blob = BuildBlob(writer =>
            {
                writer.WriteString("ssh-rsa"u8);
                writer.WriteMpint(exponent);
                writer.WriteMpint(modulus);
            });

            return $"ssh-rsa {Convert.ToBase64String(blob)}";
        }

        if (IsEc(key))
        {
            if (key.X is not { Length: > 0 } x || key.Y is not { Length: > 0 } y)
            {
                return null;
            }

            // secp256k1 has no registered OpenSSH key type, so it is deliberately unsupported.
            var (curveName, coordinateLength) = key.CurveName switch
            {
                var c when c == KeyCurveName.P256 => ("nistp256", 32),
                var c when c == KeyCurveName.P384 => ("nistp384", 48),
                var c when c == KeyCurveName.P521 => ("nistp521", 66),
                _ => (null, 0),
            };

            if (curveName is null)
            {
                return null;
            }

            // The uncompressed EC point is a fixed width per curve, so the coordinates must be
            // left-padded rather than used as-is.
            var point = new byte[1 + (coordinateLength * 2)];
            point[0] = 0x04;
            if (!TryCopyRightAligned(x, point.AsSpan(1, coordinateLength)) ||
                !TryCopyRightAligned(y, point.AsSpan(1 + coordinateLength, coordinateLength)))
            {
                return null;
            }

            var keyType = $"ecdsa-sha2-{curveName}";
            var blob = BuildBlob(writer =>
            {
                writer.WriteString(keyType);
                writer.WriteString(curveName);
                writer.WriteBytes(point);
            });

            return $"{keyType} {Convert.ToBase64String(blob)}";
        }

        return null;
    }

    private static bool IsRsa(JsonWebKey key)
        => key.KeyType == KeyType.Rsa || key.KeyType == KeyType.RsaHsm;

    private static bool IsEc(JsonWebKey key)
        => key.KeyType == KeyType.Ec || key.KeyType == KeyType.EcHsm;

    private static bool TryCopyRightAligned(byte[] source, Span<byte> destination)
    {
        // Trim any leading zero padding the vault may have included before checking for overflow.
        var offset = 0;
        while (offset < source.Length - 1 && source[offset] == 0)
        {
            offset++;
        }

        var significant = source.Length - offset;
        if (significant > destination.Length)
        {
            return false;
        }

        destination.Clear();
        source.AsSpan(offset).CopyTo(destination[(destination.Length - significant)..]);
        return true;
    }

    private static byte[] BuildBlob(Action<SshWriter> write)
    {
        var stream = new MemoryStream();
        write(new SshWriter(stream));
        return stream.ToArray();
    }

    /// <summary>
    /// Writes the length-prefixed primitives defined by RFC 4251 §5.
    /// </summary>
    private sealed class SshWriter(Stream stream)
    {
        public void WriteString(string value) => WriteBytes(System.Text.Encoding.ASCII.GetBytes(value));

        public void WriteString(ReadOnlySpan<byte> value) => WriteBytes(value);

        public void WriteBytes(ReadOnlySpan<byte> value)
        {
            Span<byte> length = stackalloc byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(length, (uint)value.Length);
            stream.Write(length);
            stream.Write(value);
        }

        /// <summary>
        /// Writes a multiple-precision integer: minimal big-endian two's complement, which means a
        /// leading zero byte whenever the high bit would otherwise imply a negative number.
        /// </summary>
        public void WriteMpint(byte[] value)
        {
            var offset = 0;
            while (offset < value.Length && value[offset] == 0)
            {
                offset++;
            }

            if (offset == value.Length)
            {
                WriteBytes([]);
                return;
            }

            var significant = value.AsSpan(offset);
            if ((significant[0] & 0x80) != 0)
            {
                Span<byte> padded = new byte[significant.Length + 1];
                significant.CopyTo(padded[1..]);
                WriteBytes(padded);
                return;
            }

            WriteBytes(significant);
        }
    }
}
