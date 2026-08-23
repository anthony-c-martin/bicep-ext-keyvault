using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Azure.Security.KeyVault.Keys;

namespace Bicep.Extension.KeyVault.Tests;

[TestClass]
public sealed class PublicKeyEncodingTests
{
    [TestMethod]
    public void Rsa_pem_round_trips_through_the_framework()
    {
        using var rsa = RSA.Create(2048);
        var key = new JsonWebKey(rsa, includePrivateParameters: false);

        var pem = PublicKeyEncoding.ToPem(key);

        Assert.IsNotNull(pem);
        using var imported = RSA.Create();
        imported.ImportFromPem(pem);
        Assert.AreEqual(
            Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo()),
            Convert.ToBase64String(imported.ExportSubjectPublicKeyInfo()));
    }

    [TestMethod]
    public void Rsa_openssh_encodes_the_exponent_and_modulus()
    {
        using var rsa = RSA.Create(2048);
        var parameters = rsa.ExportParameters(includePrivateParameters: false);
        var key = new JsonWebKey(rsa, includePrivateParameters: false);

        var openSsh = PublicKeyEncoding.ToOpenSsh(key);

        Assert.IsNotNull(openSsh);
        var parts = openSsh.Split(' ');
        Assert.AreEqual("ssh-rsa", parts[0]);

        var reader = new SshReader(Convert.FromBase64String(parts[1]));
        Assert.AreEqual("ssh-rsa", Encoding.ASCII.GetString(reader.ReadBytes()));
        CollectionAssert.AreEqual(parameters.Exponent, StripLeadingZeros(reader.ReadBytes()));
        CollectionAssert.AreEqual(parameters.Modulus, StripLeadingZeros(reader.ReadBytes()));
    }

    [TestMethod]
    public void Ec_openssh_encodes_an_uncompressed_point()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var parameters = ecdsa.ExportParameters(includePrivateParameters: false);
        var key = new JsonWebKey(ecdsa, includePrivateParameters: false);

        var openSsh = PublicKeyEncoding.ToOpenSsh(key);

        Assert.IsNotNull(openSsh);
        var parts = openSsh.Split(' ');
        Assert.AreEqual("ecdsa-sha2-nistp256", parts[0]);

        var reader = new SshReader(Convert.FromBase64String(parts[1]));
        Assert.AreEqual("ecdsa-sha2-nistp256", Encoding.ASCII.GetString(reader.ReadBytes()));
        Assert.AreEqual("nistp256", Encoding.ASCII.GetString(reader.ReadBytes()));

        var point = reader.ReadBytes();
        Assert.AreEqual(65, point.Length, "A P-256 uncompressed point is 1 + 32 + 32 bytes.");
        Assert.AreEqual(0x04, point[0]);
        CollectionAssert.AreEqual(parameters.Q.X, point[1..33]);
        CollectionAssert.AreEqual(parameters.Q.Y, point[33..65]);
    }

    [TestMethod]
    public void Ec_pem_round_trips_through_the_framework()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var key = new JsonWebKey(ecdsa, includePrivateParameters: false);

        var pem = PublicKeyEncoding.ToPem(key);

        Assert.IsNotNull(pem);
        using var imported = ECDsa.Create();
        imported.ImportFromPem(pem);
        Assert.AreEqual(
            Convert.ToBase64String(ecdsa.ExportSubjectPublicKeyInfo()),
            Convert.ToBase64String(imported.ExportSubjectPublicKeyInfo()));
    }

    [TestMethod]
    public void Symmetric_keys_have_no_public_representation()
    {
        var key = new JsonWebKey(Aes.Create());

        Assert.IsNull(PublicKeyEncoding.ToPem(key));
        Assert.IsNull(PublicKeyEncoding.ToOpenSsh(key));
    }

    /// <summary>
    /// secp256k1 is not supported by every platform's crypto stack, and OpenSSH has no registered
    /// key type for it. Neither may throw: these are outputs on an already-created key.
    /// </summary>
    [TestMethod]
    public void Unsupported_curves_are_reported_as_absent_rather_than_throwing()
    {
        var key = new JsonWebKey(Array.Empty<KeyOperation>())
        {
            KeyType = KeyType.Ec,
            CurveName = KeyCurveName.P256K,
            X = new byte[32],
            Y = new byte[32],
        };

        Assert.IsNull(PublicKeyEncoding.ToOpenSsh(key));
        Assert.IsNull(PublicKeyEncoding.ToPem(key));
    }

    [TestMethod]
    public void Keys_without_public_material_are_reported_as_absent()
    {
        var key = new JsonWebKey(Array.Empty<KeyOperation>()) { KeyType = KeyType.Rsa };

        Assert.IsNull(PublicKeyEncoding.ToOpenSsh(key));
        Assert.IsNull(PublicKeyEncoding.ToPem(key));
    }

    private static byte[] StripLeadingZeros(byte[] value)
    {
        var offset = 0;
        while (offset < value.Length - 1 && value[offset] == 0)
        {
            offset++;
        }

        return value[offset..];
    }

    private sealed class SshReader(byte[] data)
    {
        private int offset;

        public byte[] ReadBytes()
        {
            var length = (int)BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(offset, 4));
            offset += 4;
            var value = data[offset..(offset + length)];
            offset += length;

            return value;
        }
    }
}
