using System;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Decionis.VerifyingProvider;

/// <summary>
/// A key the provider issued to, or registered for, the executor, by the keyid a
/// signature names. Exactly one of <see cref="PublicKey"/> (for ed25519) and
/// <see cref="Secret"/> (for hmac-sha256) is set.
/// </summary>
public sealed class ExecutorKey
{
    private ExecutorKey(string keyId, string algorithm, Ed25519PublicKeyParameters? publicKey, byte[]? secret)
    {
        KeyId = keyId;
        Algorithm = algorithm;
        PublicKey = publicKey;
        Secret = secret;
    }

    public string KeyId { get; }

    /// <summary>ed25519 or hmac-sha256.</summary>
    public string Algorithm { get; }

    public Ed25519PublicKeyParameters? PublicKey { get; }

    public byte[]? Secret { get; }

    /// <summary>An Ed25519 key from its SPKI PEM, as the vectors and a key file carry it.</summary>
    public static ExecutorKey Ed25519(string keyId, string publicKeyPem)
    {
        var base64 = publicKeyPem
            .Replace("-----BEGIN PUBLIC KEY-----", "", StringComparison.Ordinal)
            .Replace("-----END PUBLIC KEY-----", "", StringComparison.Ordinal)
            .Replace("\r", "", StringComparison.Ordinal)
            .Replace("\n", "", StringComparison.Ordinal)
            .Trim();
        var key = PublicKeyFactory.CreateKey(Convert.FromBase64String(base64)) as Ed25519PublicKeyParameters
            ?? throw new ArgumentException($"{keyId}: not an Ed25519 public key", nameof(publicKeyPem));
        return new ExecutorKey(keyId, "ed25519", key, null);
    }

    /// <summary>A shared HMAC secret, as UTF-8 text.</summary>
    public static ExecutorKey Hmac(string keyId, string sharedMaterialUtf8)
    {
        return new ExecutorKey(keyId, "hmac-sha256", null, Encoding.UTF8.GetBytes(sharedMaterialUtf8));
    }
}
