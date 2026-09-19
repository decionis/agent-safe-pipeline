using System;
using System.Collections.Generic;
using System.Text.Json;
using Org.BouncyCastle.Crypto.Parameters;

namespace Decionis.VerifyingProvider;

/// <summary>The authority's execution-grant key set, as served: OKP Ed25519 keys by kid.</summary>
public sealed class Jwks
{
    private readonly IReadOnlyList<(string Kid, Ed25519PublicKeyParameters Key)> keys;

    private Jwks(IReadOnlyList<(string, Ed25519PublicKeyParameters)> keys)
    {
        this.keys = keys;
    }

    /// <summary>Parses the JWKS document; entries that are not OKP Ed25519 keys are left out.</summary>
    public static Jwks Parse(string json)
    {
        using var document = JsonDocument.Parse(json);
        var keys = new List<(string, Ed25519PublicKeyParameters)>();
        if (document.RootElement.TryGetProperty("keys", out var entries) && entries.ValueKind == JsonValueKind.Array)
        {
            foreach (var entry in entries.EnumerateArray())
            {
                if (Text(entry, "kty") != "OKP" || Text(entry, "crv") != "Ed25519")
                {
                    continue;
                }
                var kid = Text(entry, "kid");
                var x = Text(entry, "x");
                if (kid is null || x is null)
                {
                    continue;
                }
                byte[] bytes;
                try
                {
                    bytes = Base64Url.Decode(x);
                }
                catch (FormatException)
                {
                    continue;
                }
                if (bytes.Length != 32)
                {
                    continue;
                }
                keys.Add((kid, new Ed25519PublicKeyParameters(bytes, 0)));
            }
        }
        return new Jwks(keys);
    }

    internal Ed25519PublicKeyParameters? Find(string kid)
    {
        foreach (var (candidate, key) in keys)
        {
            if (candidate == kid)
            {
                return key;
            }
        }
        return null;
    }

    private static string? Text(JsonElement element, string name)
    {
        return element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
    }
}

/// <summary>Base64url without padding, as JWS parts and JWK values are written.</summary>
internal static class Base64Url
{
    public static byte[] Decode(string text)
    {
        var standard = text.TrimEnd('=').Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(standard.PadRight(standard.Length + (4 - standard.Length % 4) % 4, '='));
    }
}
