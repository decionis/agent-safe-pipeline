using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Decionis.VerifyingProvider;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Xunit;

namespace Decionis.VerifyingProvider.Tests;

/// <summary>The receipt vectors (VP-3): this library signs exactly the bytes every implementation agrees on.</summary>
public class EffectReceiptTests
{
    private static readonly Ed25519PrivateKeyParameters Provider = new(RandomNumberGenerator.GetBytes(32), 0);

    public static string Directory() => Path.Combine(Path.GetDirectoryName(Vector.Directory())!, "receipts");

    public static IEnumerable<object[]> ReceiptFiles()
    {
        foreach (var file in System.IO.Directory.GetFiles(Directory(), "*.json").OrderBy(path => path, StringComparer.Ordinal))
        {
            yield return new object[] { file };
        }
    }

    private static string? Optional(JsonElement element, string name)
    {
        return element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
    }

    private static ClaimAttestation AttestationOf(JsonElement node)
    {
        var binding = node.GetProperty("binding");
        return new ClaimAttestation(
            node.GetProperty("iss").GetString()!,
            node.GetProperty("sub").GetString()!,
            node.GetProperty("decision_id").GetString()!,
            node.GetProperty("dossier_id").GetString()!,
            binding.GetProperty("intent_hash").GetString()!,
            binding.GetProperty("execution_payload_digest").GetString()!,
            binding.GetProperty("execution_payload_canonicalization_profile").GetString()!,
            node.GetProperty("claim_token_digest").GetString()!,
            node.GetProperty("jti").GetString()!,
            node.GetProperty("exp").GetDouble());
    }

    private static EffectReceipt ReceiptOf(JsonElement input)
    {
        var effect = input.GetProperty("effect");
        return new EffectReceipt(
            input.GetProperty("kid").GetString()!,
            input.GetProperty("issuer").GetString()!,
            input.GetProperty("audience").GetString()!,
            AttestationOf(input.GetProperty("attestation")),
            Optional(input, "idempotency_key"),
            new Effect(
                Enum.Parse<EffectStatus>(effect.GetProperty("status").GetString()!, ignoreCase: true),
                Optional(effect, "reference"),
                Optional(effect, "digest"),
                effect.GetProperty("effected_at").GetString()!),
            input.GetProperty("iat").GetInt64(),
            input.GetProperty("jti").GetString()!);
    }

    private static bool Verifies(Ed25519PublicKeyParameters key, string signingInput, byte[] signature)
    {
        var verifier = new Ed25519Signer();
        verifier.Init(false, key);
        var bytes = Encoding.ASCII.GetBytes(signingInput);
        verifier.BlockUpdate(bytes, 0, bytes.Length);
        return verifier.VerifySignature(signature);
    }

    private static byte[] Base64UrlDecode(string text)
    {
        var standard = text.TrimEnd('=').Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(standard.PadRight(standard.Length + (4 - standard.Length % 4) % 4, '='));
    }

    [Fact]
    public void FindsTheReceiptVectors()
    {
        Assert.True(ReceiptFiles().Count() >= 4);
        Assert.Equal("x-agent-safe-effect-receipt", EffectReceipt.Header);
    }

    [Theory]
    [MemberData(nameof(ReceiptFiles))]
    public void EveryReceiptVectorIsSignedOverTheBytesItNames(string file)
    {
        using var document = JsonDocument.Parse(File.ReadAllText(file));
        var vector = document.RootElement;
        var name = vector.GetProperty("vector").GetString();
        Assert.Equal("VP-3", vector.GetProperty("level").GetString());
        var receipt = ReceiptOf(vector.GetProperty("input"));
        var expect = vector.GetProperty("expect");
        Assert.True(JsonNode.DeepEquals(receipt.Claims(), JsonNode.Parse(expect.GetProperty("claims").GetRawText())), name);
        var signingInput = receipt.SigningInput();
        Assert.Equal(expect.GetProperty("signing_input").GetString(), signingInput);
        var token = receipt.Sign(Provider);
        var parts = token.Split('.');
        Assert.Equal(3, parts.Length);
        Assert.Equal(signingInput, parts[0] + "." + parts[1]);
        Assert.True(JsonNode.DeepEquals(
            JsonNode.Parse(Encoding.UTF8.GetString(Base64UrlDecode(parts[0]))),
            JsonNode.Parse(expect.GetProperty("protected_header").GetRawText())), name);
        Assert.True(Verifies(Provider.GeneratePublicKey(), signingInput, Base64UrlDecode(parts[2])), name + ": own signature");
        // The vector's own token verifies under the public half it carries.
        var vectorParts = expect.GetProperty("token").GetString()!.Split('.');
        Assert.Equal(signingInput, vectorParts[0] + "." + vectorParts[1]);
        var x = Base64UrlDecode(expect.GetProperty("provider_jwk").GetProperty("x").GetString()!);
        Assert.True(Verifies(new Ed25519PublicKeyParameters(x, 0), signingInput, Base64UrlDecode(vectorParts[2])), name + ": the vector's signature");
    }

    [Fact]
    public void AReceiptIsNotBuiltFromWhatItCannotStandBehind()
    {
        var attestation = new ClaimAttestation("i", "g", "d", "s", "h", "p", "RFC8785/JCS", "c", "a", 1);
        var good = new EffectReceipt("k", "i", "a", attestation, null,
            new Effect(EffectStatus.Effected, null, null, "2026-09-19T12:00:01Z"), 1_789_819_202L, "r");
        good.Sign(Provider);
        var cases = new (string Code, EffectReceipt Receipt)[]
        {
            ("EFFECT_DIGEST_MALFORMED", good with { Effect = good.Effect with { Digest = "sha256:zz" } }),
            ("EFFECTED_AT_MALFORMED", good with { Effect = good.Effect with { EffectedAt = "yesterday" } }),
            ("ISSUED_AT_MALFORMED", good with { IssuedAt = -1 }),
            ("KID_EMPTY", good with { Kid = "" }),
            ("ISSUER_EMPTY", good with { Issuer = "" }),
            ("AUDIENCE_EMPTY", good with { Audience = "" }),
            ("JTI_EMPTY", good with { Jti = "" }),
        };
        foreach (var (code, receipt) in cases)
        {
            var refused = Assert.Throws<ReceiptException>(() => receipt.Sign(Provider));
            Assert.Equal(code, refused.Code);
        }
    }
}
