using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Decionis.VerifyingProvider;

/// <summary>
/// An independent .NET implementation of the Verifying Provider Profile
/// (docs/authority/verifying-provider.md in the agent-safe-pipeline repository),
/// VP-1 and VP-2, written against the profile's text and held to its vectors.
/// It shares no code with the executor; that is the point of a second
/// implementation.
/// </summary>
public sealed class VerifyingProvider
{
    public const string AttestationType = "decionis-claim-attestation+jwt";
    public const string JcsProfile = "RFC8785/JCS";
    private const string Label = "agentsafe";

    internal static readonly string[] BaseComponents =
    {
        "@method", "@path", "content-digest", "idempotency-key", "x-agent-safe-intent-hash",
    };

    internal static readonly string[] KnownComponents =
    {
        "@method", "@path", "content-digest", "idempotency-key", "x-agent-safe-intent-hash",
        "x-agent-safe-grant-id", "x-agent-safe-decision-id", "x-agent-safe-claim-attestation",
    };

    private readonly ProviderOptions options;

    public VerifyingProvider(ProviderOptions options)
    {
        this.options = options;
    }

    /// <summary>The RFC 9530 value the executor sends for a body, the empty body included.</summary>
    public static string ContentDigest(byte[]? body)
    {
        return "sha-256=:" + Convert.ToBase64String(SHA256.HashData(body ?? Array.Empty<byte>())) + ":";
    }

    /// <summary>The whole procedure for one received request.</summary>
    public Verdict Verify(ProviderRequest request)
    {
        var nowSeconds = options.Now().ToUnixTimeSeconds();
        if (!SignatureHolds(request, nowSeconds))
        {
            return Verdict.Refuse(Verdict.SignatureInvalidOrIncomplete);
        }
        if (!options.Effects)
        {
            return new Verdict(true, null, null);
        }
        ClaimAttestation attestation;
        try
        {
            attestation = AttestationOf(request.Headers.TryGetValue("x-agent-safe-claim-attestation", out var compact) ? compact : null);
        }
        catch (Exception e) when (e is FormatException or JsonException or ArgumentException or InvalidOperationException)
        {
            return Verdict.Refuse(Verdict.AttestationInvalid);
        }
        try
        {
            Described(attestation, request, nowSeconds);
        }
        catch (Exception e) when (e is ArgumentException or CanonicalDigest.NotIJsonException or InvalidOperationException or FormatException)
        {
            return Verdict.Refuse(Verdict.AttestationDoesNotDescribeThisRequest);
        }
        // The record is kept to the end of the second `exp` falls in, never shorter than `exp`.
        var expiresAt = DateTimeOffset.FromUnixTimeSeconds((long)Math.Ceiling(attestation.Exp));
        if (!options.Replay.Record(attestation.Sub, expiresAt))
        {
            return Verdict.Refuse(Verdict.GrantReplayed);
        }
        return new Verdict(true, null, attestation);
    }

    // Steps 0 to 5.
    private bool SignatureHolds(ProviderRequest request, long nowSeconds)
    {
        var headers = request.Headers;
        if (!headers.TryGetValue("signature-input", out var input) || !input.StartsWith(Label + "=", StringComparison.Ordinal))
        {
            return false;
        }
        var parameters = input[(Label.Length + 1)..];
        if (!headers.TryGetValue("signature", out var signatureHeader)
            || !signatureHeader.StartsWith(Label + "=:", StringComparison.Ordinal)
            || !signatureHeader.EndsWith(':'))
        {
            return false;
        }
        var encoded = signatureHeader[(Label.Length + 2)..^1];
        if (!headers.TryGetValue("content-digest", out var digest) || digest != ContentDigest(request.Body))
        {
            return false;
        }
        var covered = CoveredComponents(parameters);
        if (covered is null)
        {
            return false;
        }
        foreach (var component in options.Effects ? KnownComponents : BaseComponents)
        {
            if (!covered.Contains(component))
            {
                return false;
            }
        }
        var createdText = Parameter(parameters, ";created=");
        if (createdText is null || !long.TryParse(createdText, NumberStyles.None, CultureInfo.InvariantCulture, out var created))
        {
            return false;
        }
        var window = (long)options.ClockWindow.TotalSeconds;
        if (created < nowSeconds - window || created > nowSeconds + window)
        {
            return false;
        }
        var keyId = QuotedParameter(parameters, ";keyid=\"");
        var algorithm = QuotedParameter(parameters, ";alg=\"");
        ExecutorKey? key = null;
        foreach (var candidate in options.ExecutorKeys)
        {
            if (candidate.KeyId == keyId && candidate.Algorithm == algorithm)
            {
                key = candidate;
                break;
            }
        }
        if (key is null)
        {
            return false;
        }
        var baseBytes = SignatureBase(request, covered, parameters);
        if (baseBytes is null)
        {
            return false;
        }
        byte[] signature;
        try
        {
            signature = Convert.FromBase64String(encoded);
        }
        catch (FormatException)
        {
            return false;
        }
        switch (key.Algorithm)
        {
            case "ed25519":
                var verifier = new Ed25519Signer();
                verifier.Init(false, key.PublicKey);
                verifier.BlockUpdate(baseBytes, 0, baseBytes.Length);
                return signature.Length == 64 && verifier.VerifySignature(signature);
            case "hmac-sha256":
                var expected = HMACSHA256.HashData(key.Secret!, baseBytes);
                return CryptographicOperations.FixedTimeEquals(expected, signature);
            default:
                return false;
        }
    }

    /// <summary>The covered components a signature-input names, or null when the list is not one, names an unknown one, or one twice.</summary>
    internal static List<string>? CoveredComponents(string parameters)
    {
        if (!parameters.StartsWith('('))
        {
            return null;
        }
        var end = parameters.IndexOf(')', StringComparison.Ordinal);
        if (end < 0)
        {
            return null;
        }
        var inner = parameters[1..end];
        var names = new List<string>();
        if (inner.Length == 0)
        {
            return names;
        }
        foreach (var quoted in inner.Split(' '))
        {
            if (quoted.Length < 3 || quoted[0] != '"' || quoted[^1] != '"')
            {
                return null;
            }
            var name = quoted[1..^1];
            if (Array.IndexOf(KnownComponents, name) < 0 || names.Contains(name))
            {
                return null;
            }
            names.Add(name);
        }
        return names;
    }

    /// <summary>The base, exactly as both sides build it.</summary>
    internal static byte[]? SignatureBase(ProviderRequest request, List<string> covered, string parameters)
    {
        var lines = new List<string>();
        foreach (var component in covered)
        {
            string value;
            switch (component)
            {
                case "@method":
                    value = request.Method.ToUpperInvariant();
                    break;
                case "@path":
                    value = request.Path;
                    break;
                case "content-digest":
                    value = ContentDigest(request.Body);
                    break;
                default:
                    if (!request.Headers.TryGetValue(component, out var header))
                    {
                        return null;
                    }
                    value = header;
                    break;
            }
            lines.Add($"\"{component}\": {value}");
        }
        lines.Add($"\"@signature-params\": {parameters}");
        return Encoding.UTF8.GetBytes(string.Join("\n", lines));
    }

    private static string? Parameter(string parameters, string name)
    {
        var start = parameters.IndexOf(name, StringComparison.Ordinal);
        if (start < 0)
        {
            return null;
        }
        var rest = parameters[(start + name.Length)..];
        var end = rest.IndexOf(';', StringComparison.Ordinal);
        return end < 0 ? rest : rest[..end];
    }

    private static string? QuotedParameter(string parameters, string name)
    {
        var start = parameters.IndexOf(name, StringComparison.Ordinal);
        if (start < 0)
        {
            return null;
        }
        var rest = parameters[(start + name.Length)..];
        var end = rest.IndexOf('"', StringComparison.Ordinal);
        return end < 0 ? null : rest[..end];
    }

    // Step 6: the attestation by form, key, signature, issuer and the shape of
    // its claims; the claims when it is the authority's.
    private ClaimAttestation AttestationOf(string? compact)
    {
        var parts = (compact ?? "").Split('.');
        if (parts.Length != 3)
        {
            throw new ArgumentException("form");
        }
        using var header = JsonDocument.Parse(Base64Url.Decode(parts[0]));
        if (Text(header.RootElement, "alg") != "EdDSA" || Text(header.RootElement, "typ") != AttestationType)
        {
            throw new ArgumentException("header");
        }
        var key = options.AuthorityJwks.Find(Text(header.RootElement, "kid") ?? "") ?? throw new ArgumentException("kid");
        var signed = Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]);
        var verifier = new Ed25519Signer();
        verifier.Init(false, key);
        verifier.BlockUpdate(signed, 0, signed.Length);
        var signature = Base64Url.Decode(parts[2]);
        if (signature.Length != 64 || !verifier.VerifySignature(signature))
        {
            throw new ArgumentException("signature");
        }
        using var document = JsonDocument.Parse(Base64Url.Decode(parts[1]));
        var claims = document.RootElement;
        if (claims.ValueKind != JsonValueKind.Object)
        {
            throw new ArgumentException("claims");
        }
        // The claims a provider compares, and the ones a receipt is built from,
        // must be there in the right type: an attestation without them is not one.
        if (!claims.TryGetProperty("binding", out var binding) || binding.ValueKind != JsonValueKind.Object)
        {
            throw new ArgumentException("binding");
        }
        if (!claims.TryGetProperty("exp", out var exp) || exp.ValueKind != JsonValueKind.Number)
        {
            throw new ArgumentException("exp");
        }
        var attestation = new ClaimAttestation(
            Required(claims, "iss"),
            Required(claims, "sub"),
            Required(claims, "decision_id"),
            Required(claims, "dossier_id"),
            Required(binding, "intent_hash"),
            Required(binding, "execution_payload_digest"),
            Required(binding, "execution_payload_canonicalization_profile"),
            Required(claims, "claim_token_digest"),
            Required(claims, "jti"),
            exp.GetDouble());
        if (attestation.Iss != options.AuthorityIssuer)
        {
            throw new ArgumentException("issuer");
        }
        return attestation;
    }

    // Step 7: whether the attestation describes this request.
    private static void Described(ClaimAttestation attestation, ProviderRequest request, long nowSeconds)
    {
        if (request.Body is null)
        {
            throw new ArgumentException("no body");
        }
        var digest = CanonicalDigest.Of(request.Body);
        var headers = request.Headers;
        if (!(headers.TryGetValue("x-agent-safe-grant-id", out var grant) && grant == attestation.Sub)
            || !(headers.TryGetValue("x-agent-safe-decision-id", out var decision) && decision == attestation.DecisionId)
            || !(headers.TryGetValue("x-agent-safe-intent-hash", out var intent) && intent == attestation.IntentHash)
            || attestation.ExecutionPayloadCanonicalizationProfile != JcsProfile
            || attestation.ExecutionPayloadDigest != digest
            || !(attestation.Exp > nowSeconds))
        {
            throw new ArgumentException("describes another request");
        }
    }

    private static string Required(JsonElement element, string name)
    {
        return Text(element, name) ?? throw new ArgumentException(name);
    }

    private static string? Text(JsonElement element, string name)
    {
        return element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
    }
}
