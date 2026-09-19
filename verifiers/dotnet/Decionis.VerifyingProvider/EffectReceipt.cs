using System;
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Decionis.VerifyingProvider;

/// <summary>What the provider did with the claimed request. A signed refusal is evidence too.</summary>
public enum EffectStatus
{
    Effected,
    Refused,
    Indeterminate,
}

/// <summary>
/// The effect the receipt reports.
/// </summary>
/// <param name="Status">What the provider did.</param>
/// <param name="Reference">The provider's own reference for the effect: a ledger entry, an order id.</param>
/// <param name="Digest">The digest of the effect in the grant's terms (<c>expected_effect_digest</c>); equality is what confirms the effect at the authority.</param>
/// <param name="EffectedAt">When the effect took place, RFC 3339.</param>
public sealed record Effect(EffectStatus Status, string? Reference, string? Digest, string EffectedAt);

/// <summary>Why a receipt could not be built; a provider never signs one it could not stand behind.</summary>
public sealed class ReceiptException : ArgumentException
{
    public ReceiptException(string code) : base(code)
    {
        Code = code;
    }

    public string Code { get; }
}

/// <summary>
/// The effect receipt: the provider's half of the evidence (the Verifying
/// Provider Profile, VP-3).
/// <para>
/// The attestation let this provider refuse what the authority never claimed.
/// The receipt closes the other direction: after effecting, or refusing, the
/// claimed request, the provider signs a compact JWS under its own key naming
/// the grant it acted under, the claim it answered and what it did, and
/// returns it in <see cref="Header"/>. The executor forwards it unread at
/// finalization; the authority verifies it against the public key the
/// organisation registered for this provider and records it with the commit
/// evidence.
/// </para>
/// <para>
/// Every field the receipt binds comes from the attestation the provider has
/// already verified: <c>sub</c> is the grant, <c>decision_id</c> and
/// <c>dossier_id</c> are the decision's, and <c>claim_token_digest</c> is
/// copied from the attestation of this very claim. The header and the payload
/// are serialised in RFC 8785 canonical form, so every implementation of the
/// profile signs the same bytes for the same receipt, and the conformance
/// vectors say so.
/// </para>
/// </summary>
/// <param name="Kid">The <c>kid</c> the organisation registered the key under at the authority.</param>
/// <param name="Issuer">The <c>iss</c> registered with the key.</param>
/// <param name="Audience">The authority the receipt is for: its issuer, <c>https://decionis.com</c> for the hosted one.</param>
/// <param name="Attestation">The claims of the attestation this provider verified, as <see cref="VerifyingProvider.Verify"/> returned them.</param>
/// <param name="IdempotencyKey">The idempotency key of the request effected, when the provider records it.</param>
/// <param name="Effect">What the provider did.</param>
/// <param name="IssuedAt"><c>iat</c>, as an epoch second.</param>
/// <param name="Jti">Unique per receipt.</param>
public sealed record EffectReceipt(
    string Kid,
    string Issuer,
    string Audience,
    ClaimAttestation Attestation,
    string? IdempotencyKey,
    Effect Effect,
    long IssuedAt,
    string Jti)
{
    /// <summary>The protected header <c>typ</c> of an effect receipt.</summary>
    public const string Type = "decionis-effect-receipt+jwt";

    /// <summary>The response header the receipt travels in.</summary>
    public const string Header = "x-agent-safe-effect-receipt";

    private static readonly Regex Sha256 = new("^sha256:[0-9a-f]{64}$", RegexOptions.CultureInvariant);
    private static readonly Regex Rfc3339 = new(@"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$", RegexOptions.CultureInvariant);

    /// <summary>The payload of the receipt, before it is signed; what the authority reads.</summary>
    public JsonObject Claims()
    {
        if (Effect.Digest is not null && !Sha256.IsMatch(Effect.Digest))
        {
            throw new ReceiptException("EFFECT_DIGEST_MALFORMED");
        }
        if (!Rfc3339.IsMatch(Effect.EffectedAt)
            || !DateTimeOffset.TryParse(Effect.EffectedAt, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out _))
        {
            throw new ReceiptException("EFFECTED_AT_MALFORMED");
        }
        if (IssuedAt < 0)
        {
            throw new ReceiptException("ISSUED_AT_MALFORMED");
        }
        if (Attestation is null)
        {
            throw new ReceiptException("ATTESTATION_MISSING");
        }
        Require(Kid, "KID_EMPTY");
        Require(Issuer, "ISSUER_EMPTY");
        Require(Audience, "AUDIENCE_EMPTY");
        Require(Jti, "JTI_EMPTY");
        var effect = new JsonObject { ["status"] = Effect.Status.ToString().ToUpperInvariant() };
        if (Effect.Reference is not null)
        {
            effect["reference"] = Effect.Reference;
        }
        if (Effect.Digest is not null)
        {
            effect["digest"] = Effect.Digest;
        }
        effect["effected_at"] = Effect.EffectedAt;
        var claims = new JsonObject
        {
            ["iss"] = Issuer,
            ["aud"] = Audience,
            ["sub"] = Attestation.Sub,
            ["decision_id"] = Attestation.DecisionId,
            ["dossier_id"] = Attestation.DossierId,
            ["claim_token_digest"] = Attestation.ClaimTokenDigest,
            ["attestation_jti"] = Attestation.Jti,
            ["intent_hash"] = Attestation.IntentHash,
        };
        if (IdempotencyKey is not null)
        {
            claims["idempotency_key"] = IdempotencyKey;
        }
        claims["effect"] = effect;
        claims["iat"] = IssuedAt;
        claims["jti"] = Jti;
        return claims;
    }

    /// <summary>The <c>header.payload</c> the signature covers: both segments RFC 8785 canonical, base64url.</summary>
    public string SigningInput()
    {
        var header = new JsonObject { ["alg"] = "EdDSA", ["kid"] = Kid, ["typ"] = Type };
        return Segment(header) + "." + Segment(Claims());
    }

    /// <summary>The receipt: a compact EdDSA JWS the provider returns in <see cref="Header"/>.</summary>
    /// <param name="key">The provider's Ed25519 private key, which never leaves the provider.</param>
    public string Sign(Ed25519PrivateKeyParameters key)
    {
        var signingInput = SigningInput();
        var signer = new Ed25519Signer();
        signer.Init(true, key);
        var bytes = Encoding.ASCII.GetBytes(signingInput);
        signer.BlockUpdate(bytes, 0, bytes.Length);
        return signingInput + "." + Base64Url.Encode(signer.GenerateSignature());
    }

    private static string Segment(JsonObject value)
    {
        using var document = JsonDocument.Parse(value.ToJsonString());
        var canonical = CanonicalDigest.CanonicalJson(document.RootElement);
        return Base64Url.Encode(Encoding.UTF8.GetBytes(canonical));
    }

    private static void Require(string value, string code)
    {
        if (string.IsNullOrEmpty(value))
        {
            throw new ReceiptException(code);
        }
    }
}
