namespace Decionis.VerifyingProvider;

/// <summary>
/// The part of the attestation the provider reads; the authority's schema has
/// more. The dossier, the claim-token digest and the attestation's own id are
/// what a receipt (<see cref="EffectReceipt"/>, VP-3) is built from.
/// <see cref="ExpectedStateVersion"/> is the target's version the grant was
/// decided against, when the attestation names one: the precondition of the
/// write, compared as a strong <c>If-Match</c> is.
/// </summary>
public sealed record ClaimAttestation(
    string Iss,
    string Sub,
    string DecisionId,
    string DossierId,
    string IntentHash,
    string ExecutionPayloadDigest,
    string ExecutionPayloadCanonicalizationProfile,
    string ClaimTokenDigest,
    string Jti,
    double Exp,
    string? ExpectedStateVersion = null);

/// <summary>
/// The outcome of the procedure for one request. <see cref="Attestation"/> is
/// set on an accepted dispatch, and null for a read a non-effecting provider
/// verified at VP-1 alone; a refusal carries the code the response body names.
/// The one refusal that carries the attestation too is
/// <see cref="TargetStateChanged"/>: the provider's own refusal of a genuine,
/// now spent, attestation, which a provider at VP-3 signs as a receipt built
/// from those claims.
/// </summary>
public sealed record Verdict(bool Accepted, string? ReasonCode, ClaimAttestation? Attestation)
{
    public const string SignatureInvalidOrIncomplete = "SIGNATURE_INVALID_OR_INCOMPLETE";
    public const string AttestationInvalid = "ATTESTATION_INVALID";
    public const string AttestationDoesNotDescribeThisRequest = "ATTESTATION_DOES_NOT_DESCRIBE_THIS_REQUEST";
    public const string GrantReplayed = "GRANT_REPLAYED";
    public const string TargetStateChanged = "TARGET_STATE_CHANGED";

    internal static Verdict Refuse(string reasonCode) => new(false, reasonCode, null);

    /// <summary>The refusal body the profile names; the status is the provider's, 409 in the references.</summary>
    public string RefusalBody() => $"{{\"status\":\"REJECTED\",\"reason_code\":\"{ReasonCode}\"}}";
}
