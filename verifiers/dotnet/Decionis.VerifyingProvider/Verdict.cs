namespace Decionis.VerifyingProvider;

/// <summary>
/// The part of the attestation the provider reads; the authority's schema has
/// more. The dossier, the claim-token digest and the attestation's own id are
/// what a receipt (<see cref="EffectReceipt"/>, VP-3) is built from.
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
    double Exp);

/// <summary>
/// The outcome of the procedure for one request. <see cref="Attestation"/> is
/// set on an accepted dispatch, and null for a read a non-effecting provider
/// verified at VP-1 alone; a refusal carries the code the response body names.
/// </summary>
public sealed record Verdict(bool Accepted, string? ReasonCode, ClaimAttestation? Attestation)
{
    public const string SignatureInvalidOrIncomplete = "SIGNATURE_INVALID_OR_INCOMPLETE";
    public const string AttestationInvalid = "ATTESTATION_INVALID";
    public const string AttestationDoesNotDescribeThisRequest = "ATTESTATION_DOES_NOT_DESCRIBE_THIS_REQUEST";
    public const string GrantReplayed = "GRANT_REPLAYED";

    internal static Verdict Refuse(string reasonCode) => new(false, reasonCode, null);

    /// <summary>The refusal body the profile names; the status is the provider's, 409 in the references.</summary>
    public string RefusalBody() => $"{{\"status\":\"REJECTED\",\"reason_code\":\"{ReasonCode}\"}}";
}
