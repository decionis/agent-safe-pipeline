//! The effect receipt (the profile, VP-3): the provider's half of the
//! evidence. After effecting, or refusing, a claimed request, the provider
//! signs a compact JWS under its own key naming the grant it acted under, the
//! claim it answered and what it did, and returns it in
//! `x-agent-safe-effect-receipt`. The executor forwards it unread; the
//! authority verifies it against the public key the organisation registered
//! for this provider and records it with the commit evidence.
//!
//! Every field the receipt binds comes from the attestation the provider has
//! already verified: `sub` is the grant, `decision_id` and `dossier_id` are
//! the decision's, and `claim_token_digest` is copied from the attestation of
//! this very claim. The header and the payload are serialised in RFC 8785
//! canonical form, so every implementation of the profile signs the same
//! bytes for the same receipt, and the conformance vectors say so.

use crate::canonical::canonical_json;
use crate::ClaimAttestation;
use base64::Engine;
use ed25519_compact::SecretKey;
use serde_json::{json, Map, Value};

/// The protected header `typ` of an effect receipt.
pub const RECEIPT_TYPE: &str = "decionis-effect-receipt+jwt";
/// The response header the receipt travels in.
pub const RECEIPT_HEADER: &str = "x-agent-safe-effect-receipt";

/// What the provider did with the claimed request. A signed refusal is evidence too.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectStatus {
    Effected,
    Refused,
    Indeterminate,
}

impl EffectStatus {
    fn as_str(self) -> &'static str {
        match self {
            EffectStatus::Effected => "EFFECTED",
            EffectStatus::Refused => "REFUSED",
            EffectStatus::Indeterminate => "INDETERMINATE",
        }
    }

    /// The status by its wire name, or `None` for a name the profile does not define.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "EFFECTED" => Some(EffectStatus::Effected),
            "REFUSED" => Some(EffectStatus::Refused),
            "INDETERMINATE" => Some(EffectStatus::Indeterminate),
            _ => None,
        }
    }
}

/// The effect the receipt reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Effect {
    pub status: EffectStatus,
    /// The provider's own reference for the effect: a ledger entry, an order id.
    pub reference: Option<String>,
    /// The digest of the effect in the grant's terms (`expected_effect_digest`).
    /// Equality is what confirms the effect at the authority.
    pub digest: Option<String>,
    /// When the effect took place, RFC 3339.
    pub effected_at: String,
}

/// Why a receipt could not be built; a provider never signs one it could not stand behind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptError {
    EffectDigestMalformed,
    EffectedAtMalformed,
    KidEmpty,
    IssuerEmpty,
    AudienceEmpty,
    JtiEmpty,
    /// The header and payload are always I-JSON; this is unreachable for well-formed strings.
    NotIJson,
}

impl ReceiptError {
    /// The error's code, as the other implementations name it.
    pub fn code(self) -> &'static str {
        match self {
            ReceiptError::EffectDigestMalformed => "EFFECT_DIGEST_MALFORMED",
            ReceiptError::EffectedAtMalformed => "EFFECTED_AT_MALFORMED",
            ReceiptError::KidEmpty => "KID_EMPTY",
            ReceiptError::IssuerEmpty => "ISSUER_EMPTY",
            ReceiptError::AudienceEmpty => "AUDIENCE_EMPTY",
            ReceiptError::JtiEmpty => "JTI_EMPTY",
            ReceiptError::NotIJson => "NOT_I_JSON",
        }
    }
}

impl std::fmt::Display for ReceiptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for ReceiptError {}

/// Everything a provider signs after effecting, or refusing, a claimed request.
#[derive(Debug, Clone, PartialEq)]
pub struct Receipt {
    /// The `kid` the organisation registered the key under at the authority.
    pub kid: String,
    /// The `iss` registered with the key.
    pub issuer: String,
    /// The authority the receipt is for: its issuer, `https://decionis.com` for the hosted one.
    pub audience: String,
    /// The claims of the attestation this provider verified, as [`crate::verify`] returned them.
    pub attestation: ClaimAttestation,
    /// The idempotency key of the request effected, when the provider records it.
    pub idempotency_key: Option<String>,
    pub effect: Effect,
    /// `iat`, as an epoch second.
    pub issued_at: u64,
    /// Unique per receipt.
    pub jti: String,
}

fn is_sha256_digest(text: &str) -> bool {
    text.len() == 71
        && text.starts_with("sha256:")
        && text[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// RFC 3339 by shape: a date, a `T`, a time with optional fraction, and `Z` or an offset.
fn is_rfc3339(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() < 20 || bytes[10] != b'T' {
        return false;
    }
    let date_time_ok = bytes[..19]
        .iter()
        .enumerate()
        .all(|(index, byte)| match index {
            4 | 7 => *byte == b'-',
            10 => *byte == b'T',
            13 | 16 => *byte == b':',
            _ => byte.is_ascii_digit(),
        });
    if !date_time_ok {
        return false;
    }
    let mut rest = &text[19..];
    if let Some(fraction) = rest.strip_prefix('.') {
        let digits = fraction
            .bytes()
            .take_while(|byte| byte.is_ascii_digit())
            .count();
        if digits == 0 {
            return false;
        }
        rest = &fraction[digits..];
    }
    rest == "Z"
        || (rest.len() == 6
            && (rest.starts_with('+') || rest.starts_with('-'))
            && rest[1..3].bytes().all(|byte| byte.is_ascii_digit())
            && &rest[3..4] == ":"
            && rest[4..].bytes().all(|byte| byte.is_ascii_digit()))
}

impl Receipt {
    /// The payload of the receipt, before it is signed; what the authority reads.
    pub fn claims(&self) -> Result<Value, ReceiptError> {
        if let Some(digest) = &self.effect.digest {
            if !is_sha256_digest(digest) {
                return Err(ReceiptError::EffectDigestMalformed);
            }
        }
        if !is_rfc3339(&self.effect.effected_at) {
            return Err(ReceiptError::EffectedAtMalformed);
        }
        for (value, error) in [
            (&self.kid, ReceiptError::KidEmpty),
            (&self.issuer, ReceiptError::IssuerEmpty),
            (&self.audience, ReceiptError::AudienceEmpty),
            (&self.jti, ReceiptError::JtiEmpty),
        ] {
            if value.is_empty() {
                return Err(error);
            }
        }
        let mut effect = Map::new();
        effect.insert("status".into(), json!(self.effect.status.as_str()));
        if let Some(reference) = &self.effect.reference {
            effect.insert("reference".into(), json!(reference));
        }
        if let Some(digest) = &self.effect.digest {
            effect.insert("digest".into(), json!(digest));
        }
        effect.insert("effected_at".into(), json!(self.effect.effected_at));
        let mut claims = Map::new();
        claims.insert("iss".into(), json!(self.issuer));
        claims.insert("aud".into(), json!(self.audience));
        claims.insert("sub".into(), json!(self.attestation.sub));
        claims.insert("decision_id".into(), json!(self.attestation.decision_id));
        claims.insert("dossier_id".into(), json!(self.attestation.dossier_id));
        claims.insert(
            "claim_token_digest".into(),
            json!(self.attestation.claim_token_digest),
        );
        claims.insert("attestation_jti".into(), json!(self.attestation.jti));
        claims.insert("intent_hash".into(), json!(self.attestation.intent_hash));
        if let Some(key) = &self.idempotency_key {
            claims.insert("idempotency_key".into(), json!(key));
        }
        claims.insert("effect".into(), Value::Object(effect));
        claims.insert("iat".into(), json!(self.issued_at));
        claims.insert("jti".into(), json!(self.jti));
        Ok(Value::Object(claims))
    }

    /// The `header.payload` the signature covers: both segments RFC 8785 canonical, base64url.
    pub fn signing_input(&self) -> Result<String, ReceiptError> {
        let header = json!({"alg": "EdDSA", "kid": self.kid, "typ": RECEIPT_TYPE});
        let claims = self.claims()?;
        Ok(format!("{}.{}", segment(&header)?, segment(&claims)?))
    }

    /// The receipt: a compact EdDSA JWS the provider returns in `x-agent-safe-effect-receipt`.
    pub fn sign(&self, key: &SecretKey) -> Result<String, ReceiptError> {
        let signing_input = self.signing_input()?;
        let signature = key.sign(signing_input.as_bytes(), None);
        Ok(format!(
            "{signing_input}.{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature.as_ref())
        ))
    }
}

fn segment(value: &Value) -> Result<String, ReceiptError> {
    let canonical = canonical_json(value).map_err(|_| ReceiptError::NotIJson)?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(canonical.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_by_shape() {
        for ok in [
            "2026-09-19T12:00:01Z",
            "2026-09-19T12:00:01.000Z",
            "2026-09-19T12:00:01.5+02:00",
            "2026-09-19T12:00:01-00:30",
        ] {
            assert!(is_rfc3339(ok), "{ok}");
        }
        for bad in [
            "yesterday",
            "2026-09-19 12:00:01Z",
            "2026-09-19T12:00:01",
            "2026-09-19T12:00:01.Z",
            "2026-09-19T12:00:01+0200",
        ] {
            assert!(!is_rfc3339(bad), "{bad}");
        }
    }

    #[test]
    fn digest_by_shape() {
        assert!(is_sha256_digest(&format!("sha256:{}", "a".repeat(64))));
        assert!(!is_sha256_digest(&format!("sha256:{}", "A".repeat(64))));
        assert!(!is_sha256_digest("sha256:zz"));
    }
}
