//! An independent Rust implementation of the Verifying Provider Profile
//! (`docs/authority/verifying-provider.md` in the agent-safe-pipeline
//! repository), VP-1 and VP-2, written against the profile's text and held to
//! its vectors. It shares no code with the executor; that is the point of a
//! second implementation.
//!
//! [`verify`] is the whole procedure for one received request. With the
//! `tower` feature, [`tower::VerifyingProviderLayer`] runs it in front of any
//! service that speaks `http::Request`.

#![forbid(unsafe_code)]

use base64::Engine;
use ed25519_compact::{PublicKey, Signature};
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;

pub mod canonical;
pub mod receipt;
#[cfg(feature = "tower")]
pub mod tower;

pub use canonical::{canonical_digest, canonical_json, NotIJson};
pub use receipt::{Effect, EffectStatus, Receipt, ReceiptError, RECEIPT_HEADER, RECEIPT_TYPE};

/// The protected header `typ` of a claim attestation.
pub const ATTESTATION_TYPE: &str = "decionis-claim-attestation+jwt";
/// The one canonicalization profile this version defines.
pub const JCS_PROFILE: &str = "RFC8785/JCS";
const LABEL: &str = "agentsafe";

const BASE_COMPONENTS: [&str; 5] = [
    "@method",
    "@path",
    "content-digest",
    "idempotency-key",
    "x-agent-safe-intent-hash",
];
const KNOWN_COMPONENTS: [&str; 8] = [
    "@method",
    "@path",
    "content-digest",
    "idempotency-key",
    "x-agent-safe-intent-hash",
    "x-agent-safe-grant-id",
    "x-agent-safe-decision-id",
    "x-agent-safe-claim-attestation",
];

/// The refusal codes the profile names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    SignatureInvalidOrIncomplete,
    AttestationInvalid,
    AttestationDoesNotDescribeThisRequest,
    GrantReplayed,
}

impl Refusal {
    /// The code as the profile spells it.
    pub fn code(self) -> &'static str {
        match self {
            Refusal::SignatureInvalidOrIncomplete => "SIGNATURE_INVALID_OR_INCOMPLETE",
            Refusal::AttestationInvalid => "ATTESTATION_INVALID",
            Refusal::AttestationDoesNotDescribeThisRequest => {
                "ATTESTATION_DOES_NOT_DESCRIBE_THIS_REQUEST"
            }
            Refusal::GrantReplayed => "GRANT_REPLAYED",
        }
    }

    /// The refusal body the profile names; the status is the provider's, 409 in the references.
    pub fn body(self) -> String {
        format!(r#"{{"status":"REJECTED","reason_code":"{}"}}"#, self.code())
    }
}

/// A key the provider issued to, or registered for, the executor, by the keyid a signature names.
#[derive(Debug, Clone)]
pub enum ExecutorKey {
    Ed25519 {
        key_id: String,
        public_key: PublicKey,
    },
    HmacSha256 {
        key_id: String,
        secret: Vec<u8>,
    },
}

impl ExecutorKey {
    /// An Ed25519 key from its SPKI PEM, as the vectors and a key file carry it.
    pub fn ed25519_pem(key_id: &str, public_key_pem: &str) -> Result<Self, ed25519_compact::Error> {
        Ok(ExecutorKey::Ed25519 {
            key_id: key_id.to_owned(),
            public_key: PublicKey::from_pem(public_key_pem)?,
        })
    }

    /// A shared HMAC secret, as UTF-8 text.
    pub fn hmac(key_id: &str, shared_material_utf8: &str) -> Self {
        ExecutorKey::HmacSha256 {
            key_id: key_id.to_owned(),
            secret: shared_material_utf8.as_bytes().to_vec(),
        }
    }

    fn key_id(&self) -> &str {
        match self {
            ExecutorKey::Ed25519 { key_id, .. } | ExecutorKey::HmacSha256 { key_id, .. } => key_id,
        }
    }

    fn algorithm(&self) -> &'static str {
        match self {
            ExecutorKey::Ed25519 { .. } => "ed25519",
            ExecutorKey::HmacSha256 { .. } => "hmac-sha256",
        }
    }
}

/// The authority's execution-grant key set, as served: OKP Ed25519 keys by kid.
#[derive(Debug, Clone, Default)]
pub struct Jwks {
    keys: Vec<(String, PublicKey)>,
}

impl Jwks {
    /// Parses the JWKS document; entries that are not OKP Ed25519 keys are left out.
    pub fn parse(json: &str) -> Result<Self, serde_json::Error> {
        let document: Value = serde_json::from_str(json)?;
        let mut keys = Vec::new();
        for entry in document
            .get("keys")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let text = |name: &str| entry.get(name).and_then(Value::as_str);
            if text("kty") != Some("OKP") || text("crv") != Some("Ed25519") {
                continue;
            }
            let (Some(kid), Some(x)) = (text("kid"), text("x")) else {
                continue;
            };
            let Ok(bytes) = base64url(x) else { continue };
            let Ok(key) = PublicKey::from_slice(&bytes) else {
                continue;
            };
            keys.push((kid.to_owned(), key));
        }
        Ok(Jwks { keys })
    }

    fn find(&self, kid: &str) -> Option<&PublicKey> {
        self.keys
            .iter()
            .find(|(id, _)| id == kid)
            .map(|(_, key)| key)
    }
}

/// Where a provider keeps the grants it accepted, until their attestation
/// expires. `record` answers true when the grant was not there and is now,
/// and false when it was: the second presentation. Shared by every instance
/// that can effect; the profile's step 8.
pub trait ReplayStore: Send + Sync {
    fn record(&self, grant_id: &str, expires_at: u64) -> bool;
}

/// A replay store for one process: enough for a single instance, and for the
/// vectors. Expired grants are forgotten on the next record, which is why the
/// store needs no life beyond the lease.
pub struct MemoryReplayStore {
    seen: Mutex<HashMap<String, u64>>,
    now: Box<dyn Fn() -> u64 + Send + Sync>,
}

impl MemoryReplayStore {
    /// A store reading the clock given, in seconds since the epoch.
    pub fn with_clock(now: impl Fn() -> u64 + Send + Sync + 'static) -> Self {
        MemoryReplayStore {
            seen: Mutex::new(HashMap::new()),
            now: Box::new(now),
        }
    }
}

impl Default for MemoryReplayStore {
    fn default() -> Self {
        MemoryReplayStore::with_clock(unix_now)
    }
}

impl ReplayStore for MemoryReplayStore {
    fn record(&self, grant_id: &str, expires_at: u64) -> bool {
        let now = (self.now)();
        let mut seen = self
            .seen
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        seen.retain(|_, expiry| *expiry > now);
        if seen.contains_key(grant_id) {
            return false;
        }
        seen.insert(grant_id.to_owned(), expires_at);
        true
    }
}

/// Seconds since the epoch, from the wall clock.
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

/// How this provider is configured.
pub struct Options {
    /// Whether this endpoint effects anything; an effecting provider requires all eight components covered.
    pub effects: bool,
    /// The keys the provider issued to the executor, unique by keyid.
    pub executor_keys: Vec<ExecutorKey>,
    /// The authority's execution-grant JWKS, as its well-known path serves it.
    pub authority_jwks: Jwks,
    /// The `iss` the provider trusts: `https://decionis.com` for Decionis.
    pub authority_issuer: String,
    /// How far `created` may lie from now, each way, in seconds.
    pub clock_window_seconds: u64,
    pub replay: Box<dyn ReplayStore>,
    /// The provider's clock, in seconds since the epoch.
    pub now: Box<dyn Fn() -> u64 + Send + Sync>,
}

/// What the provider received. Header names are lower case; a covered header
/// received more than once is a refusal and must not be collapsed into this
/// map. `body` is `None` when the request carried none.
pub struct Request<'a> {
    pub method: &'a str,
    /// The request path, without its query.
    pub path: &'a str,
    pub body: Option<&'a [u8]>,
    pub headers: &'a HashMap<String, String>,
}

/// The part of the attestation the provider reads; the authority's schema has
/// more. The dossier, the claim-token digest and the attestation's own id are
/// what a receipt ([`receipt::Receipt`], VP-3) is built from.
#[derive(Debug, Clone, PartialEq)]
pub struct ClaimAttestation {
    pub iss: String,
    pub sub: String,
    pub decision_id: String,
    pub dossier_id: String,
    pub intent_hash: String,
    pub execution_payload_digest: String,
    pub execution_payload_canonicalization_profile: String,
    pub claim_token_digest: String,
    pub jti: String,
    pub exp: f64,
}

/// The outcome of the procedure for one request. `Accepted(None)` is a read
/// a non-effecting provider verified at VP-1 alone. The attestation is boxed
/// so a refusal, the common small value, is not sized by the rare large one.
#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    Accepted(Option<Box<ClaimAttestation>>),
    Refused(Refusal),
}

/// The RFC 9530 value the executor sends for a body, the empty body included.
pub fn content_digest(body: Option<&[u8]>) -> String {
    let sum = Sha256::digest(body.unwrap_or(&[]));
    format!(
        "sha-256=:{}:",
        base64::engine::general_purpose::STANDARD.encode(sum)
    )
}

/// The whole procedure for one received request.
pub fn verify(request: &Request<'_>, options: &Options) -> Verdict {
    let now = (options.now)();
    if !signature_holds(request, options, now) {
        return Verdict::Refused(Refusal::SignatureInvalidOrIncomplete);
    }
    if !options.effects {
        return Verdict::Accepted(None);
    }
    let Some(attestation) = attestation_of(
        request.headers.get("x-agent-safe-claim-attestation"),
        options,
    ) else {
        return Verdict::Refused(Refusal::AttestationInvalid);
    };
    if !described(&attestation, request, now) {
        return Verdict::Refused(Refusal::AttestationDoesNotDescribeThisRequest);
    }
    if !options
        .replay
        .record(&attestation.sub, attestation.exp as u64)
    {
        return Verdict::Refused(Refusal::GrantReplayed);
    }
    Verdict::Accepted(Some(Box::new(attestation)))
}

// Steps 0 to 5.
fn signature_holds(request: &Request<'_>, options: &Options, now: u64) -> bool {
    let Some(input) = request.headers.get("signature-input") else {
        return false;
    };
    let Some(parameters) = input.strip_prefix(&format!("{LABEL}=")) else {
        return false;
    };
    let Some(encoded) = request
        .headers
        .get("signature")
        .and_then(|value| value.strip_prefix(&format!("{LABEL}=:")))
        .and_then(|value| value.strip_suffix(':'))
    else {
        return false;
    };
    if request.headers.get("content-digest").map(String::as_str)
        != Some(content_digest(request.body).as_str())
    {
        return false;
    }
    let Some(covered) = covered_components(parameters) else {
        return false;
    };
    let required: &[&str] = if options.effects {
        &KNOWN_COMPONENTS
    } else {
        &BASE_COMPONENTS
    };
    if required
        .iter()
        .any(|component| !covered.contains(component))
    {
        return false;
    }
    let Some(created) =
        parameter(parameters, ";created=").and_then(|value| value.parse::<u64>().ok())
    else {
        return false;
    };
    let window = options.clock_window_seconds;
    if created + window < now || created > now + window {
        return false;
    }
    let key_id = quoted_parameter(parameters, ";keyid=\"");
    let algorithm = quoted_parameter(parameters, ";alg=\"");
    let Some(key) = options
        .executor_keys
        .iter()
        .find(|key| Some(key.key_id()) == key_id && Some(key.algorithm()) == algorithm)
    else {
        return false;
    };
    let Some(base) = signature_base(request, &covered, parameters) else {
        return false;
    };
    let Ok(signature) = base64::engine::general_purpose::STANDARD.decode(encoded) else {
        return false;
    };
    match key {
        ExecutorKey::Ed25519 { public_key, .. } => {
            let Ok(signature) = Signature::from_slice(&signature) else {
                return false;
            };
            public_key.verify(&base, &signature).is_ok()
        }
        ExecutorKey::HmacSha256 { secret, .. } => {
            let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(secret) else {
                return false;
            };
            mac.update(&base);
            mac.verify_slice(&signature).is_ok()
        }
    }
}

/// The covered components a signature-input names, or None when the list is
/// not one, names a component this profile does not know, or names one twice.
fn covered_components(parameters: &str) -> Option<Vec<&str>> {
    let inner = parameters.strip_prefix('(')?;
    let end = inner.find(')')?;
    let inner = &inner[..end];
    if inner.is_empty() {
        return Some(Vec::new());
    }
    let mut names = Vec::new();
    for quoted in inner.split(' ') {
        let name = quoted.strip_prefix('"')?.strip_suffix('"')?;
        if name.is_empty() || !KNOWN_COMPONENTS.contains(&name) || names.contains(&name) {
            return None;
        }
        names.push(name);
    }
    Some(names)
}

/// The base, exactly as both sides build it.
fn signature_base(request: &Request<'_>, covered: &[&str], parameters: &str) -> Option<Vec<u8>> {
    let mut lines = Vec::with_capacity(covered.len() + 1);
    for component in covered {
        let value = match *component {
            "@method" => request.method.to_ascii_uppercase(),
            "@path" => request.path.to_owned(),
            "content-digest" => content_digest(request.body),
            name => request.headers.get(name)?.clone(),
        };
        lines.push(format!("\"{component}\": {value}"));
    }
    lines.push(format!("\"@signature-params\": {parameters}"));
    Some(lines.join("\n").into_bytes())
}

/// The value of an unquoted parameter such as `;created=1700000000`.
fn parameter<'a>(parameters: &'a str, name: &str) -> Option<&'a str> {
    let start = parameters.find(name)? + name.len();
    let rest = &parameters[start..];
    let end = rest.find(';').unwrap_or(rest.len());
    Some(&rest[..end])
}

/// The value of a quoted parameter such as `;keyid="executor-1"`.
fn quoted_parameter<'a>(parameters: &'a str, name: &str) -> Option<&'a str> {
    let start = parameters.find(name)? + name.len();
    let rest = &parameters[start..];
    let end = rest.find('"')?;
    Some(&rest[..end])
}

fn base64url(text: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(text.trim_end_matches('='))
}

// Step 6: the attestation by form, key, signature, issuer and the shape of
// its claims; the claims when it is the authority's.
fn attestation_of(compact: Option<&String>, options: &Options) -> Option<ClaimAttestation> {
    let compact = compact?;
    let mut parts = compact.split('.');
    let (header, payload, signature) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let protected: Value = serde_json::from_slice(&base64url(header).ok()?).ok()?;
    let field = |name: &str| protected.get(name).and_then(Value::as_str);
    if field("alg") != Some("EdDSA") || field("typ") != Some(ATTESTATION_TYPE) {
        return None;
    }
    let key = options.authority_jwks.find(field("kid")?)?;
    let signature = Signature::from_slice(&base64url(signature).ok()?).ok()?;
    key.verify(format!("{header}.{payload}").as_bytes(), &signature)
        .ok()?;
    let claims: Value = serde_json::from_slice(&base64url(payload).ok()?).ok()?;
    // The claims a provider compares, and the ones a receipt is built from,
    // must be there in the right type: an attestation without them is not one.
    let text =
        |value: &Value, name: &str| value.get(name).and_then(Value::as_str).map(str::to_owned);
    let binding = claims.get("binding")?;
    let attestation = ClaimAttestation {
        iss: text(&claims, "iss")?,
        sub: text(&claims, "sub")?,
        decision_id: text(&claims, "decision_id")?,
        dossier_id: text(&claims, "dossier_id")?,
        intent_hash: text(binding, "intent_hash")?,
        execution_payload_digest: text(binding, "execution_payload_digest")?,
        execution_payload_canonicalization_profile: text(
            binding,
            "execution_payload_canonicalization_profile",
        )?,
        claim_token_digest: text(&claims, "claim_token_digest")?,
        jti: text(&claims, "jti")?,
        exp: claims.get("exp").and_then(Value::as_f64)?,
    };
    if attestation.iss != options.authority_issuer {
        return None;
    }
    Some(attestation)
}

// Step 7: whether the attestation describes this request.
fn described(attestation: &ClaimAttestation, request: &Request<'_>, now: u64) -> bool {
    let Some(body) = request.body else {
        return false;
    };
    let Ok(digest) = canonical_digest(body) else {
        return false;
    };
    let header = |name: &str| request.headers.get(name).map(String::as_str);
    Some(attestation.sub.as_str()) == header("x-agent-safe-grant-id")
        && Some(attestation.decision_id.as_str()) == header("x-agent-safe-decision-id")
        && Some(attestation.intent_hash.as_str()) == header("x-agent-safe-intent-hash")
        && attestation.execution_payload_canonicalization_profile == JCS_PROFILE
        && attestation.execution_payload_digest == digest
        && attestation.exp.partial_cmp(&(now as f64)) == Some(std::cmp::Ordering::Greater)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_replay_store_forgets_a_grant_once_its_attestation_expired() {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::Arc;
        let clock = Arc::new(AtomicU64::new(1_789_819_200));
        let reading = clock.clone();
        let store = MemoryReplayStore::with_clock(move || reading.load(Ordering::SeqCst));
        assert!(store.record("g", 1_789_819_201));
        assert!(!store.record("g", 1_789_819_201));
        assert!(!store.record("g", 1_789_819_205));
        clock.store(1_789_819_201, Ordering::SeqCst);
        assert!(store.record("g", 1_789_819_205));
    }

    #[test]
    fn covered_components_refuse_the_unknown_and_the_repeated() {
        assert_eq!(covered_components("()").map(|list| list.len()), Some(0));
        assert!(covered_components(r#"("@method" "@path")"#).is_some());
        assert!(covered_components(r#"("@method" "@method")"#).is_none());
        assert!(covered_components(r#"("@method" "x-other")"#).is_none());
        assert!(covered_components(r#"("@method)"#).is_none());
        assert!(covered_components(r#""@method""#).is_none());
    }
}
