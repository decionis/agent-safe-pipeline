//! The receipt vectors (VP-3): this crate signs exactly the bytes every
//! implementation agrees on, under a key of its own.
mod common;

use base64::Engine;
use common::vectors_directory;
use decionis_verifying_provider::{
    ClaimAttestation, Effect, EffectStatus, Receipt, ReceiptError, RECEIPT_HEADER, RECEIPT_TYPE,
};
use ed25519_compact::{KeyPair, PublicKey, Seed, Signature};
use serde_json::Value;
use std::path::PathBuf;

fn text(value: &Value, name: &str) -> String {
    value[name].as_str().expect(name).to_owned()
}

fn optional(value: &Value, name: &str) -> Option<String> {
    value.get(name).and_then(Value::as_str).map(str::to_owned)
}

fn receipt_of(vector: &Value) -> Receipt {
    let input = &vector["input"];
    let attestation = &input["attestation"];
    let effect = &input["effect"];
    Receipt {
        kid: text(input, "kid"),
        issuer: text(input, "issuer"),
        audience: text(input, "audience"),
        attestation: ClaimAttestation {
            iss: text(attestation, "iss"),
            sub: text(attestation, "sub"),
            decision_id: text(attestation, "decision_id"),
            dossier_id: text(attestation, "dossier_id"),
            intent_hash: text(&attestation["binding"], "intent_hash"),
            execution_payload_digest: text(&attestation["binding"], "execution_payload_digest"),
            execution_payload_canonicalization_profile: text(
                &attestation["binding"],
                "execution_payload_canonicalization_profile",
            ),
            claim_token_digest: text(attestation, "claim_token_digest"),
            jti: text(attestation, "jti"),
            exp: attestation["exp"].as_f64().expect("exp"),
        },
        idempotency_key: optional(input, "idempotency_key"),
        effect: Effect {
            status: EffectStatus::parse(&text(effect, "status")).expect("status"),
            reference: optional(effect, "reference"),
            digest: optional(effect, "digest"),
            effected_at: text(effect, "effected_at"),
        },
        issued_at: input["iat"].as_u64().expect("iat"),
        jti: text(input, "jti"),
    }
}

fn base64url(text: &str) -> Vec<u8> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(text)
        .expect("base64url")
}

#[test]
fn every_receipt_vector_is_signed_over_the_bytes_it_names() {
    let directory = vectors_directory().parent().unwrap().join("receipts");
    let mut files: Vec<PathBuf> = std::fs::read_dir(directory)
        .expect("receipts")
        .map(|entry| entry.expect("entry").path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect();
    files.sort();
    assert!(files.len() >= 4, "found {} receipt vectors", files.len());
    let pair = KeyPair::from_seed(Seed::new([7u8; 32]));
    for file in files {
        let vector: Value = serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
        let name = text(&vector, "vector");
        assert_eq!(vector["level"], "VP-3", "{name}");
        let receipt = receipt_of(&vector);
        assert_eq!(
            receipt.claims().unwrap(),
            vector["expect"]["claims"],
            "{name}"
        );
        let signing_input = receipt.signing_input().unwrap();
        assert_eq!(
            signing_input,
            text(&vector["expect"], "signing_input"),
            "{name}"
        );
        let token = receipt.sign(&pair.sk).unwrap();
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "{name}");
        assert_eq!(
            format!("{}.{}", parts[0], parts[1]),
            signing_input,
            "{name}"
        );
        let header: Value = serde_json::from_slice(&base64url(parts[0])).unwrap();
        assert_eq!(header, vector["expect"]["protected_header"], "{name}");
        assert_eq!(header["typ"], RECEIPT_TYPE);
        let signature = Signature::from_slice(&base64url(parts[2])).unwrap();
        pair.pk
            .verify(signing_input.as_bytes(), &signature)
            .expect("this provider's signature verifies under its own key");
        // The vector's own token verifies under the public half it carries.
        let vector_token = text(&vector["expect"], "token");
        let vector_parts: Vec<&str> = vector_token.split('.').collect();
        let public =
            PublicKey::from_slice(&base64url(&text(&vector["expect"]["provider_jwk"], "x")))
                .unwrap();
        public
            .verify(
                format!("{}.{}", vector_parts[0], vector_parts[1]).as_bytes(),
                &Signature::from_slice(&base64url(vector_parts[2])).unwrap(),
            )
            .expect("the vector's token verifies under its public key");
    }
    assert_eq!(RECEIPT_HEADER, "x-agent-safe-effect-receipt");
}

#[test]
fn a_receipt_is_not_built_from_what_it_cannot_stand_behind() {
    let attestation = ClaimAttestation {
        iss: "i".into(),
        sub: "g".into(),
        decision_id: "d".into(),
        dossier_id: "s".into(),
        intent_hash: "h".into(),
        execution_payload_digest: "p".into(),
        execution_payload_canonicalization_profile: "RFC8785/JCS".into(),
        claim_token_digest: "c".into(),
        jti: "a".into(),
        exp: 1.0,
    };
    let good = Receipt {
        kid: "k".into(),
        issuer: "i".into(),
        audience: "a".into(),
        attestation,
        idempotency_key: None,
        effect: Effect {
            status: EffectStatus::Effected,
            reference: None,
            digest: None,
            effected_at: "2026-09-19T12:00:01Z".into(),
        },
        issued_at: 1_789_819_202,
        jti: "r".into(),
    };
    let pair = KeyPair::from_seed(Seed::new([7u8; 32]));
    assert!(good.sign(&pair.sk).is_ok());
    let cases: Vec<(Receipt, ReceiptError)> = vec![
        (
            Receipt {
                effect: Effect {
                    digest: Some("sha256:zz".into()),
                    ..good.effect.clone()
                },
                ..good.clone()
            },
            ReceiptError::EffectDigestMalformed,
        ),
        (
            Receipt {
                effect: Effect {
                    effected_at: "yesterday".into(),
                    ..good.effect.clone()
                },
                ..good.clone()
            },
            ReceiptError::EffectedAtMalformed,
        ),
        (
            Receipt {
                kid: String::new(),
                ..good.clone()
            },
            ReceiptError::KidEmpty,
        ),
        (
            Receipt {
                issuer: String::new(),
                ..good.clone()
            },
            ReceiptError::IssuerEmpty,
        ),
        (
            Receipt {
                audience: String::new(),
                ..good.clone()
            },
            ReceiptError::AudienceEmpty,
        ),
        (
            Receipt {
                jti: String::new(),
                ..good.clone()
            },
            ReceiptError::JtiEmpty,
        ),
    ];
    for (receipt, error) in cases {
        assert_eq!(receipt.sign(&pair.sk), Err(error), "{}", error.code());
    }
}
