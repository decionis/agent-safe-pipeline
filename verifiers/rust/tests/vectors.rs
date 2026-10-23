mod common;

use common::{epoch_seconds, load, vectors_directory};
use decionis_verifying_provider::{verify, Refusal, Target, Verdict};
use std::path::PathBuf;

#[test]
fn the_instant_reads_as_the_generator_wrote_it() {
    assert_eq!(epoch_seconds("2026-09-19T12:00:00.000Z"), 1_789_819_200);
    assert_eq!(epoch_seconds("1970-01-01T00:00:00Z"), 0);
}

#[test]
fn every_vector_reaches_the_outcomes_it_names() {
    let mut files: Vec<PathBuf> = std::fs::read_dir(vectors_directory())
        .expect("vectors")
        .map(|entry| entry.expect("entry").path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect();
    files.sort();
    assert!(files.len() >= 20, "found {} vectors", files.len());
    for file in files {
        let vector = load(&file);
        assert_eq!(vector.profile, "agent-safe.verifying-provider/1");
        assert_eq!(vector.version, "0.1");
        let options = vector.options();
        for (index, request) in vector.requests.iter().enumerate() {
            let verdict = verify(&request.received(), &options, request.target());
            let name = &vector.name;
            match request.outcome.as_str() {
                "ACCEPT" => match verdict {
                    Verdict::Accepted(attestation) => {
                        assert!(
                            attestation.is_some() || !vector.effects,
                            "{name} request {index}: an accepted dispatch carries its attestation"
                        );
                        assert_eq!(
                            attestation.and_then(|attestation| attestation.expected_state_version),
                            request.expected_state_version,
                            "{name} request {index}"
                        );
                    }
                    Verdict::Refused(refusal) => {
                        panic!(
                            "{name} request {index}: expected ACCEPT, got {}",
                            refusal.code()
                        )
                    }
                },
                "REFUSE" => match verdict {
                    Verdict::Refused(refusal) => {
                        assert_eq!(
                            refusal.code(),
                            request.reason_code.as_deref().unwrap(),
                            "{name} request {index}"
                        );
                        // Only the provider's own refusal at step 9 hands the claims back.
                        let handed_back = match refusal {
                            Refusal::TargetStateChanged(attestation) => {
                                attestation.expected_state_version
                            }
                            _ => None,
                        };
                        assert_eq!(
                            handed_back, request.expected_state_version,
                            "{name} request {index}"
                        );
                    }
                    Verdict::Accepted(_) => panic!("{name} request {index}: expected a refusal"),
                },
                other => panic!("{name} request {index}: unknown outcome {other}"),
            }
        }
    }
}

#[test]
fn step_nine_holds_the_effect_to_the_version_the_grant_was_decided_on() {
    let vector = load(&vectors_directory().join("state-version-unchanged-accepts.json"));
    let request = vector.requests[0].received();
    let accepted = verify(&request, &vector.options(), None);
    let Verdict::Accepted(Some(attestation)) = &accepted else {
        panic!("no target: {accepted:?}");
    };
    assert_eq!(
        attestation.expected_state_version.as_deref(),
        Some("\"17\"")
    );
    assert_eq!(
        verify(&request, &vector.options(), Some(Target::At("\"17\""))),
        accepted
    );
    for target in [Target::At("\"18\""), Target::At("W/\"17\""), Target::Gone] {
        let options = vector.options();
        assert_eq!(
            verify(&request, &options, Some(target)),
            Verdict::Refused(Refusal::TargetStateChanged(attestation.clone())),
            "{target:?}"
        );
        // The presentation was recorded before the target refused it: the grant is spent.
        assert_eq!(
            verify(&request, &options, Some(Target::At("\"17\""))),
            Verdict::Refused(Refusal::GrantReplayed),
            "{target:?} presented again"
        );
    }
}

#[test]
fn step_nine_ignores_the_target_when_the_attestation_names_no_version() {
    let vector = load(&vectors_directory().join("dispatch-attested-accepts.json"));
    for target in [Target::At("\"18\""), Target::Gone] {
        match verify(
            &vector.requests[0].received(),
            &vector.options(),
            Some(target),
        ) {
            Verdict::Accepted(Some(attestation)) => {
                assert_eq!(attestation.expected_state_version, None, "{target:?}")
            }
            other => panic!("{target:?}: {other:?}"),
        }
    }
}
