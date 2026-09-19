mod common;

use common::{epoch_seconds, load, vectors_directory};
use decionis_verifying_provider::{verify, Request, Verdict};
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
            let verdict = verify(
                &Request {
                    method: &request.method,
                    path: &request.path,
                    body: request.body.as_deref().map(str::as_bytes),
                    headers: &request.headers,
                },
                &options,
            );
            let name = &vector.name;
            match request.outcome.as_str() {
                "ACCEPT" => match verdict {
                    Verdict::Accepted(attestation) => assert!(
                        attestation.is_some() || !vector.effects,
                        "{name} request {index}: an accepted dispatch carries its attestation"
                    ),
                    Verdict::Refused(refusal) => {
                        panic!(
                            "{name} request {index}: expected ACCEPT, got {}",
                            refusal.code()
                        )
                    }
                },
                "REFUSE" => match verdict {
                    Verdict::Refused(refusal) => assert_eq!(
                        refusal.code(),
                        request.reason_code.as_deref().unwrap(),
                        "{name} request {index}"
                    ),
                    Verdict::Accepted(_) => panic!("{name} request {index}: expected a refusal"),
                },
                other => panic!("{name} request {index}: unknown outcome {other}"),
            }
        }
    }
}
