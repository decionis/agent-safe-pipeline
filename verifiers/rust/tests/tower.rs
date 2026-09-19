#![cfg(feature = "tower")]

mod common;

use bytes::Bytes;
use common::{load, vectors_directory, VectorRequest};
use decionis_verifying_provider::tower::VerifyingProviderLayer;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use std::convert::Infallible;
use tower::{Layer, ServiceExt};

fn request(entry: &VectorRequest) -> Request<Full<Bytes>> {
    let mut builder = Request::builder()
        .method(entry.method.as_str())
        .uri(format!("{}?trace=1", entry.path));
    for (name, value) in &entry.headers {
        builder = builder.header(name, value);
    }
    builder
        .body(Full::new(Bytes::from(
            entry.body.clone().unwrap_or_default(),
        )))
        .unwrap()
}

/// The system of record behind the hop: it effects when reached.
async fn effect(_request: Request<Full<Bytes>>) -> Result<Response<Full<Bytes>>, Infallible> {
    Ok(Response::new(Full::new(Bytes::from("effected"))))
}

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(future)
}

async fn text(response: Response<Full<Bytes>>) -> (StatusCode, String) {
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

#[test]
fn the_layer_answers_the_vectors_outcomes() {
    block_on(async {
        for name in [
            "dispatch-replayed-within-lease",
            "payload-changed-after-claim",
            "copied-headers-unsigned",
        ] {
            let vector = load(&vectors_directory().join(format!("{name}.json")));
            let service =
                VerifyingProviderLayer::new(vector.options()).layer(tower::service_fn(effect));
            for (index, entry) in vector.requests.iter().enumerate() {
                let (status, body) =
                    text(service.clone().oneshot(request(entry)).await.unwrap()).await;
                match entry.outcome.as_str() {
                    "ACCEPT" => {
                        assert_eq!(status, StatusCode::OK, "{name} request {index}: {body}");
                        assert_eq!(body, "effected");
                    }
                    _ => {
                        assert_eq!(status, StatusCode::CONFLICT, "{name} request {index}");
                        let refusal: serde_json::Value = serde_json::from_str(&body).unwrap();
                        assert_eq!(refusal["status"], "REJECTED");
                        assert_eq!(
                            refusal["reason_code"],
                            entry.reason_code.as_deref().unwrap()
                        );
                    }
                }
            }
        }
    });
}

#[test]
fn the_layer_refuses_a_covered_header_received_twice_and_a_body_beyond_the_bound() {
    block_on(async {
        let vector = load(&vectors_directory().join("dispatch-attested-accepts.json"));
        let entry = &vector.requests[0];
        let service =
            VerifyingProviderLayer::new(vector.options()).layer(tower::service_fn(effect));
        let mut twice = request(entry);
        twice.headers_mut().append(
            "x-agent-safe-grant-id",
            entry.headers["x-agent-safe-grant-id"].parse().unwrap(),
        );
        let (status, _) = text(service.clone().oneshot(twice).await.unwrap()).await;
        assert_eq!(status, StatusCode::CONFLICT);
        let bounded = VerifyingProviderLayer::new(vector.options())
            .max_body_bytes(8)
            .layer(tower::service_fn(effect));
        let (status, body) = text(bounded.oneshot(request(entry)).await.unwrap()).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert!(body.contains("BODY_BEYOND_BOUND"), "{body}");
    });
}
