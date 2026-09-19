//! A tower layer that runs the profile in front of any service that speaks
//! `http::Request`: axum, hyper, tonic's HTTP side. It buffers the body up
//! to a bound, verifies, and either answers with the profile's status and
//! body or hands the request on with its body intact. The hop this runs in is
//! a verifying provider only when the system of record admits nothing but
//! that hop (the profile's section 1).

use crate::{verify, Options, Refusal, Request, Verdict};
use bytes::Bytes;
use http::{header, HeaderMap, Request as HttpRequest, Response, StatusCode};
use http_body_util::{BodyExt, Full, Limited};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower::{Layer, Service};

/// The headers the signature may cover; received twice, any of them is a refusal.
const COVERED: [&str; 8] = [
    "content-digest",
    "idempotency-key",
    "x-agent-safe-intent-hash",
    "x-agent-safe-grant-id",
    "x-agent-safe-decision-id",
    "x-agent-safe-claim-attestation",
    "signature",
    "signature-input",
];

/// Wraps a service with the verifying provider.
#[derive(Clone)]
pub struct VerifyingProviderLayer {
    options: Arc<Options>,
    max_body_bytes: usize,
}

impl VerifyingProviderLayer {
    /// A layer over the provider's options, buffering bodies up to one MiB.
    pub fn new(options: Options) -> Self {
        VerifyingProviderLayer {
            options: Arc::new(options),
            max_body_bytes: 1 << 20,
        }
    }

    /// The body bound; a larger body is refused with 413.
    pub fn max_body_bytes(mut self, bytes: usize) -> Self {
        self.max_body_bytes = bytes;
        self
    }
}

impl<S> Layer<S> for VerifyingProviderLayer {
    type Service = VerifyingProviderService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        VerifyingProviderService {
            inner,
            options: self.options.clone(),
            max_body_bytes: self.max_body_bytes,
        }
    }
}

/// The service the layer makes: the profile, then the inner service.
#[derive(Clone)]
pub struct VerifyingProviderService<S> {
    inner: S,
    options: Arc<Options>,
    max_body_bytes: usize,
}

impl<S, ReqBody, ResBody> Service<HttpRequest<ReqBody>> for VerifyingProviderService<S>
where
    S: Service<HttpRequest<Full<Bytes>>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: http_body::Body<Data = Bytes> + Send + 'static,
    ReqBody::Error: std::error::Error + Send + Sync + 'static,
    ResBody: From<Bytes>,
{
    type Response = Response<ResBody>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: HttpRequest<ReqBody>) -> Self::Future {
        // The inner service is taken ready and swapped for a clone, as tower's
        // guide has it, so the future owns a service that was polled ready.
        let inner = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, inner);
        let options = self.options.clone();
        let max_body_bytes = self.max_body_bytes;
        Box::pin(async move {
            let (parts, body) = request.into_parts();
            let body = match Limited::new(body, max_body_bytes).collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(_) => return Ok(refuse(StatusCode::PAYLOAD_TOO_LARGE, "BODY_BEYOND_BOUND")),
            };
            let headers = match lower_case_headers(&parts.headers) {
                Some(headers) => headers,
                None => {
                    return Ok(refuse(
                        StatusCode::CONFLICT,
                        Refusal::SignatureInvalidOrIncomplete.code(),
                    ))
                }
            };
            let verdict = verify(
                &Request {
                    method: parts.method.as_str(),
                    path: parts.uri.path(),
                    body: if body.is_empty() { None } else { Some(&body) },
                    headers: &headers,
                },
                &options,
            );
            match verdict {
                Verdict::Accepted(_) => {
                    inner
                        .call(HttpRequest::from_parts(parts, Full::new(body)))
                        .await
                }
                Verdict::Refused(refusal) => Ok(refuse(StatusCode::CONFLICT, refusal.code())),
            }
        })
    }
}

/// Header names lower-cased with their single values; None when a covered
/// header was received more than once, or a value is not text.
fn lower_case_headers(headers: &HeaderMap) -> Option<HashMap<String, String>> {
    let mut lowered = HashMap::new();
    for name in headers.keys() {
        let values: Vec<_> = headers.get_all(name).iter().collect();
        if values.len() > 1 && COVERED.contains(&name.as_str()) {
            return None;
        }
        let value = values.first()?.to_str().ok()?.trim().to_owned();
        lowered.insert(name.as_str().to_owned(), value);
    }
    Some(lowered)
}

fn refuse<ResBody: From<Bytes>>(status: StatusCode, code: &str) -> Response<ResBody> {
    let body = format!(r#"{{"status":"REJECTED","reason_code":"{code}"}}"#);
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(ResBody::from(Bytes::from(body)))
        .expect("a static response builds")
}
