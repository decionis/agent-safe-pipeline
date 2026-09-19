//! What every test loads from a vector file, read from serde_json values so
//! the tests need no derive macro either.
#![allow(dead_code)]

use decionis_verifying_provider::{ExecutorKey, Jwks, MemoryReplayStore, Options};
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub struct Vector {
    pub name: String,
    pub profile: String,
    pub version: String,
    pub effects: bool,
    pub clock_window_seconds: u64,
    pub now: u64,
    pub authority_issuer: String,
    pub executor_keys: Vec<ExecutorKey>,
    pub authority_jwks: Jwks,
    pub requests: Vec<VectorRequest>,
}

pub struct VectorRequest {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub outcome: String,
    pub reason_code: Option<String>,
}

/// The vectors live at the repository root; walk up to them from this crate.
pub fn vectors_directory() -> PathBuf {
    let mut directory: &Path = Path::new(env!("CARGO_MANIFEST_DIR"));
    loop {
        let candidate = directory.join("conformance/provider/vectors");
        if candidate.is_dir() {
            return candidate;
        }
        directory = directory
            .parent()
            .expect("conformance/provider/vectors above this crate");
    }
}

pub fn load(path: &Path) -> Vector {
    let value: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let text = |value: &Value, name: &str| value[name].as_str().expect(name).to_owned();
    let provider = &value["provider"];
    let executor_keys = value["executor_keys"]
        .as_array()
        .expect("executor_keys")
        .iter()
        .map(|key| match text(key, "alg").as_str() {
            "ed25519" => {
                ExecutorKey::ed25519_pem(&text(key, "keyid"), &text(key, "public_pem")).unwrap()
            }
            "hmac-sha256" => {
                ExecutorKey::hmac(&text(key, "keyid"), &text(key, "shared_material_utf8"))
            }
            other => panic!("unknown algorithm {other}"),
        })
        .collect();
    let requests = value["requests"]
        .as_array()
        .expect("requests")
        .iter()
        .map(|request| VectorRequest {
            method: text(request, "method"),
            path: text(request, "path"),
            headers: request["headers"]
                .as_object()
                .expect("headers")
                .iter()
                .map(|(name, value)| (name.clone(), value.as_str().expect("header").to_owned()))
                .collect(),
            body: request["body"].as_str().map(str::to_owned),
            outcome: text(&request["expect"], "outcome"),
            reason_code: request["expect"]["reason_code"].as_str().map(str::to_owned),
        })
        .collect();
    Vector {
        name: text(&value, "vector"),
        profile: text(&value, "profile"),
        version: text(&value, "version"),
        effects: provider["effects"].as_bool().expect("effects"),
        clock_window_seconds: provider["clock_window_seconds"].as_u64().expect("window"),
        now: epoch_seconds(&text(provider, "now")),
        authority_issuer: text(provider, "authority_issuer"),
        executor_keys,
        authority_jwks: Jwks::parse(&value["authority_jwks"].to_string()).unwrap(),
        requests,
    }
}

impl Vector {
    pub fn options(&self) -> Options {
        let now = self.now;
        Options {
            effects: self.effects,
            executor_keys: self.executor_keys.clone(),
            authority_jwks: self.authority_jwks.clone(),
            authority_issuer: self.authority_issuer.clone(),
            clock_window_seconds: self.clock_window_seconds,
            replay: Box::new(MemoryReplayStore::with_clock(move || now)),
            now: Box::new(move || now),
        }
    }
}

/// The vectors' instant as seconds since the epoch, without a date crate: the
/// generator writes it as an RFC 3339 UTC time.
pub fn epoch_seconds(rfc3339: &str) -> u64 {
    let (date, time) = rfc3339.split_once('T').expect("date and time");
    let mut parts = date
        .split('-')
        .map(|part| part.parse::<i64>().expect("number"));
    let (year, month, day) = (
        parts.next().unwrap(),
        parts.next().unwrap(),
        parts.next().unwrap(),
    );
    let time = time.trim_end_matches('Z');
    let time = time.split('.').next().unwrap();
    let mut parts = time
        .split(':')
        .map(|part| part.parse::<i64>().expect("number"));
    let (hour, minute, second) = (
        parts.next().unwrap(),
        parts.next().unwrap(),
        parts.next().unwrap(),
    );
    // Days from civil, Howard Hinnant's algorithm.
    let (y, m) = if month <= 2 {
        (year - 1, month + 9)
    } else {
        (year, month - 3)
    };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * m + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    (days * 86_400 + hour * 3_600 + minute * 60 + second) as u64
}
