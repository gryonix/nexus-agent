//! The schema and the router have to agree — in BOTH directions

use std::path::Path;

fn read(relative: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("{}: {err}", path.display()))
}

/// The schema, wherever this crate is standing
fn read_proto() -> String {
    for candidate in ["../proto/gryonixnexusd/v1/gryonixnexusd.proto",
                      "../../Proto/gryonixnexusd/v1/gryonixnexusd.proto"] {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(candidate);
        if path.is_file() {
            return read(candidate);
        }
    }
    panic!("gryonixnexusd.proto found in neither ../proto nor ../../Proto");
}

/// Every `rpc Name(` in the schema.
fn declared_rpcs(proto: &str) -> Vec<String> {
    proto
        .lines()
        .map(str::trim)
        .filter_map(|line| line.strip_prefix("rpc "))
        .filter_map(|rest| rest.split('(').next())
        .map(|name| name.trim().to_string())
        .filter(|name| !name.is_empty())
        .collect()
}

/// Every `"/gryonixnexusd.v1.<Service>/<Method>"` the router matches on.
fn routed_rpcs(api: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in api.lines() {
        let mut rest = line;
        while let Some(start) = rest.find("\"/gryonixnexusd.v1.") {
            let after = &rest[start + 1..];
            let Some(end) = after.find('"') else { break };
            let path = &after[..end];
            if let Some(method) = path.rsplit('/').next() {
                if !method.is_empty() {
                    out.push(method.to_string());
                }
            }
            rest = &after[end..];
        }
    }
    out
}

#[test]
fn every_rpc_the_schema_declares_is_answered_by_the_router() {
    let declared = declared_rpcs(&read_proto());
    let routed = routed_rpcs(&read("src/api.rs"));
    assert!(!declared.is_empty(), "the proto parser found nothing — it stopped matching the file");
    assert!(!routed.is_empty(), "the router parser found nothing — it stopped matching the file");

    let missing: Vec<&String> = declared.iter().filter(|name| !routed.contains(name)).collect();
    assert!(
        missing.is_empty(),
        "declared in the schema but not routed, so the agent answers 404 — which the app reads as \
         a dead route rather than as a missing arm: {missing:?}"
    );
}

#[test]
fn every_route_the_agent_answers_is_declared_in_the_schema() {
    let declared = declared_rpcs(&read_proto());
    let routed = routed_rpcs(&read("src/api.rs"));

    let undeclared: Vec<&String> = routed.iter().filter(|name| !declared.contains(name)).collect();
    assert!(
        undeclared.is_empty(),
        "answered by the router but absent from the schema, so no generated client can reach it: \
         {undeclared:?}"
    );
}

#[test]
fn every_streaming_rpc_decodes_its_request_from_the_envelope() {
    let proto = read_proto();
    let api = read("src/api.rs");

    // `rpc Name(Req) returns (stream Resp);`
    let streaming: Vec<String> = proto
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("rpc ") && line.contains("returns (stream "))
        .filter_map(|line| line.strip_prefix("rpc "))
        .filter_map(|rest| rest.split('(').next())
        .map(|name| name.trim().to_string())
        .collect();
    assert!(
        streaming.len() >= 8,
        "the schema should still declare the streaming verbs; found {streaming:?}"
    );

    let mut plain = Vec::new();
    for method in &streaming {
        let Some(at) = api.find(&format!("/{}\"", method)).or_else(|| api.find(&format!("/{method}\""))) else {
            continue; // reachability is the other test's job
        };
        let tail = &api[at..];
        let Some(decode_at) = tail.find("codec.decode") else { continue };
        // Only the arm's own body, never the next one's.
        let arm_end = tail.find("\n        \"/gryonixnexusd").unwrap_or(tail.len());
        if decode_at > arm_end {
            continue;
        }
        if !tail[decode_at..].starts_with("codec.decode_enveloped") {
            plain.push(method.clone());
        }
    }
    assert!(
        plain.is_empty(),
        "these streaming verbs decode their request WITHOUT the Connect envelope, so every call \
         to them fails with a 500 and no stream:\n  {}",
        plain.join("\n  ")
    );
}
