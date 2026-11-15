//! Hands allowed odio-api calls to the audio module.

use hyper::StatusCode;
use serde::Deserialize;

use crate::api::{connect_error, Codec, Resp};
use crate::pb;

#[derive(Deserialize)]
struct Reply {
    status: u32,
    body: String,
}

/// The hub is installed and stays silent
fn not_answering(why: &str) -> Resp {
    crate::api::connect_reason(StatusCode::SERVICE_UNAVAILABLE, "unavailable", why, "audio.hub_not_answering")
}

/// Relay one call when the hub is installed
pub async fn odio_call(codec: Codec, req: pb::OdioCallRequest) -> Resp {
    if !std::path::Path::new(crate::install::odio::CONTROL_PATH).exists() {
        return crate::api::connect_refusal(
            StatusCode::PRECONDITION_FAILED,
            "failed_precondition",
            "the audio hub (odio) is not installed here",
            "audio.hub_not_installed",
            &[],
        );
    }
    let input = serde_json::json!({ "method": req.method, "path": req.path, "body": req.body }).to_string();
    let reply = match crate::modules::run(&crate::modules::AUDIO, "odio", &input).await {
        Ok(text) => serde_json::from_str::<Reply>(&text).map_err(|err| err.to_string()),
        Err(why) => Err(why),
    };
    match reply {
        Ok(Reply { status, body }) => codec
            .encode(&pb::OdioCallResponse { status, body })
            .unwrap_or_else(|err| connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string())),
        Err(why) if why.contains("not allowed") => connect_error(StatusCode::FORBIDDEN, "permission_denied", &why),
        Err(why) => not_answering(&why),
    }
}

#[cfg(test)]
mod unreadable_tests {
    use super::*;

    #[tokio::test]
    async fn a_silent_hub_is_unavailable_by_reason() {
        let resp = not_answering("connection refused");
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(crate::api::reason_of(resp).await, "audio.hub_not_answering");
    }
}
