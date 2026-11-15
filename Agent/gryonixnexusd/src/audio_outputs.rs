//! Lists the machine's playback devices through the audio module.

use hyper::StatusCode;
use serde::Deserialize;

use crate::api::{connect_error, Codec, Resp};
use crate::pb;

#[derive(Deserialize)]
struct Output {
    device: String,
    title: String,
    mixers: Vec<String>,
}

/// Playback devices, as the audio module reads them
pub async fn list_audio_outputs(codec: Codec, _req: pb::ListAudioOutputsRequest) -> Resp {
    let text = match crate::modules::run(&crate::modules::AUDIO, "outputs", "").await {
        Ok(text) => text,
        Err(why) => return connect_error(StatusCode::SERVICE_UNAVAILABLE, "unavailable", &why),
    };
    let found: Vec<Output> = serde_json::from_str(&text).unwrap_or_default();
    let outputs = found.into_iter().map(|o| pb::AudioOutput { device: o.device, title: o.title, mixers: o.mixers }).collect();
    let reply = pb::ListAudioOutputsResponse { outputs };
    codec.encode(&reply).unwrap_or_else(|err| connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string()))
}
