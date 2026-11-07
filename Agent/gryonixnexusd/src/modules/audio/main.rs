//! gryonixnexus-audio: the audio module the core runs on demand.

mod odio;
mod outputs;

use serde::Deserialize;
use std::io::Read;

#[derive(Deserialize)]
struct OdioRequest {
    method: String,
    path: String,
    #[serde(default)]
    body: String,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let verb = std::env::args().nth(1).unwrap_or_default();
    let outcome = match verb.as_str() {
        "version" => Ok(format!("gryonixnexus-audio {}", env!("CARGO_PKG_VERSION"))),
        "outputs" => Ok(serde_json::to_string(&outputs::list().await).unwrap_or_default()),
        "odio" => odio_call().await,
        other => Err(format!("unknown verb {other:?}")),
    };
    match outcome {
        Ok(text) => println!("{text}"),
        Err(why) => {
            eprintln!("{why}");
            std::process::exit(1);
        }
    }
}

async fn odio_call() -> Result<String, String> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).map_err(|err| err.to_string())?;
    let request: OdioRequest = serde_json::from_str(&input).map_err(|err| err.to_string())?;
    if !odio::allowed(&request.method, &request.path) {
        return Err("this odio call is not allowed".into());
    }
    let (status, body) = odio::relay(&request.method, &request.path, &request.body).await?;
    Ok(serde_json::json!({ "status": status, "body": body }).to_string())
}
