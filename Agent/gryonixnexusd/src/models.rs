//! The models the local engine runs: what is there, fetching one, removing one

use bytes::Bytes;
use hyper::StatusCode;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use crate::api::{connect_error, envelope, error_trailer, stream_response, Codec, Resp};
use crate::install::ollama;
use crate::pb;

fn encode<T>(codec: Codec, message: &T) -> Resp
where
    T: prost::Message + serde::Serialize,
{
    codec.encode(message).unwrap_or_else(|err| {
        connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string())
    })
}

const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

/// Characters a model name may contain
fn checked_name(raw: &str) -> Result<String, Resp> {
    let name = raw.trim();
    let ok = !name.is_empty()
        && name.len() <= 128
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':' | '/'));
    if ok {
        Ok(name.to_string())
    } else {
        Err(connect_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_argument",
            "a model name is letters, digits and . _ - : / — nothing else",
        ))
    }
}

async fn engine_models_path() -> Option<String> {
    let format = format!(
        "{{{{range .Mounts}}}}{{{{if eq .Destination \"{}\"}}}}{{{{.Source}}}}{{{{end}}}}{{{{end}}}}",
        ollama::MODELS_MOUNT
    );
    let args = ["inspect".to_string(), ollama::CONTAINER.to_string(), "--format".to_string(), format];
    let captured = crate::container_ops::capture("/usr/bin/docker", &args, 10).await.ok()?;
    let path = captured.stdout.trim().to_string();
    (!path.is_empty() && path.starts_with('/')).then_some(path)
}

fn disk(path: &str) -> (u64, u64) {
    match crate::metrics::statvfs_usage(path) {
        Some((size, used)) => ((size - used).max(0) as u64, size.max(0) as u64),
        None => (0, 0),
    }
}

/// One HTTP request to the engine, read to the end
async fn call(method: &str, path: &str, body: Option<&str>) -> Result<(u16, String), String> {
    let work = async {
        let mut stream = TcpStream::connect(("127.0.0.1", ollama::API_PORT))
            .await
            .map_err(|err| err.to_string())?;
        stream.write_all(request_head(method, path, body).as_bytes()).await.map_err(|e| e.to_string())?;
        let mut raw = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut raw).await.map_err(|e| e.to_string())?;
        let text = String::from_utf8_lossy(&raw).to_string();
        let (head, body) = text
            .split_once("\r\n\r\n")
            .ok_or_else(|| "the engine's answer had no body".to_string())?;
        let status = head
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse().ok())
            .ok_or_else(|| "the engine's answer had no status".to_string())?;
        Ok((status, body.to_string()))
    };
    tokio::time::timeout(TIMEOUT, work)
        .await
        .map_err(|_| "the model engine did not answer in time".to_string())?
}

fn request_head(method: &str, path: &str, body: Option<&str>) -> String {
    let mut head =
        format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n");
    match body {
        Some(body) => head.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        )),
        None => head.push_str("\r\n"),
    }
    head
}

fn parse_models(body: &str) -> Vec<pb::Model> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(body) else {
        return Vec::new();
    };
    let Some(items) = value.get("models").and_then(|m| m.as_array()) else {
        return Vec::new();
    };
    items
        .iter()
        .map(|item| {
            let details = item.get("details");
            pb::Model {
                name: item.get("name").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
                size_bytes: item.get("size").and_then(|v| v.as_u64()).unwrap_or_default(),
                modified_unix: item
                    .get("modified_at")
                    .and_then(|v| v.as_str())
                    .and_then(parse_rfc3339)
                    .unwrap_or_default(),
                parameter_size: details
                    .and_then(|d| d.get("parameter_size"))
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
                quantization: details
                    .and_then(|d| d.get("quantization_level"))
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
            }
        })
        .filter(|model| !model.name.is_empty())
        .collect()
}

/// Seconds since the epoch from the engine's RFC 3339 timestamp
fn parse_rfc3339(text: &str) -> Option<i64> {
    let date = text.get(0..10)?;
    let time = text.get(11..19)?;
    let mut date = date.split('-');
    let (y, m, d): (i64, i64, i64) =
        (date.next()?.parse().ok()?, date.next()?.parse().ok()?, date.next()?.parse().ok()?);
    let mut time = time.split(':');
    let (hh, mm, ss): (i64, i64, i64) =
        (time.next()?.parse().ok()?, time.next()?.parse().ok()?, time.next()?.parse().ok()?);
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + hh * 3_600 + mm * 60 + ss)
}

/// The listing, with the disk it lives on.
pub async fn list_now() -> pb::ModelList {
    let path = engine_models_path().await.unwrap_or_default();
    let (free, total) = if path.is_empty() { (0, 0) } else { disk(&path) };
    match call("GET", "/api/tags", None).await {
        Ok((200, body)) => pb::ModelList {
            models: parse_models(&body),
            engine_present: true,
            path,
            disk_free_bytes: free,
            disk_total_bytes: total,
        },
        _ => pb::ModelList {
            models: Vec::new(),
            engine_present: false,
            path,
            disk_free_bytes: free,
            disk_total_bytes: total,
        },
    }
}

pub async fn list(codec: Codec, _req: pb::ListModelsRequest) -> Resp {
    encode(codec, &list_now().await)
}

pub async fn delete(codec: Codec, req: pb::DeleteModelRequest) -> Resp {
    let name = match checked_name(&req.name) {
        Ok(name) => name,
        Err(response) => return response,
    };
    let body = serde_json::json!({ "model": name }).to_string();
    match call("DELETE", "/api/delete", Some(&body)).await {
        Ok((200..=299, _)) => encode(codec, &list_now().await),
        Ok((404, _)) => connect_error(
            StatusCode::NOT_FOUND,
            "not_found",
            "the engine has no model by that name",
        ),
        Ok((status, body)) => connect_error(
            StatusCode::BAD_GATEWAY,
            "unavailable",
            &format!("the engine refused to remove it: {}", engine_error(&body, status)),
        ),
        Err(err) => connect_error(StatusCode::BAD_GATEWAY, "unavailable", &err),
    }
}

fn engine_error(body: &str, status: u16) -> String {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_string))
        .unwrap_or_else(|| format!("HTTP {status}"))
}

pub async fn pull(codec: Codec, req: pb::PullModelRequest) -> Resp {
    let name = match checked_name(&req.name) {
        Ok(name) => name,
        Err(response) => return response,
    };
    let before = list_now().await;
    if !before.engine_present {
        return connect_error(
            StatusCode::FAILED_DEPENDENCY,
            "failed_precondition",
            "no model engine is installed on this server",
        );
    }
    let claim = match crate::jobs::OperationClaim::acquire("model", &name) {
        Ok(claim) => claim,
        Err(response) => return response,
    };

    let json = matches!(codec, Codec::Json);
    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(64);

    tokio::spawn(async move {
        let _claim = claim;
        let journal = crate::jobs::Journal::open(pb::JobKind::ModelPull, &name);
        let switch = crate::jobs::cancellable(&journal);
        let sink = PullSink { tx, codec, journal };
        let _ = sink.started(&name).await;
        let outcome = fetch(&name, before.disk_free_bytes, &sink, switch.as_ref()).await;
        match outcome {
            Ok(Pull::Done) => {
                let _ = sink.completed(list_now().await).await;
            }
            Ok(Pull::Stopped) => {
                let note = reclaim_partial_blobs().await;
                let _ = sink.progress(&note, 0, 0).await;
                let _ = sink.completed(list_now().await).await;
                sink.stopped(&note);
            }
            Err(err) => {
                let _ = sink.completed(list_now().await).await;
                let _ = sink.fail(&err).await;
            }
        }
    });

    stream_response(json, rx)
}

enum Pull {
    Done,
    Stopped,
}

/// Connects to the engine and sends the pull request
async fn open_pull(name: &str) -> Result<BufReader<TcpStream>, String> {
    let body = serde_json::json!({ "model": name, "stream": true }).to_string();
    let mut stream = TcpStream::connect(("127.0.0.1", ollama::API_PORT))
        .await
        .map_err(|err| format!("could not reach the model engine: {err}"))?;
    stream
        .write_all(request_head("POST", "/api/pull", Some(&body)).as_bytes())
        .await
        .map_err(|err| err.to_string())?;
    Ok(BufReader::new(stream))
}

async fn next_line(
    reader: &mut BufReader<TcpStream>,
    line: &mut String,
    switch: Option<&crate::jobs::CancelSwitch>,
) -> Result<Option<usize>, String> {
    let read = match switch {
        Some(switch) => tokio::select! {
            biased;
            () = switch.wait() => return Ok(None),
            read = reader.read_line(line) => read.map_err(|err| err.to_string())?,
        },
        None => reader.read_line(line).await.map_err(|err| err.to_string())?,
    };
    Ok(Some(read))
}

/// Refuses a model the disk cannot hold, with a margin
fn check_space(total: u64, free_bytes: u64) -> Result<(), String> {
    let needed = total.saturating_add((total / 10).max(1_073_741_824));
    if free_bytes < needed {
        return Err(format!(
            "this model needs about {} and the disk has {} free",
            human(needed),
            human(free_bytes)
        ));
    }
    Ok(())
}

async fn fetch(
    name: &str,
    free_bytes: u64,
    sink: &PullSink,
    switch: Option<&crate::jobs::CancelSwitch>,
) -> Result<Pull, String> {
    let mut reader = open_pull(name).await?;
    let mut line = String::new();
    let mut in_body = false;
    let mut checked_space = false;
    let mut last_reported = 0u64;
    let mut succeeded = false;
    loop {
        line.clear();
        let Some(read) = next_line(&mut reader, &mut line, switch).await? else { return Ok(Pull::Stopped) };
        if read == 0 {
            break;
        }
        let text = line.trim_end();
        if !in_body {
            if text.is_empty() {
                in_body = true;
            }
            continue;
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
            continue;
        };
        if let Some(err) = value.get("error").and_then(|v| v.as_str()) {
            return Err(err.to_string());
        }
        let status = value.get("status").and_then(|v| v.as_str()).unwrap_or_default();
        succeeded |= status == "success";
        let total = value.get("total").and_then(|v| v.as_u64()).unwrap_or_default();
        let completed = value.get("completed").and_then(|v| v.as_u64()).unwrap_or_default();

        if total > 0 && !checked_space {
            checked_space = true;
            check_space(total, free_bytes)?;
        }
        let percent = if total > 0 { completed * 100 / total } else { 0 };
        if total == 0 || percent != last_reported {
            last_reported = percent;
            let _ = sink.progress(status, total, completed).await;
        }
    }
    if !succeeded {
        return Err("the model engine closed the connection before the pull finished".to_string());
    }
    Ok(Pull::Done)
}

async fn reclaim_partial_blobs() -> String {
    let others = crate::jobs::list(pb::JobKind::ModelPull, true).len();
    if others > 1 {
        return "stopped; the partly fetched layers were left in place because another \
                model is being fetched on this server"
            .to_string();
    }
    let Some(root) = engine_models_path().await else {
        return "stopped".to_string();
    };
    let blobs = std::path::Path::new(&root).join("models").join("blobs");
    let Ok(entries) = std::fs::read_dir(&blobs) else {
        return "stopped".to_string();
    };
    let mut freed = 0u64;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !is_partial_blob(name) {
            continue;
        }
        let size = entry.metadata().map(|meta| meta.len()).unwrap_or(0);
        if std::fs::remove_file(entry.path()).is_ok() {
            freed = freed.saturating_add(size);
        }
    }
    if freed == 0 {
        "stopped".to_string()
    } else {
        format!("stopped; {} of partly fetched layers removed", human(freed))
    }
}

fn is_partial_blob(name: &str) -> bool {
    name.starts_with("sha256-") && name.contains("-partial")
}

fn human(bytes: u64) -> String {
    const GB: u64 = 1_073_741_824;
    const MB: u64 = 1_048_576;
    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else {
        format!("{} MB", bytes / MB)
    }
}

struct PullSink {
    tx: tokio::sync::mpsc::Sender<Bytes>,
    codec: Codec,
    journal: Option<crate::jobs::Journal>,
}

impl PullSink {
    async fn send(&self, event: pb::ModelPullEvent) -> Result<(), ()> {
        crate::jobs::tee(&self.journal, event.phase, "", &event.text);
        let payload = self.codec.encode_payload(&event);
        self.tx.send(envelope(0x00, &payload)).await.map_err(|_| ())
    }

    fn base(&self, phase: pb::ServiceOperationPhase) -> pb::ModelPullEvent {
        pb::ModelPullEvent {
            phase: phase as i32,
            text: String::new(),
            total_bytes: 0,
            completed_bytes: 0,
            job_id: crate::jobs::id_of(&self.journal),
            list: None,
        }
    }

    async fn started(&self, name: &str) -> Result<(), ()> {
        let mut event = self.base(pb::ServiceOperationPhase::Started);
        event.text = format!("fetching {name}");
        self.send(event).await
    }

    async fn progress(&self, status: &str, total: u64, completed: u64) -> Result<(), ()> {
        let mut event = self.base(pb::ServiceOperationPhase::Progress);
        event.text = status.to_string();
        event.total_bytes = total;
        event.completed_bytes = completed;
        self.send(event).await
    }

    async fn completed(&self, list: pb::ModelList) -> Result<(), ()> {
        let mut event = self.base(pb::ServiceOperationPhase::Completed);
        event.list = Some(list);
        self.send(event).await
    }

    /// The journal side of a stop
    fn stopped(&self, note: &str) {
        if let Some(journal) = &self.journal {
            journal.cancelled(note);
        }
    }

    async fn fail(&self, message: &str) -> Result<(), ()> {
        crate::jobs::finish(&self.journal, Some(message));
        self.tx.send(error_trailer("internal", message)).await.map_err(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The engine's real `/api/tags` shape, reduced to two entries.
    const TAGS: &str = r#"{"models":[
      {"name":"llama3.2:3b","model":"llama3.2:3b","modified_at":"2026-09-05T14:23:11.123456789Z",
       "size":2019393189,"digest":"a80c4f17","details":{"parameter_size":"3.2B","quantization_level":"Q4_K_M"}},
      {"name":"nomic-embed-text:latest","modified_at":"2026-08-01T09:00:00Z","size":274302450,
       "details":{"parameter_size":"137M","quantization_level":"F16"}}
    ]}"#;

    #[test]
    fn the_listing_carries_exact_bytes_and_a_real_date() {
        let models = parse_models(TAGS);
        assert_eq!(models.len(), 2);
        assert_eq!(models[0].name, "llama3.2:3b");
        assert_eq!(models[0].size_bytes, 2_019_393_189);
        assert_eq!(models[0].parameter_size, "3.2B");
        assert_eq!(models[0].quantization, "Q4_K_M");
        assert!(models[0].modified_unix > 1_780_000_000, "a real epoch second");
    }

    #[test]
    fn a_model_missing_its_details_still_lists() {
        let models = parse_models(r#"{"models":[{"name":"x:latest"}]}"#);
        assert_eq!(models.len(), 1);
        assert_eq!(models[0].size_bytes, 0);
        assert_eq!(models[0].parameter_size, "");
        assert_eq!(models[0].modified_unix, 0);
    }

    #[test]
    fn nothing_parseable_is_an_empty_list() {
        assert!(parse_models("not json").is_empty());
        assert!(parse_models("{}").is_empty());
        assert!(parse_models(r#"{"models":"nope"}"#).is_empty());
        assert!(parse_models(r#"{"models":[{"size":1}]}"#).is_empty());
    }

    #[test]
    fn the_engines_timestamp_becomes_an_epoch_second() {
        assert_eq!(parse_rfc3339("2026-09-05T14:23:11.123456789Z"), Some(1_788_618_191));
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_rfc3339("2000-03-01T00:00:00Z"), Some(951_868_800));
        assert_eq!(parse_rfc3339("nope"), None);
    }

    #[test]
    fn only_real_model_names_are_accepted() {
        for good in ["llama3.2:3b", "library/qwen2.5:7b-instruct", "nomic-embed-text", "a_b.c-d"] {
            assert!(checked_name(good).is_ok(), "{good} is a model name");
        }
        for bad in ["", "   ", "a b", "a;rm -rf /", "a\"b", "a\nb", "модель", &"x".repeat(129)] {
            assert!(checked_name(bad).is_err(), "{bad:?} is not");
        }
        assert_eq!(checked_name("  llama3.2  ").unwrap(), "llama3.2");
    }

    #[test]
    fn the_engines_error_text_is_preferred_to_a_status() {
        assert_eq!(engine_error(r#"{"error":"model not found"}"#, 404), "model not found");
        assert_eq!(engine_error("<html>", 502), "HTTP 502");
    }

    #[test]
    fn only_the_layers_a_fetch_never_finished_are_removable() {
        assert!(is_partial_blob("sha256-1a2b3c-partial"));
        assert!(is_partial_blob("sha256-1a2b3c-partial-0"), "the engine suffixes some of them");

        assert!(!is_partial_blob("sha256-1a2b3c"), "a finished layer is a model on this disk");
        assert!(!is_partial_blob("partial"), "not every file with the word in it is one of these");
        assert!(!is_partial_blob("manifest-partial"), "and not every prefix is the blob prefix");
        assert!(!is_partial_blob(""));
    }

    #[test]
    fn sizes_are_rendered_for_a_person() {
        assert_eq!(human(2_147_483_648), "2.0 GB");
        assert_eq!(human(524_288_000), "500 MB");
    }

    #[test]
    fn the_mount_query_asks_for_the_engines_own_destination() {
        assert_eq!(ollama::MODELS_MOUNT, "/root/.ollama");
        let compose = crate::install::ollama::compose_contents(&crate::install::context::Input {
            domain: "example.com".to_string(),
            ..Default::default()
        });
        assert!(
            compose.contains(&format!(":{}", ollama::MODELS_MOUNT)),
            "the mount this queries for has to be the one the install writes"
        );
    }

    #[test]
    fn a_post_carries_its_length_and_a_get_does_not() {
        let post = request_head("POST", "/api/pull", Some(r#"{"model":"x"}"#));
        assert!(post.contains("Content-Length: 13\r\n"));
        assert!(post.ends_with(r#"{"model":"x"}"#));
        let get = request_head("GET", "/api/tags", None);
        assert!(get.ends_with("\r\n\r\n"));
        assert!(!get.contains("Content-Length"));
    }
}
