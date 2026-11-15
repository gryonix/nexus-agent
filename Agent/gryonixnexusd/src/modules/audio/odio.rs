//! Relays allowed calls to the audio hub's local odio-api.

use tokio::io::{AsyncReadExt, AsyncWriteExt};

const ADDRESS: &str = "127.0.0.1:8018";
const MAX_REPLY: usize = 1 << 20;

const READS: &[&str] = &["/audio", "/audio/server", "/audio/outputs", "/players", "/services", "/bluetooth"];

const WRITES: &[&[&str]] = &[
    &["audio", "server", "mute"],
    &["audio", "server", "volume"],
    &["audio", "outputs", "*", "default"],
    &["audio", "outputs", "*", "mute"],
    &["audio", "outputs", "*", "volume"],
    &["players", "*", "play_pause"],
    &["players", "*", "next"],
    &["players", "*", "previous"],
    &["players", "*", "volume"],
    &["services", "user", "*", "start"],
    &["services", "user", "*", "stop"],
    &["services", "user", "*", "restart"],
    &["bluetooth", "power_up"],
    &["bluetooth", "power_down"],
    &["bluetooth", "pairing_mode"],
];

/// Reads by exact path, writes by pattern with safe names
pub fn allowed(method: &str, path: &str) -> bool {
    match method {
        "GET" => READS.contains(&path),
        "POST" => {
            let Some(rest) = path.strip_prefix('/') else { return false };
            let parts: Vec<&str> = rest.split('/').collect();
            WRITES.iter().any(|pattern| matches(pattern, &parts))
        }
        _ => false,
    }
}

fn matches(pattern: &[&str], parts: &[&str]) -> bool {
    pattern.len() == parts.len()
        && pattern.iter().zip(parts).all(|(want, got)| if *want == "*" { safe_name(got) } else { want == got })
}

fn safe_name(segment: &str) -> bool {
    !segment.is_empty()
        && segment.len() <= 200
        && segment.chars().all(|c| c.is_ascii_alphanumeric() || "._:-@".contains(c))
}

pub async fn relay(method: &str, path: &str, body: &str) -> Result<(u32, String), String> {
    let call = async {
        let mut stream = tokio::net::TcpStream::connect(ADDRESS).await.map_err(|e| e.to_string())?;
        stream.write_all(request_bytes(method, path, body).as_bytes()).await.map_err(|e| e.to_string())?;
        let mut reply = Vec::new();
        stream.take(MAX_REPLY as u64).read_to_end(&mut reply).await.map_err(|e| e.to_string())?;
        parse_reply(&String::from_utf8_lossy(&reply))
    };
    tokio::time::timeout(std::time::Duration::from_secs(15), call).await.map_err(|_| "timed out".to_string())?
}

fn request_bytes(method: &str, path: &str, body: &str) -> String {
    format!(
        "{method} {path} HTTP/1.0\r\nHost: localhost\r\nAccept: application/json\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

/// Status and body of an HTTP/1.x reply
fn parse_reply(text: &str) -> Result<(u32, String), String> {
    let (head, body) = text.split_once("\r\n\r\n").ok_or("no header end")?;
    let status = head.split_whitespace().nth(1).and_then(|code| code.parse().ok()).ok_or("no status")?;
    Ok((status, body.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_and_controls_pass_and_everything_else_is_refused() {
        assert!(allowed("GET", "/players"));
        assert!(allowed("POST", "/audio/outputs/alsa_output.platform-soc_sound.stereo-fallback/volume"));
        assert!(allowed("POST", "/services/user/spotifyd.service/restart"));
        assert!(!allowed("POST", "/services/user/spotifyd.service/disable"));
        assert!(!allowed("POST", "/power/reboot"));
        assert!(!allowed("POST", "/players/../power/volume"));
        assert!(!allowed("POST", "/players/a b/volume"));
        assert!(!allowed("DELETE", "/players"));
        assert!(!allowed("GET", "/players?x=1"));
    }

    #[test]
    fn the_reply_splits_into_status_and_body() {
        assert_eq!(parse_reply("HTTP/1.1 200 OK\r\nX: y\r\n\r\n{\"a\":1}").unwrap(), (200, "{\"a\":1}".to_string()));
        assert!(parse_reply("garbage").is_err());
        assert!(request_bytes("POST", "/audio/server/volume", "{}").contains("Content-Length: 2\r\n"));
    }
}
