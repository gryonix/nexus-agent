//! One HTTP call through curl; every secret travels on its stdin

use std::process::Stdio;

use tokio::io::AsyncWriteExt;

use super::Refusal;

const CURL_ENV: &str = "GRYONIXNEXUSD_USERS_CURL_BIN";
const TIMEOUT_SECS: u64 = 55;

pub struct Request {
    pub method: &'static str,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
}

pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(key, _)| key.eq_ignore_ascii_case(name)).map(|(_, value)| value.as_str())
    }

    pub fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

pub fn arguments() -> Vec<&'static str> {
    vec!["-K", "-", "-s", "-S", "-i", "--max-time", "55"]
}

fn quoted(value: &str) -> String {
    let mut out = String::from("\"");
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

pub fn form_encode(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            other => format!("%{other:02X}"),
        })
        .collect()
}

pub fn form_body(pairs: &[(&str, &str)]) -> String {
    pairs.iter().map(|(key, value)| format!("{key}={}", form_encode(value))).collect::<Vec<_>>().join("&")
}

/// The curl config text for one request
pub fn config(request: &Request) -> String {
    config_with(request, false)
}

pub fn config_with(request: &Request, insecure: bool) -> String {
    let mut text = format!("url = {}\nrequest = {}\n", quoted(&request.url), quoted(request.method));
    if insecure {
        text.push_str("insecure\n");
    }
    for (name, value) in &request.headers {
        text.push_str(&format!("header = {}\n", quoted(&format!("{name}: {value}"))));
    }
    if let Some(body) = &request.body {
        text.push_str(&format!("data-raw = {}\n", quoted(body)));
    }
    text
}

/// Splits `curl -i` output into status, headers and body
pub fn parse_response(raw: &str) -> Option<Response> {
    let mut rest = raw;
    loop {
        let (head, body) = rest.split_once("\r\n\r\n").or_else(|| rest.split_once("\n\n"))?;
        let mut lines = head.lines();
        let status: u16 = lines.next()?.split_whitespace().nth(1)?.parse().ok()?;
        if status == 100 {
            rest = body;
            continue;
        }
        let headers = lines
            .filter_map(|line| line.split_once(':'))
            .map(|(name, value)| (name.trim().to_string(), value.trim().to_string()))
            .collect();
        return Some(Response { status, headers, body: body.to_string() });
    }
}

pub async fn send(request: &Request) -> Result<Response, Refusal> {
    send_with(request, false).await
}

pub async fn send_with(request: &Request, insecure: bool) -> Result<Response, Refusal> {
    let program = std::env::var(CURL_ENV).unwrap_or_else(|_| "curl".to_string());
    let mut child = tokio::process::Command::new(program)
        .args(arguments())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| Refusal::ServiceDown)?;
    if let Some(mut pipe) = child.stdin.take() {
        pipe.write_all(config_with(request, insecure).as_bytes()).await.map_err(|_| Refusal::Failed)?;
        pipe.shutdown().await.map_err(|_| Refusal::Failed)?;
    }
    let wait = std::time::Duration::from_secs(TIMEOUT_SECS + 3);
    let output = tokio::time::timeout(wait, child.wait_with_output())
        .await
        .map_err(|_| Refusal::ServiceTimeout)?
        .map_err(|_| Refusal::Failed)?;
    if !output.status.success() {
        return Err(Refusal::ServiceDown);
    }
    parse_response(&String::from_utf8_lossy(&output.stdout)).ok_or(Refusal::Failed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_are_in_the_config_and_never_in_the_arguments() {
        let request = Request {
            method: "POST",
            url: "http://127.0.0.1:8082/admin".into(),
            headers: vec![("Authorization".into(), "Bearer tok-123".into())],
            body: Some("token=tok-123".into()),
        };
        let text = config(&request);
        assert!(text.contains("tok-123"));
        assert!(arguments().iter().all(|arg| !arg.contains("tok-123")));
        assert!(arguments().contains(&"-K"));
    }

    #[test]
    fn quotes_and_newlines_cannot_break_out_of_a_config_line() {
        let request = Request {
            method: "POST",
            url: "http://127.0.0.1/x".into(),
            headers: Vec::new(),
            body: Some("a\"b\nurl = \"http://203.0.113.9/\"".into()),
        };
        let text = config(&request);
        assert_eq!(text.lines().count(), 3);
        assert!(text.contains("\\\"b\\nurl"));
    }

    #[test]
    fn a_local_panel_can_be_reached_with_its_own_certificate() {
        let request = Request { method: "GET", url: "https://127.0.0.1:8095/".into(), headers: Vec::new(), body: None };
        assert!(!config(&request).contains("insecure"));
        assert!(config_with(&request, true).contains("\ninsecure\n"));
        assert!(arguments().iter().all(|arg| !arg.contains("insecure") && *arg != "-k"));
    }

    #[test]
    fn a_redirect_with_a_cookie_parses() {
        let raw = "HTTP/1.1 303 See Other\r\nlocation: /admin\r\nset-cookie: VW_ADMIN=abc.def; Path=/admin; HttpOnly\r\n\r\n";
        let response = parse_response(raw).unwrap();
        assert_eq!(response.status, 303);
        assert!(response.header("Set-Cookie").unwrap().starts_with("VW_ADMIN=abc.def"));
    }

    #[test]
    fn an_interim_continue_is_skipped() {
        let raw = "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 201 Created\r\ncontent-type: application/json\r\n\r\n{\"a\":1}";
        let response = parse_response(raw).unwrap();
        assert_eq!((response.status, response.body.as_str()), (201, "{\"a\":1}"));
        assert!(response.ok());
    }

    #[test]
    fn garbage_is_not_a_response() {
        assert!(parse_response("not http").is_none());
    }
}
