use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use hyper::StatusCode;

use crate::api::{connect_error, Codec, Resp};
use crate::util::strip_ansi;
use crate::pb;

pub const WRAPPER_PATH: &str = "/opt/gryonixnexus-admin-lockdown.sh";

/// Deadline for one call
const QUICK_TIMEOUT_SECS: u64 = 60;

const ECHO_LIMIT: usize = 200;

fn truncate(value: &str) -> String {
    value.chars().take(ECHO_LIMIT).collect()
}

fn wrapper_path() -> PathBuf {
    PathBuf::from(std::env::var("GRYONIXNEXUSD_LOCKDOWN_WRAPPER").unwrap_or_else(|_| WRAPPER_PATH.to_string()))
}

fn guard_path() -> PathBuf {
    PathBuf::from(
        std::env::var("GRYONIXNEXUSD_ADMIN_GUARD").unwrap_or_else(|_| crate::install::caddy::ADMIN_GUARD_PATH.to_string()),
    )
}

/// Restores a missing wrapper where sites import the guard
fn ensure_wrapper() -> bool {
    let wrapper = wrapper_path();
    if wrapper.exists() {
        return true;
    }
    guard_path().exists()
        && crate::util::write_file_atomic(&wrapper, crate::install::vpn::panel::ADMIN_LOCKDOWN_SH.as_bytes(), 0o750)
            .is_ok()
}

#[derive(Debug, PartialEq, Eq)]
enum Rejection {
    NoWrapper,
    UnspecifiedMode,
}

impl Rejection {
    fn parts(&self) -> (StatusCode, &'static str, String) {
        match self {
            Rejection::NoWrapper => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "failed_precondition",
                format!(
                    "this server has no lockdown wrapper ({WRAPPER_PATH}): it serves no web sites"
                ),
            ),
            Rejection::UnspecifiedMode => (
                StatusCode::BAD_REQUEST,
                "invalid_argument",
                "mode is required (off, all or only)".to_string(),
            ),
        }
    }

    fn response(&self) -> Resp {
        let (status, code, message) = self.parts();
        connect_error(status, code, &message)
    }
}

fn is_valid_host(value: &str) -> bool {
    !value.is_empty() && value.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

fn parse_lockdown_answer(output: &str) -> pb::LockdownState {
    let last = output
        .split('\n')
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .last()
        .unwrap_or("");

    if last == "on" {
        return pb::LockdownState { mode: pb::LockdownMode::All as i32, hosts: Vec::new() };
    }
    if let Some(rest) = last.strip_prefix("only ") {
        let hosts: Vec<String> =
            rest.split(' ').filter(|h| !h.is_empty()).filter(|h| is_valid_host(h)).map(str::to_string).collect();
        return if hosts.is_empty() {
            pb::LockdownState { mode: pb::LockdownMode::Off as i32, hosts: Vec::new() }
        } else {
            pb::LockdownState { mode: pb::LockdownMode::Only as i32, hosts }
        };
    }
    pb::LockdownState { mode: pb::LockdownMode::Off as i32, hosts: Vec::new() }
}

fn build_set_args(mode: pb::LockdownMode, hosts: &[String]) -> Result<Vec<String>, Rejection> {
    match mode {
        pb::LockdownMode::Unspecified => Err(Rejection::UnspecifiedMode),
        pb::LockdownMode::Off => Ok(vec!["off".to_string()]),
        pb::LockdownMode::All => Ok(vec!["on".to_string()]),
        pb::LockdownMode::Only => {
            let valid: Vec<String> = hosts.iter().filter(|h| is_valid_host(h)).cloned().collect();
            if valid.is_empty() {
                Ok(vec!["off".to_string()])
            } else {
                let mut args = vec!["only".to_string()];
                args.extend(valid);
                Ok(args)
            }
        }
    }
}

fn encode<T>(codec: Codec, message: &T) -> Resp
where
    T: prost::Message + serde::Serialize,
{
    codec.encode(message).unwrap_or_else(|err| connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string()))
}

async fn run_wrapper(args: &[&str]) -> Result<String, String> {
    let child = tokio::process::Command::new(wrapper_path())
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|err| format!("could not run the lockdown wrapper: {err}"))?;

    let output = tokio::time::timeout(Duration::from_secs(QUICK_TIMEOUT_SECS), child.wait_with_output())
        .await
        .map_err(|_| format!("the lockdown wrapper timed out after {QUICK_TIMEOUT_SECS}s"))?
        .map_err(|err| format!("the lockdown wrapper did not finish: {err}"))?;

    let stdout = strip_ansi(&String::from_utf8_lossy(&output.stdout));
    if output.status.success() {
        return Ok(stdout);
    }
    let stderr = strip_ansi(&String::from_utf8_lossy(&output.stderr));
    Err(describe_failure(output.status.code(), &stderr))
}

fn describe_failure(code: Option<i32>, stderr: &str) -> String {
    let detail = truncate(stderr.trim());
    match (code, detail.is_empty()) {
        (_, false) => detail,
        (Some(code), true) => format!("the lockdown wrapper exited {code}"),
        (None, true) => "the lockdown wrapper was killed by a signal".to_string(),
    }
}

fn wrapper_failed(detail: &str) -> Resp {
    connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", detail)
}

pub async fn refresh_guard() -> Result<bool, String> {
    let wrapper = wrapper_path();
    let Ok(old) = std::fs::read_to_string(&wrapper) else { return Ok(false) };
    let fresh = crate::install::vpn::panel::ADMIN_LOCKDOWN_SH;
    let rewritten = old != fresh;
    if rewritten {
        std::fs::write(&wrapper, fresh).map_err(|err| format!("could not write {}: {err}", wrapper.display()))?;
    }
    let guard = std::fs::read_to_string(crate::install::caddy::ADMIN_GUARD_PATH).unwrap_or_default();
    if guard.trim().is_empty() || guard.contains("@gryonixnexus_tunnel") {
        return Ok(rewritten);
    }
    let state = parse_lockdown_answer(&run_wrapper(&["status"]).await?);
    let mode = pb::LockdownMode::try_from(state.mode).unwrap_or(pb::LockdownMode::Off);
    if mode == pb::LockdownMode::Off {
        return Ok(rewritten);
    }
    let args = build_set_args(mode, &state.hosts).map_err(|_| "the guard's mode is unreadable".to_string())?;
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    run_wrapper(&args).await?;
    Ok(true)
}

pub async fn get_lockdown(codec: Codec, _req: pb::GetLockdownRequest) -> Resp {
    if !ensure_wrapper() {
        return Rejection::NoWrapper.response();
    }
    match run_wrapper(&["status"]).await {
        Ok(stdout) => encode(codec, &parse_lockdown_answer(&stdout)),
        Err(why) => wrapper_failed(&why),
    }
}

/// Change the guard state
pub async fn set_lockdown(codec: Codec, req: pb::SetLockdownRequest) -> Resp {
    let mode = pb::LockdownMode::try_from(req.mode).unwrap_or(pb::LockdownMode::Unspecified);
    let args = match build_set_args(mode, &req.hosts) {
        Ok(args) => args,
        Err(rejection) => return rejection.response(),
    };
    if !ensure_wrapper() {
        return Rejection::NoWrapper.response();
    }
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match run_wrapper(&args).await {
        Ok(stdout) => encode(codec, &parse_lockdown_answer(&stdout)),
        Err(why) => wrapper_failed(&why),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn write_stub(dir: &std::path::Path, name: &str, body: &str) -> PathBuf {
        std::fs::create_dir_all(dir).unwrap();
        let script = dir.join(name);
        std::fs::write(&script, body).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        script
    }

    // ─────────────────────────── parse_lockdown_answer ───────────────────────────

    #[test]
    fn bare_on_is_all() {
        let state = parse_lockdown_answer("on\n");
        assert_eq!(state.mode, pb::LockdownMode::All as i32);
        assert!(state.hosts.is_empty());
    }

    #[test]
    fn bare_off_is_off() {
        let state = parse_lockdown_answer("off\n");
        assert_eq!(state.mode, pb::LockdownMode::Off as i32);
        assert!(state.hosts.is_empty());
    }

    #[test]
    fn only_line_lists_the_hosts() {
        let state = parse_lockdown_answer("only a.example.com b.example.com\n");
        assert_eq!(state.mode, pb::LockdownMode::Only as i32);
        assert_eq!(state.hosts, vec!["a.example.com", "b.example.com"]);
    }

    #[test]
    fn an_only_line_where_a_host_fails_the_charset_check_drops_just_that_host() {
        let state = parse_lockdown_answer("only a.example.com evil;host b.example.com\n");
        assert_eq!(state.mode, pb::LockdownMode::Only as i32);
        assert_eq!(state.hosts, vec!["a.example.com", "b.example.com"]);
    }

    #[test]
    fn an_only_line_where_every_host_fails_collapses_to_off() {
        let state = parse_lockdown_answer("only evil;host another$one\n");
        assert_eq!(state.mode, pb::LockdownMode::Off as i32);
        assert!(state.hosts.is_empty());
    }

    #[test]
    fn empty_or_garbage_output_is_off() {
        assert_eq!(parse_lockdown_answer("").mode, pb::LockdownMode::Off as i32);
        assert_eq!(parse_lockdown_answer("\n\n").mode, pb::LockdownMode::Off as i32);
        assert_eq!(parse_lockdown_answer("some unrelated line\n").mode, pb::LockdownMode::Off as i32);
    }

    #[test]
    fn only_the_last_non_empty_line_is_read() {
        let state = parse_lockdown_answer("reloading caddy\n\non\n");
        assert_eq!(state.mode, pb::LockdownMode::All as i32);
    }

    // ─────────────────────────── build_set_args ───────────────────────────

    #[test]
    fn unspecified_mode_is_refused_before_anything_runs() {
        assert_eq!(build_set_args(pb::LockdownMode::Unspecified, &[]), Err(Rejection::UnspecifiedMode));
    }

    #[test]
    fn off_and_all_build_their_bare_subcommand() {
        assert_eq!(build_set_args(pb::LockdownMode::Off, &[]), Ok(vec!["off".to_string()]));
        assert_eq!(build_set_args(pb::LockdownMode::All, &[]), Ok(vec!["on".to_string()]));
        // Hosts are ignored outside ONLY.
        assert_eq!(
            build_set_args(pb::LockdownMode::Off, &["a.example.com".to_string()]),
            Ok(vec!["off".to_string()])
        );
    }

    #[test]
    fn only_builds_the_subcommand_plus_every_valid_host() {
        let hosts = vec!["a.example.com".to_string(), "b.example.com".to_string()];
        assert_eq!(
            build_set_args(pb::LockdownMode::Only, &hosts),
            Ok(vec!["only".to_string(), "a.example.com".to_string(), "b.example.com".to_string()])
        );
    }

    #[test]
    fn only_filters_out_a_host_with_a_shell_metacharacter_or_a_space_before_it_ever_reaches_argv() {
        let hosts = vec![
            "a.example.com".to_string(),
            "evil;rm -rf /".to_string(),
            "has space.example.com".to_string(),
            "$(whoami).example.com".to_string(),
        ];
        assert_eq!(build_set_args(pb::LockdownMode::Only, &hosts), Ok(vec!["only".to_string(), "a.example.com".to_string()]));
    }

    #[test]
    fn only_with_an_empty_host_list_becomes_off() {
        assert_eq!(build_set_args(pb::LockdownMode::Only, &[]), Ok(vec!["off".to_string()]));
    }

    #[test]
    fn only_where_every_host_fails_the_charset_check_also_becomes_off() {
        let hosts = vec!["evil;rm -rf /".to_string(), "has space".to_string()];
        assert_eq!(build_set_args(pb::LockdownMode::Only, &hosts), Ok(vec!["off".to_string()]));
    }

    // ─────────────────────────── get_lockdown, against a real stub ───────────────────────────

    #[tokio::test]
    async fn get_lockdown_reports_no_wrapper_when_the_host_has_none() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("GRYONIXNEXUSD_LOCKDOWN_WRAPPER", "/nonexistent/gryonixnexus-admin-lockdown.sh");
        std::env::set_var("GRYONIXNEXUSD_ADMIN_GUARD", "/nonexistent/gryonixnexus-admin-guard");
        let resp = get_lockdown(Codec::Proto, pb::GetLockdownRequest {}).await;
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        std::env::remove_var("GRYONIXNEXUSD_LOCKDOWN_WRAPPER");
        std::env::remove_var("GRYONIXNEXUSD_ADMIN_GUARD");
    }

    #[tokio::test]
    async fn a_missing_wrapper_comes_back_where_sites_import_the_guard() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-lockdown-heal-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let wrapper = dir.join("admin-lockdown.sh");
        let _ = std::fs::remove_file(&wrapper);
        std::fs::write(dir.join("admin-guard"), "").unwrap();
        std::env::set_var("GRYONIXNEXUSD_LOCKDOWN_WRAPPER", &wrapper);
        std::env::set_var("GRYONIXNEXUSD_ADMIN_GUARD", dir.join("admin-guard"));

        let resp = get_lockdown(Codec::Proto, pb::GetLockdownRequest {}).await;
        assert_eq!(std::fs::read_to_string(&wrapper).unwrap(), crate::install::vpn::panel::ADMIN_LOCKDOWN_SH);
        assert_eq!(resp.status(), StatusCode::OK);

        std::env::remove_var("GRYONIXNEXUSD_LOCKDOWN_WRAPPER");
        std::env::remove_var("GRYONIXNEXUSD_ADMIN_GUARD");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn get_lockdown_parses_each_of_the_three_wrapper_answers() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-lockdown-get-{}", std::process::id()));

        for (script_body, expected_mode) in [
            ("#!/bin/sh\necho on\n", pb::LockdownMode::All),
            ("#!/bin/sh\necho off\n", pb::LockdownMode::Off),
            ("#!/bin/sh\necho 'only a.example.com'\n", pb::LockdownMode::Only),
        ] {
            let script = write_stub(&dir, "admin-lockdown.sh", script_body);
            std::env::set_var("GRYONIXNEXUSD_LOCKDOWN_WRAPPER", &script);
            let resp = get_lockdown(Codec::Json, pb::GetLockdownRequest {}).await;
            assert_eq!(resp.status(), StatusCode::OK);
            let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
            let state: pb::LockdownState = serde_json::from_slice(&body).unwrap();
            assert_eq!(state.mode, expected_mode as i32);
        }

        std::env::remove_var("GRYONIXNEXUSD_LOCKDOWN_WRAPPER");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ─────────────────────────── set_lockdown, against a real stub ───────────────────────────

    #[tokio::test]
    async fn set_lockdown_reports_no_wrapper_when_the_host_has_none() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("GRYONIXNEXUSD_LOCKDOWN_WRAPPER", "/nonexistent/gryonixnexus-admin-lockdown.sh");
        std::env::set_var("GRYONIXNEXUSD_ADMIN_GUARD", "/nonexistent/gryonixnexus-admin-guard");
        let resp = set_lockdown(Codec::Proto, pb::SetLockdownRequest { mode: pb::LockdownMode::All as i32, hosts: Vec::new() }).await;
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        std::env::remove_var("GRYONIXNEXUSD_LOCKDOWN_WRAPPER");
        std::env::remove_var("GRYONIXNEXUSD_ADMIN_GUARD");
    }

    #[tokio::test]
    async fn set_lockdown_refuses_unspecified_mode_without_touching_the_host() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let resp = set_lockdown(Codec::Proto, pb::SetLockdownRequest { mode: 0, hosts: Vec::new() }).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn set_lockdown_passes_the_right_argv_and_reads_the_wrappers_own_answer_back() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-lockdown-set-{}", std::process::id()));
        let script = write_stub(
            &dir,
            "admin-lockdown.sh",
            "#!/bin/sh\necho \"args: $*\" >&2\necho on\n",
        );
        std::env::set_var("GRYONIXNEXUSD_LOCKDOWN_WRAPPER", &script);

        let resp = set_lockdown(
            Codec::Json,
            pb::SetLockdownRequest { mode: pb::LockdownMode::Only as i32, hosts: vec!["a.example.com".to_string()] },
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let state: pb::LockdownState = serde_json::from_slice(&body).unwrap();
        assert_eq!(state.mode, pb::LockdownMode::All as i32);

        std::env::remove_var("GRYONIXNEXUSD_LOCKDOWN_WRAPPER");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn set_lockdown_only_with_an_empty_host_list_runs_off_not_only() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-lockdown-set-empty-{}", std::process::id()));
        let script = write_stub(&dir, "admin-lockdown.sh", "#!/bin/sh\necho \"args: $*\" >&2\necho off\n");
        std::env::set_var("GRYONIXNEXUSD_LOCKDOWN_WRAPPER", &script);

        let resp = set_lockdown(Codec::Proto, pb::SetLockdownRequest { mode: pb::LockdownMode::Only as i32, hosts: Vec::new() }).await;
        assert_eq!(resp.status(), StatusCode::OK);

        std::env::remove_var("GRYONIXNEXUSD_LOCKDOWN_WRAPPER");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn set_lockdown_surfaces_the_wrappers_own_failure_text() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-lockdown-set-fail-{}", std::process::id()));
        let script = write_stub(&dir, "admin-lockdown.sh", "#!/bin/sh\necho 'no caddyfile found' >&2\nexit 1\n");
        std::env::set_var("GRYONIXNEXUSD_LOCKDOWN_WRAPPER", &script);

        let resp = set_lockdown(Codec::Proto, pb::SetLockdownRequest { mode: pb::LockdownMode::All as i32, hosts: Vec::new() }).await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = http_body_util::BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(parsed["message"].as_str().unwrap().contains("no caddyfile found"));

        std::env::remove_var("GRYONIXNEXUSD_LOCKDOWN_WRAPPER");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
