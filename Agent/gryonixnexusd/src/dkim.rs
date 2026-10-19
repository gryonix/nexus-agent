//! DKIM records for the mail engine installed on this host

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use hyper::StatusCode;

use crate::api::{connect_error, Codec, Resp};
use crate::util::strip_ansi;
use crate::{discover, pb};

struct Engine {
    service_id: &'static str,
    display_name: &'static str,
    wrapper_default: &'static str,
    wrapper_env: &'static str,
}

/// Checked in order; the first installed engine wins
const ENGINES: &[Engine] = &[
    Engine {
        service_id: "mailcow",
        display_name: "Mailcow",
        wrapper_default: "/opt/gryonixnexus-dkim.sh",
        wrapper_env: "GRYONIXNEXUSD_DKIM_WRAPPER_MAILCOW",
    },
    Engine {
        service_id: "docker-mailserver",
        display_name: "Docker Mailserver",
        wrapper_default: "/opt/gryonixnexus-dms-dkim.sh",
        wrapper_env: "GRYONIXNEXUSD_DKIM_WRAPPER_DMS",
    },
    Engine {
        service_id: "mailu",
        display_name: "Mailu",
        wrapper_default: "/opt/gryonixnexus-mailu-dkim.sh",
        wrapper_env: "GRYONIXNEXUSD_DKIM_WRAPPER_MAILU",
    },
];

const MARKER: &str = "GRYONIXNEXUS_DKIM";

const WRAPPER_TIMEOUT_SECS: u64 = 60;

const ECHO_LIMIT: usize = 200;

fn truncate(value: &str) -> String {
    value.chars().take(ECHO_LIMIT).collect()
}

fn wrapper_path(engine: &Engine) -> PathBuf {
    PathBuf::from(std::env::var(engine.wrapper_env).unwrap_or_else(|_| engine.wrapper_default.to_string()))
}

enum Rejection {
    /// No mail engine at all is installed on this host.
    NoMailEngine,
    NoWrapper(&'static Engine),
}

impl Rejection {
    fn parts(&self) -> (StatusCode, &'static str, String) {
        match self {
            Rejection::NoMailEngine => (
                StatusCode::NOT_FOUND,
                "not_found",
                "no mail engine (Mailcow, Mailu, or Docker Mailserver) is installed on this host".to_string(),
            ),
            Rejection::NoWrapper(engine) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "failed_precondition",
                format!(
                    "this server has no DKIM wrapper ({}) for {} — re-run the setup script to install it",
                    engine.wrapper_default, engine.display_name
                ),
            ),
        }
    }

    fn response(&self) -> Resp {
        let (status, code, message) = self.parts();
        connect_error(status, code, &message)
    }
}

async fn resolve_engine() -> Result<&'static Engine, Resp> {
    for engine in ENGINES {
        match discover::service_snapshot(engine.service_id).await {
            Ok(Some(_)) => return Ok(engine),
            Ok(None) => continue,
            Err(err) => {
                return Err(connect_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "unavailable",
                    &format!("container engine unavailable: {err}"),
                ))
            }
        }
    }
    Err(Rejection::NoMailEngine.response())
}

/// Run one engine's DKIM wrapper and return its stdout
async fn run_wrapper(engine: &'static Engine) -> Result<String, Resp> {
    let path = wrapper_path(engine);
    if !path.exists() {
        return Err(Rejection::NoWrapper(engine).response());
    }

    let child = tokio::process::Command::new(&path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn();
    let child = match child {
        Ok(child) => child,
        Err(err) => {
            return Err(connect_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "unavailable",
                &format!("could not run the DKIM wrapper: {err}"),
            ))
        }
    };

    let output = match tokio::time::timeout(Duration::from_secs(WRAPPER_TIMEOUT_SECS), child.wait_with_output()).await
    {
        Ok(Ok(output)) => output,
        Ok(Err(err)) => {
            return Err(connect_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "unavailable",
                &format!("the DKIM wrapper did not finish: {err}"),
            ))
        }
        Err(_) => {
            return Err(connect_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "unavailable",
                &format!("the DKIM wrapper timed out after {WRAPPER_TIMEOUT_SECS}s"),
            ))
        }
    };

    let stdout = strip_ansi(&String::from_utf8_lossy(&output.stdout));
    if !output.status.success() {
        let stderr = strip_ansi(&String::from_utf8_lossy(&output.stderr)).trim().to_string();
        let detail = if stderr.is_empty() { "the DKIM wrapper failed".to_string() } else { truncate(&stderr) };
        return Err(connect_error(StatusCode::UNPROCESSABLE_ENTITY, "failed_precondition", &detail));
    }
    Ok(stdout)
}

fn parse(output: &str) -> Vec<pb::DkimRecord> {
    let prefix = format!("{MARKER} ");
    let mut records = Vec::new();
    for line in output.split('\n') {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix(&prefix) else { continue };
        let Some(index) = rest.find(' ') else { continue };
        let name = &rest[..index];
        let value = rest[index + 1..].trim();
        if name.is_empty() || value.is_empty() {
            continue;
        }
        records.push(pb::DkimRecord { name: name.to_string(), value: value.to_string() });
    }
    records
}

fn encode<T>(codec: Codec, message: &T) -> Resp
where
    T: prost::Message + serde::Serialize,
{
    codec
        .encode(message)
        .unwrap_or_else(|err| connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string()))
}

pub async fn get_dkim_records(codec: Codec, _req: pb::GetDkimRecordsRequest) -> Resp {
    let engine = match resolve_engine().await {
        Ok(engine) => engine,
        Err(refusal) => return refusal,
    };
    match run_wrapper(engine).await {
        Ok(stdout) => encode(codec, &pb::DkimRecordList { records: parse(&stdout) }),
        Err(refusal) => refusal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static WRAPPER_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    const MAILCOW_OUTPUT: &str = "\
GRYONIXNEXUS_DKIM dkim._domainkey.example.com v=DKIM1; k=rsa; p=MIIBIjANBgkq...
GRYONIXNEXUS_DKIM_DONE
";

    #[test]
    fn a_single_domain_line_parses() {
        let records = parse(MAILCOW_OUTPUT);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].name, "dkim._domainkey.example.com");
        assert_eq!(records[0].value, "v=DKIM1; k=rsa; p=MIIBIjANBgkq...");
    }

    #[test]
    fn multiple_domains_all_parse_in_order() {
        let output = "\
GRYONIXNEXUS_DKIM dkim._domainkey.a.example.com v=DKIM1; p=aaa
GRYONIXNEXUS_DKIM dkim._domainkey.b.example.com v=DKIM1; p=bbb
GRYONIXNEXUS_DKIM_DONE
";
        let records = parse(output);
        assert_eq!(
            records.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(),
            ["dkim._domainkey.a.example.com", "dkim._domainkey.b.example.com"]
        );
    }

    #[test]
    fn the_done_marker_never_becomes_a_record() {
        assert!(parse("GRYONIXNEXUS_DKIM_DONE\n").is_empty());
    }

    #[test]
    fn a_key_not_minted_yet_is_an_empty_list_not_a_failure() {
        assert!(parse("GRYONIXNEXUS_DKIM_DONE\n").is_empty());
        assert!(parse("").is_empty());
    }

    #[test]
    fn docker_mailserver_quotes_the_value_and_that_quoting_survives_verbatim() {
        let output = "GRYONIXNEXUS_DKIM dkim._domainkey.example.com \"v=DKIM1; k=rsa; p=zzz\"\nGRYONIXNEXUS_DKIM_DONE\n";
        let records = parse(output);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].value, "\"v=DKIM1; k=rsa; p=zzz\"");
    }

    #[test]
    fn unrelated_output_lines_are_ignored() {
        let output = "some log line\nGRYONIXNEXUS_DKIM dkim._domainkey.a.com v=DKIM1\nnoise\nGRYONIXNEXUS_DKIM_DONE\n";
        let records = parse(output);
        assert_eq!(records.len(), 1);
    }

    #[test]
    fn every_engine_is_addressed_through_the_same_catalog_gate_as_everything_else() {
        for engine in ENGINES {
            assert_eq!(discover::known_service(engine.service_id), Some(engine.display_name));
        }
    }

    #[test]
    fn refusals_carry_distinct_codes() {
        let (status, code, _) = Rejection::NoMailEngine.parts();
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(code, "not_found");

        let (status, code, message) = Rejection::NoWrapper(&ENGINES[0]).parts();
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(code, "failed_precondition");
        assert!(message.contains(ENGINES[0].wrapper_default));
    }

    #[tokio::test]
    async fn a_missing_wrapper_is_refused_before_anything_runs() {
        // Held for the whole test — see WRAPPER_ENV_LOCK.
        let _guard = WRAPPER_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var(ENGINES[0].wrapper_env, "/nonexistent/gryonixnexus-dkim.sh");
        let result = run_wrapper(&ENGINES[0]).await;
        std::env::remove_var(ENGINES[0].wrapper_env);
        let Err(resp) = result else { panic!("a missing wrapper must be refused") };
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn a_wrapper_that_prints_records_is_read_back_correctly() {
        // Held for the whole test — see WRAPPER_ENV_LOCK.
        let _guard = WRAPPER_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-dkim-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("dkim.sh");
        std::fs::write(
            &script,
            "#!/bin/sh\necho 'GRYONIXNEXUS_DKIM dkim._domainkey.example.com v=DKIM1; p=abc'\necho GRYONIXNEXUS_DKIM_DONE\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        }

        std::env::set_var(ENGINES[0].wrapper_env, &script);
        let stdout = run_wrapper(&ENGINES[0]).await;
        std::env::remove_var(ENGINES[0].wrapper_env);
        let stdout = stdout.expect("the stub wrapper must run cleanly");
        let records = parse(&stdout);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].name, "dkim._domainkey.example.com");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_wrapper_that_exits_nonzero_is_reported_with_its_own_stderr() {
        // Held for the whole test — see WRAPPER_ENV_LOCK.
        let _guard = WRAPPER_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-dkim-fail-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("dkim.sh");
        std::fs::write(&script, "#!/bin/sh\necho 'no api key configured' >&2\nexit 1\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        }

        std::env::set_var(ENGINES[0].wrapper_env, &script);
        let result = run_wrapper(&ENGINES[0]).await;
        std::env::remove_var(ENGINES[0].wrapper_env);
        let Err(resp) = result else { panic!("a nonzero exit must be reported, not swallowed") };
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
