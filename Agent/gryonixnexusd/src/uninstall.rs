//! Removing ONE service, through the deployment's own uninstall wrapper

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::process::Stdio;
use std::time::Duration;

use bytes::Bytes;
use hyper::StatusCode;
use tokio::io::AsyncBufReadExt;
use tokio::sync::mpsc::Sender;

use crate::api::{connect_error, envelope, error_trailer, stream_response, Codec, Resp};
use crate::util::strip_ansi;
use crate::state::Store;
use crate::{discover, pb};

pub const WRAPPER_PATH: &str = "/opt/gryonixnexus-uninstall.sh";

const DONE_MARKER: &str = "GRYONIXNEXUS_UNINSTALL_DONE";

/// The wrapper's two independent purge flags
const PURGE_DATA_FLAG: &str = "--purge-data";
const PURGE_BACKUPS_FLAG: &str = "--purge-backups";

/// Deadline for one removal
const RUN_TIMEOUT_SECS: u64 = 600;

const ECHO_LIMIT: usize = 64;

#[derive(Debug, PartialEq, Eq)]
pub enum Rejection {
    UnknownService(String),
    NoWrapper,
}

impl Rejection {
    fn parts(&self) -> (StatusCode, &'static str, String) {
        match self {
            Rejection::UnknownService(id) => (
                StatusCode::BAD_REQUEST,
                "invalid_argument",
                format!("unknown service '{}'", truncate(id)),
            ),
            Rejection::NoWrapper => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "failed_precondition",
                format!(
                    "this server has no uninstall wrapper ({WRAPPER_PATH}) — re-run the setup script to install it"
                ),
            ),
        }
    }

    fn response(&self) -> Resp {
        let (status, code, message) = self.parts();
        connect_error(status, code, &message)
    }
}

fn truncate(value: &str) -> String {
    value.chars().take(ECHO_LIMIT).collect()
}

fn wrapper_path() -> PathBuf {
    PathBuf::from(std::env::var("GRYONIXNEXUSD_UNINSTALL_WRAPPER").unwrap_or_else(|_| WRAPPER_PATH.to_string()))
}

/// `systemd-run`, overridable for tests
fn systemd_run_bin() -> String {
    std::env::var("GRYONIXNEXUSD_UNINSTALL_SYSTEMD_RUN_BIN").unwrap_or_else(|_| "systemd-run".to_string())
}

/// Is that binary usable?
fn systemd_run_available(bin: &str) -> bool {
    let path = Path::new(bin);
    if path.is_absolute() {
        path.is_file()
    } else {
        crate::install::packages::have_binary(bin)
    }
}

fn wrapper_command(args: &[&str]) -> (PathBuf, Vec<String>) {
    let wrapper = wrapper_path();
    if !systemd_run_available(&systemd_run_bin()) {
        return (wrapper, args.iter().map(|a| a.to_string()).collect());
    }
    let mut argv: Vec<String> = ["--quiet", "--collect", "--wait", "--pipe", "--service-type=oneshot"]
        .iter()
        .map(|flag| flag.to_string())
        .collect();
    argv.push(wrapper.to_string_lossy().to_string());
    argv.extend(args.iter().map(|a| a.to_string()));
    (PathBuf::from(systemd_run_bin()), argv)
}

pub fn resolve(service_id: &str) -> Result<&'static str, Rejection> {
    let label =
        discover::known_service_id(service_id).ok_or_else(|| Rejection::UnknownService(service_id.to_string()))?;
    if !wrapper_path().exists() {
        return Err(Rejection::NoWrapper);
    }
    Ok(label)
}

fn build_args(label: &'static str, purge_data: bool, purge_backups: bool) -> Vec<&'static str> {
    let mut args = vec![label];
    if purge_data {
        args.push(PURGE_DATA_FLAG);
    }
    if purge_backups {
        args.push(PURGE_BACKUPS_FLAG);
    }
    args
}

async fn read_status(service_id: &str) -> Result<pb::ServiceStatusResponse, String> {
    let display = discover::known_service(service_id).unwrap_or(service_id);
    match discover::service_snapshot(service_id).await {
        Ok(Some(service)) => Ok(pb::ServiceStatusResponse {
            service: Some(service),
            installed: true,
        }),
        Ok(None) => Ok(pb::ServiceStatusResponse {
            service: Some(pb::Service {
                    installed_outside: false,
                id: service_id.to_string(),
                display_name: display.to_string(),
                status: pb::ServiceStatus::Unspecified as i32,
                version: String::new(),
                containers: Vec::new(),
            }),
            installed: false,
        }),
        Err(err) => Err(err.to_string()),
    }
}

pub async fn remove_service(codec: Codec, req: pb::RemoveServiceRequest,
                            store: Arc<Mutex<Store>>) -> Resp {
    let claim = match crate::jobs::OperationClaim::acquire("service", &req.service_id) {
        Ok(claim) => claim,
        Err(response) => return response,
    };

    let label = match resolve(&req.service_id) {
        Ok(label) => label,
        Err(rejection) => return rejection.response(),
    };
    let args = build_args(label, req.purge_data, req.purge_backups);

    let json = matches!(codec, Codec::Json);
    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(64);
    let service_id = req.service_id.clone();

    tokio::spawn(async move {
        let _claim = claim;
        run(&service_id, &args, codec, tx, store).await;
    });

    stream_response(json, rx)
}

async fn run(service_id: &str, args: &[&str], codec: Codec, tx: Sender<Bytes>,
             store: Arc<Mutex<Store>>) {
    run_with(service_id, args, codec, tx, move |id| async move {
        let status = read_status(&id).await;
        if let Ok(status) = &status {
            let service = if status.installed { status.service.as_ref() } else { None };
            if let Ok(store) = store.lock() {
                if let Err(err) = store.record_action(&id, service) {
                    tracing::warn!(?err, service_id = %id, "could not persist post-removal status");
                }
            }
        }
        status
    })
    .await;
}

async fn run_with<F, Fut>(service_id: &str, args: &[&str], codec: Codec, tx: Sender<Bytes>, status_reader: F)
where
    F: FnOnce(String) -> Fut,
    Fut: std::future::Future<Output = Result<pb::ServiceStatusResponse, String>>,
{
    let sink = EventSink {
        tx,
        codec,
        service_id: service_id.to_string(),
        journal: crate::jobs::Journal::open(pb::JobKind::Uninstall, service_id),
    };
    let _ = sink.started().await;

    let outcome = run_wrapper_streaming(args, RUN_TIMEOUT_SECS, &sink).await;
    if outcome.is_ok() {
        if let Err(why) = crate::install::execute::forget_service_sites(service_id).await {
            let _ = sink.progress("agent", format!("the web address was not fully removed: {why}")).await;
        }
        if let Err(why) = crate::install::firewall::apply_service_ports(service_id, &[]).await {
            let _ = sink.progress("agent", format!("its firewall ports were not closed: {why}")).await;
        }
        if service_id == "vpn" {
            let _ = crate::install::vpn::port_share::clear().await;
        }
        forget_in_schedules(&scheduled_ids(service_id, args.first().copied()));
    }

    let mut failure = outcome.err();
    let status = match status_reader(service_id.to_string()).await {
        Ok(status) => Some(status),
        Err(err) => {
            failure.get_or_insert_with(|| format!("could not re-read status after removal: {err}"));
            None
        }
    };
    let _ = sink.completed(status).await;
    if let Some(why) = failure {
        let _ = sink.fail(&why).await;
    }
}

const SCHEDULE_CONFIGS: [&str; 2] = ["/etc/gryonixnexus/autoupdate.conf", "/etc/gryonixnexus/autobackup.conf"];
const VPN_SCHEDULE_IDS: [&str; 5] = ["amnezia-wg", "shadowsocks", "xray-reality", "openvpn", "wireguard-vpn"];

/// The schedule names a removed service may be listed under
fn scheduled_ids<'a>(service_id: &'a str, label: Option<&'a str>) -> Vec<&'a str> {
    let mut ids = vec![service_id];
    ids.extend(label.filter(|label| *label != service_id));
    if service_id == "vpn" {
        ids.extend(VPN_SCHEDULE_IDS);
    }
    ids
}

/// Takes a removed service out of both nightly schedules
fn forget_in_schedules(gone: &[&str]) {
    for path in SCHEDULE_CONFIGS {
        let Ok(text) = std::fs::read_to_string(path) else { continue };
        if let Some(kept) = without_services(&text, gone) {
            if let Err(err) = std::fs::write(path, kept) {
                tracing::warn!(%err, path, "could not take a removed service out of the schedule");
            }
        }
    }
}

/// The config with these ids gone from SERVICES, or None
fn without_services(text: &str, gone: &[&str]) -> Option<String> {
    let mut changed = false;
    let lines: Vec<String> = text
        .lines()
        .map(|line| {
            let Some(rest) = line.strip_prefix("SERVICES=") else { return line.to_string() };
            let listed: Vec<&str> = rest.trim_matches('\'').split_whitespace().collect();
            let kept: Vec<&str> = listed.iter().copied().filter(|id| !gone.contains(id)).collect();
            if kept.len() == listed.len() {
                return line.to_string();
            }
            changed = true;
            format!("SERVICES='{}'", kept.join(" "))
        })
        .collect();
    let ending = if text.ends_with('\n') { "\n" } else { "" };
    changed.then(|| format!("{}{ending}", lines.join("\n")))
}

/// Run the wrapper, streaming every line as PROGRESS
async fn run_wrapper_streaming(args: &[&str], timeout_secs: u64, sink: &EventSink) -> Result<(), String> {
    let (program, argv) = wrapper_command(args);
    let mut child = tokio::process::Command::new(program)
        .args(&argv)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|err| format!("could not run the uninstall wrapper: {err}"))?;

    let mut out = child.stdout.take().map(|s| tokio::io::BufReader::new(s).lines());
    let mut err = child.stderr.take().map(|s| tokio::io::BufReader::new(s).lines());
    let mut stdout = String::new();
    let mut stderr = String::new();

    let outcome = tokio::time::timeout(Duration::from_secs(timeout_secs), async {
        loop {
            tokio::select! {
                line = async { out.as_mut().unwrap().next_line().await }, if out.is_some() => {
                    match line {
                        Ok(Some(text)) => {
                            let text = strip_ansi(&text);
                            stdout.push_str(&text);
                            stdout.push('\n');
                            let _ = sink.progress("stdout", text).await;
                        }
                        _ => out = None, // EOF or read error on this pipe
                    }
                }
                line = async { err.as_mut().unwrap().next_line().await }, if err.is_some() => {
                    match line {
                        Ok(Some(text)) => {
                            let text = strip_ansi(&text);
                            stderr.push_str(&text);
                            stderr.push('\n');
                            let _ = sink.progress("stderr", text).await;
                        }
                        _ => err = None,
                    }
                }
                else => break,
            }
        }
        child.wait().await
    })
    .await;

    match outcome {
        Err(_) => Err(format!("the uninstall wrapper timed out after {timeout_secs}s")),
        Ok(Err(io)) => Err(format!("the uninstall wrapper did not finish: {io}")),
        Ok(Ok(status)) if status.success() && stdout.contains(DONE_MARKER) => Ok(()),
        Ok(Ok(status)) if status.success() => {
            Err("the uninstall wrapper exited without printing the completion marker".to_string())
        }
        Ok(Ok(status)) => Err(describe_failure(status.code(), &stderr)),
    }
}

fn describe_failure(code: Option<i32>, stderr: &str) -> String {
    let detail = stderr.trim();
    let detail: String = detail.chars().rev().take(400).collect::<Vec<_>>().into_iter().rev().collect();
    match (code, detail.is_empty()) {
        (_, false) => detail,
        (Some(code), true) => format!("the uninstall wrapper exited {code}"),
        (None, true) => "the uninstall wrapper was killed by a signal".to_string(),
    }
}

/// Frames and pushes one run's events
struct EventSink {
    tx: Sender<Bytes>,
    codec: Codec,
    service_id: String,
    journal: Option<crate::jobs::Journal>,
}

impl EventSink {
    fn event(&self, phase: pb::ServiceOperationPhase) -> pb::UninstallEvent {
        pb::UninstallEvent {
            job_id: crate::jobs::id_of(&self.journal),
            phase: phase as i32,
            service_id: self.service_id.clone(),
            text: String::new(),
            stream: String::new(),
            status: None,
        }
    }

    async fn send(&self, event: pb::UninstallEvent) -> Result<(), ()> {
        crate::jobs::tee(&self.journal, event.phase, &event.stream, &event.text);
        let payload = self.codec.encode_payload(&event);
        self.tx.send(envelope(0x00, &payload)).await.map_err(|_| ())
    }

    async fn started(&self) -> Result<(), ()> {
        self.send(self.event(pb::ServiceOperationPhase::Started)).await
    }

    async fn progress(&self, stream: &str, text: String) -> Result<(), ()> {
        let mut event = self.event(pb::ServiceOperationPhase::Progress);
        event.stream = stream.to_string();
        event.text = text;
        self.send(event).await
    }

    async fn completed(&self, status: Option<pb::ServiceStatusResponse>) -> Result<(), ()> {
        let mut event = self.event(pb::ServiceOperationPhase::Completed);
        event.status = status;
        self.send(event).await
    }

    async fn fail(&self, message: &str) -> Result<(), ()> {
        crate::jobs::finish(&self.journal, Some(message));
        self.tx.send(error_trailer("internal", message)).await.map_err(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::END_OF_STREAM_FLAG;
    use prost::Message;

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

    fn decode_data_frame(bytes: &Bytes) -> pb::UninstallEvent {
        assert_eq!(bytes[0], 0x00, "expected a data frame, got flags {:#x}", bytes[0]);
        pb::UninstallEvent::decode(&bytes[5..]).expect("valid UninstallEvent frame")
    }

    fn is_trailer(bytes: &Bytes) -> bool {
        bytes[0] == END_OF_STREAM_FLAG
    }

    async fn drain(rx: &mut tokio::sync::mpsc::Receiver<Bytes>) -> Vec<Bytes> {
        let mut frames = Vec::new();
        while let Ok(frame) = rx.try_recv() {
            frames.push(frame);
        }
        frames
    }

    // ─────────────────────────── resolve / gate ───────────────────────────

    #[test]
    fn the_wrapper_escapes_the_sandbox_through_a_transient_unit_when_the_host_has_one() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-uninstall-run-{}", std::process::id()));
        let wrapper = write_stub(&dir, "uninstall.sh", "#!/bin/sh\necho done\n");
        let systemd_run = write_stub(&dir, "systemd-run", "#!/bin/sh\nexit 0\n");
        std::env::set_var("GRYONIXNEXUSD_UNINSTALL_WRAPPER", &wrapper);

        std::env::set_var("GRYONIXNEXUSD_UNINSTALL_SYSTEMD_RUN_BIN", dir.join("no-such-systemd-run"));
        let (program, argv) = wrapper_command(&["nextcloud", "--purge-data"]);
        assert_eq!(program, wrapper);
        assert_eq!(argv, vec!["nextcloud".to_string(), "--purge-data".to_string()]);

        std::env::set_var("GRYONIXNEXUSD_UNINSTALL_SYSTEMD_RUN_BIN", &systemd_run);
        let (program, argv) = wrapper_command(&["nextcloud", "--purge-data"]);
        assert_eq!(program, systemd_run);
        assert_eq!(
            argv,
            vec![
                "--quiet".to_string(),
                "--collect".to_string(),
                "--wait".to_string(),
                "--pipe".to_string(),
                "--service-type=oneshot".to_string(),
                wrapper.to_string_lossy().to_string(),
                "nextcloud".to_string(),
                "--purge-data".to_string(),
            ],
            "the wrapper and its arguments must stay LAST and in order — systemd-run \
             treats the first non-flag word as the command"
        );

        std::env::remove_var("GRYONIXNEXUSD_UNINSTALL_SYSTEMD_RUN_BIN");
        std::env::remove_var("GRYONIXNEXUSD_UNINSTALL_WRAPPER");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unknown_service_id_is_refused_before_anything_runs() {
        assert_eq!(resolve("nope"), Err(Rejection::UnknownService("nope".into())));
        assert!(matches!(
            resolve("nextcloud; rm -rf /"),
            Err(Rejection::UnknownService(_))
        ));
    }

    #[test]
    fn the_target_all_is_never_a_catalog_service_and_cannot_reach_resolve() {
        assert_eq!(resolve("--all"), Err(Rejection::UnknownService("--all".into())));
        assert_eq!(resolve("vpn --all"), Err(Rejection::UnknownService("vpn --all".into())));
    }

    #[test]
    fn the_label_that_reaches_argv_is_the_agents_own_string_not_the_requests() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-uninstall-ptr-{}", std::process::id()));
        let script = write_stub(&dir, "uninstall.sh", "#!/bin/sh\necho done\n");
        std::env::set_var("GRYONIXNEXUSD_UNINSTALL_WRAPPER", &script);

        let from_the_wire = String::from("nextcloud");
        let label = resolve(&from_the_wire).expect("a catalog id resolves");
        assert_eq!(label, "nextcloud");
        assert!(
            !std::ptr::eq(label.as_ptr(), from_the_wire.as_ptr()),
            "the wrapper label must come from the agent's table, not from the request"
        );

        std::env::remove_var("GRYONIXNEXUSD_UNINSTALL_WRAPPER");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_host_with_no_wrapper_is_told_what_to_do_and_the_unknown_id_check_comes_first() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("GRYONIXNEXUSD_UNINSTALL_WRAPPER", "/nonexistent/gryonixnexus-uninstall.sh");
        assert_eq!(resolve("nextcloud"), Err(Rejection::NoWrapper));
        assert_eq!(resolve("nope"), Err(Rejection::UnknownService("nope".into())));
        std::env::remove_var("GRYONIXNEXUSD_UNINSTALL_WRAPPER");
    }

    #[test]
    fn missing_wrapper_response_is_failed_precondition_naming_the_path() {
        let (status, code, message) = Rejection::NoWrapper.parts();
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(code, "failed_precondition");
        assert!(message.contains(WRAPPER_PATH));
        assert!(message.to_lowercase().contains("re-run"));
    }

    // ─────────────────────────── argv assembly ───────────────────────────

    #[test]
    fn purge_flags_are_independent_and_absent_by_default() {
        assert_eq!(build_args("nextcloud", false, false), vec!["nextcloud"]);
        assert_eq!(
            build_args("nextcloud", true, false),
            vec!["nextcloud", "--purge-data"]
        );
        assert_eq!(
            build_args("nextcloud", false, true),
            vec!["nextcloud", "--purge-backups"]
        );
        assert_eq!(
            build_args("nextcloud", true, true),
            vec!["nextcloud", "--purge-data", "--purge-backups"]
        );
        assert_eq!(build_args("vaultwarden", false, false).len(), 1);
    }

    #[test]
    fn the_literal_all_flag_never_appears_in_constructed_argv() {
        for id in discover::all_service_ids() {
            let label = discover::known_service_id(id).expect("catalog id");
            for purge_data in [false, true] {
                for purge_backups in [false, true] {
                    let args = build_args(label, purge_data, purge_backups);
                    assert!(
                        !args.contains(&"--all"),
                        "build_args({label}, {purge_data}, {purge_backups}) produced --all: {args:?}"
                    );
                }
            }
        }
    }

    // ─────────────────────────── wrapper plumbing ───────────────────────────

    #[tokio::test]
    async fn a_clean_removal_prints_the_marker_and_completes_with_installed_false() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-uninstall-clean-{}", std::process::id()));
        let script = write_stub(
            &dir,
            "uninstall.sh",
            "#!/bin/sh\necho 'stopping containers'\necho 'GRYONIXNEXUS_UNINSTALL_DONE'\n",
        );
        std::env::set_var("GRYONIXNEXUSD_UNINSTALL_WRAPPER", &script);

        let (tx, mut rx) = tokio::sync::mpsc::channel::<Bytes>(64);
        run_with(
            "nextcloud",
            &["nextcloud"],
            Codec::Proto,
            tx,
            |_id| async { Ok(pb::ServiceStatusResponse { service: None, installed: false }) },
        )
        .await;

        let frames = drain(&mut rx).await;
        assert!(!frames.is_empty());
        // Success ends the stream cleanly — no error trailer at all.
        assert!(frames.iter().all(|f| !is_trailer(f)), "a clean removal must not send a trailer");

        let events: Vec<_> = frames.iter().map(decode_data_frame).collect();
        assert_eq!(events.first().unwrap().phase, pb::ServiceOperationPhase::Started as i32);
        let progressed_marker = events
            .iter()
            .any(|e| e.phase == pb::ServiceOperationPhase::Progress as i32 && e.text.contains(DONE_MARKER));
        assert!(progressed_marker, "the marker line must have been streamed as progress");

        let completed = events.last().unwrap();
        assert_eq!(completed.phase, pb::ServiceOperationPhase::Completed as i32);
        let status = completed.status.as_ref().expect("completed carries a status");
        assert!(!status.installed, "a removed service must report installed = false");

        std::env::remove_var("GRYONIXNEXUSD_UNINSTALL_WRAPPER");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_failing_wrapper_completes_first_and_then_sends_an_error_trailer() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-uninstall-fail-{}", std::process::id()));
        let script = write_stub(
            &dir,
            "uninstall.sh",
            "#!/bin/sh\necho 'compose down failed' >&2\nexit 7\n",
        );
        std::env::set_var("GRYONIXNEXUSD_UNINSTALL_WRAPPER", &script);

        let (tx, mut rx) = tokio::sync::mpsc::channel::<Bytes>(64);
        run_with(
            "nextcloud",
            &["nextcloud"],
            Codec::Proto,
            tx,
            |_id| async {
                Ok(pb::ServiceStatusResponse {
                    service: Some(pb::Service {
                    installed_outside: false,
                        id: "nextcloud".to_string(),
                        display_name: "Nextcloud".to_string(),
                        status: pb::ServiceStatus::Running as i32,
                        version: String::new(),
                        containers: Vec::new(),
                    }),
                    installed: true,
                })
            },
        )
        .await;

        let frames = drain(&mut rx).await;
        assert!(frames.len() >= 2, "expected at least a COMPLETED event and a trailer");
        let (last, rest) = frames.split_last().unwrap();
        assert!(is_trailer(last), "the LAST frame must be the error trailer");
        let completed = rest
            .iter()
            .map(decode_data_frame)
            .find(|e| e.phase == pb::ServiceOperationPhase::Completed as i32)
            .expect("a COMPLETED event must precede the trailer");
        let status = completed.status.as_ref().expect("COMPLETED carries a status even on failure");
        assert!(status.installed, "the service the wrapper failed to remove is still installed");

        let payload = String::from_utf8(last[5..].to_vec()).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(parsed["error"]["code"], "internal");
        assert!(parsed["error"]["message"].as_str().unwrap().contains("compose down failed"));

        std::env::remove_var("GRYONIXNEXUSD_UNINSTALL_WRAPPER");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn exit_zero_without_the_marker_is_still_a_failure() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-uninstall-nomark-{}", std::process::id()));
        let script = write_stub(&dir, "uninstall.sh", "#!/bin/sh\necho 'nothing to do'\nexit 0\n");
        std::env::set_var("GRYONIXNEXUSD_UNINSTALL_WRAPPER", &script);

        let outcome = run_wrapper_streaming(
            &["nextcloud"],
            30,
            &EventSink {
                tx: tokio::sync::mpsc::channel(64).0,
                codec: Codec::Proto,
                service_id: "nextcloud".to_string(),
                journal: None,
            },
        )
        .await;
        assert!(outcome.is_err(), "exit 0 without the marker must not count as success");
        assert!(outcome.unwrap_err().contains("marker"));

        std::env::remove_var("GRYONIXNEXUSD_UNINSTALL_WRAPPER");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn describe_failure_prefers_the_wrappers_own_words() {
        assert_eq!(
            describe_failure(Some(2), "compose down failed\n"),
            "compose down failed"
        );
        assert_eq!(describe_failure(Some(2), "   "), "the uninstall wrapper exited 2");
        assert_eq!(describe_failure(None, ""), "the uninstall wrapper was killed by a signal");
    }

    #[test]
    fn a_removed_service_leaves_both_schedules() {
        let conf = "SCHEDULE=every:1d@04:00\nSERVICES='amnezia-wg nextcloud vaultwarden xray-reality'\n";
        assert_eq!(without_services(conf, &["vaultwarden"]).as_deref(),
                   Some("SCHEDULE=every:1d@04:00\nSERVICES='amnezia-wg nextcloud xray-reality'\n"));
        assert_eq!(without_services(conf, &["immich"]), None, "an unlisted service changes nothing");
    }

    #[test]
    fn removing_the_vpn_takes_every_protocol_with_it() {
        let ids = scheduled_ids("vpn", Some("vpn"));
        assert!(ids.contains(&"shadowsocks") && ids.contains(&"amnezia-wg"));
        let conf = "SERVICES='amnezia-wg nextcloud shadowsocks'";
        assert_eq!(without_services(conf, &ids).as_deref(), Some("SERVICES='nextcloud'"));
    }
}
