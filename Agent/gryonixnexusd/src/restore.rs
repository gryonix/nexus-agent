use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use bytes::Bytes;
use hyper::StatusCode;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::sync::mpsc::Sender;

use crate::api::{connect_error, envelope, error_trailer, stream_response, Codec, Resp};
use crate::backup::wrapper_home;
use crate::util::strip_ansi;
use crate::{backup, discover, pb};

const WRAPPER_PATH: &str = "/opt/gryonixnexus-restore.sh";

const DONE_MARKER: &str = "GRYONIXNEXUS_RESTORE_DONE";

const RUN_TIMEOUT_SECS: u64 = 4 * 3600;

const ECHO_LIMIT: usize = 96;

#[derive(Debug, PartialEq, Eq)]
pub enum Rejection {
    UnknownService(String),
    NoWrapper,
    /// No archive named at all
    NoArchive,
    MalformedArchive(String),
}

impl Rejection {
    fn parts(&self) -> (StatusCode, &'static str, String) {
        match self {
            Rejection::UnknownService(id) => (
                StatusCode::BAD_REQUEST,
                "invalid_argument",
                format!("unknown service '{}'", truncate(id)),
            ),
            Rejection::MalformedArchive(path) => (
                StatusCode::BAD_REQUEST,
                "invalid_argument",
                format!(
                    "'{}' is not an archive path — it must be absolute and must not contain '..'",
                    truncate(path)
                ),
            ),
            Rejection::NoArchive => (
                StatusCode::BAD_REQUEST,
                "invalid_argument",
                "no archive named — archive_path must be one of the paths ListBackups returned \
                 for this service"
                    .to_string(),
            ),
            Rejection::NoWrapper => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "failed_precondition",
                format!(
                    "this server has no restore wrapper ({WRAPPER_PATH}) — re-run the setup script to install it"
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
    PathBuf::from(std::env::var("GRYONIXNEXUSD_RESTORE_WRAPPER").unwrap_or_else(|_| WRAPPER_PATH.to_string()))
}

pub fn resolve(service_id: &str) -> Result<&'static str, Rejection> {
    let label =
        backup::wrapper_target(service_id).ok_or_else(|| Rejection::UnknownService(service_id.to_string()))?;
    if !wrapper_path().exists() {
        return Err(Rejection::NoWrapper);
    }
    Ok(label)
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

fn malformed_archive_path(path: &str) -> Option<Rejection> {
    if !path.starts_with('/') || path.contains("..") {
        return Some(Rejection::MalformedArchive(path.to_string()));
    }
    None
}

pub async fn run_restore(codec: Codec, req: pb::RunRestoreRequest) -> Resp {
    let claim = match crate::jobs::OperationClaim::acquire("service", &req.service_id) {
        Ok(claim) => claim,
        Err(response) => return response,
    };

    if req.archive_path.trim().is_empty() {
        return Rejection::NoArchive.response();
    }
    if let Some(rejection) = malformed_archive_path(req.archive_path.trim()) {
        return rejection.response();
    }
    let label = match resolve(&req.service_id) {
        Ok(label) => label,
        Err(rejection) => return rejection.response(),
    };
    let args = vec![label.to_string(), req.archive_path.clone()];

    let json = matches!(codec, Codec::Json);
    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(64);
    let service_id = req.service_id.clone();
    let passphrase = req.passphrase.clone();

    tokio::spawn(async move {
        let _claim = claim;
        run(&service_id, &args, &passphrase, codec, tx).await;
    });

    stream_response(json, rx)
}

async fn run(service_id: &str, args: &[String], passphrase: &str, codec: Codec, tx: Sender<Bytes>) {
    run_with(service_id, args, passphrase, codec, tx, |id| async move { read_status(&id).await }).await;
}

async fn run_with<F, Fut>(
    service_id: &str,
    args: &[String],
    passphrase: &str,
    codec: Codec,
    tx: Sender<Bytes>,
    status_reader: F,
) where
    F: FnOnce(String) -> Fut,
    Fut: std::future::Future<Output = Result<pb::ServiceStatusResponse, String>>,
{
    let sink = EventSink {
        tx,
        codec,
        service_id: service_id.to_string(),
        journal: crate::jobs::Journal::open(pb::JobKind::Restore, service_id),
    };
    let _ = sink.started().await;

    let outcome = run_wrapper_streaming(args, passphrase, RUN_TIMEOUT_SECS, &sink).await;

    let mut failure = outcome.err();
    let status = match status_reader(service_id.to_string()).await {
        Ok(status) => Some(status),
        Err(err) => {
            failure.get_or_insert_with(|| format!("could not re-read status after restore: {err}"));
            None
        }
    };
    let _ = sink.completed(status).await;
    if let Some(why) = failure {
        let _ = sink.fail(&why).await;
    }
}

async fn run_wrapper_streaming(args: &[String], passphrase: &str, timeout_secs: u64, sink: &EventSink) -> Result<(), String> {
    let home = wrapper_home();
    let mut child = tokio::process::Command::new(wrapper_path())
        .args(args)
        .env("HOME", &home)
        .env("GNUPGHOME", home.join(".gnupg"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|err| format!("could not run the restore wrapper: {err}"))?;

    feed_passphrase(&mut child, passphrase).await;

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
                        _ => out = None,
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

    wrapper_verdict(outcome, timeout_secs, &stdout, &stderr)
}

async fn feed_passphrase(child: &mut tokio::process::Child, passphrase: &str) {
    if let Some(mut stdin) = child.stdin.take() {
        if !passphrase.is_empty() {
            let _ = stdin.write_all(passphrase.as_bytes()).await;
        }
        let _ = stdin.shutdown().await;
        drop(stdin);
    }
}

/// What the wrapper's end says about the run
fn wrapper_verdict(
    outcome: Result<std::io::Result<std::process::ExitStatus>, tokio::time::error::Elapsed>,
    timeout_secs: u64,
    stdout: &str,
    stderr: &str,
) -> Result<(), String> {
    match outcome {
        Err(_) => Err(format!("the restore wrapper timed out after {timeout_secs}s")),
        Ok(Err(io)) => Err(format!("the restore wrapper did not finish: {io}")),
        Ok(Ok(status)) if status.success() && stdout.contains(DONE_MARKER) => Ok(()),
        Ok(Ok(status)) if status.success() => {
            Err("the restore wrapper exited without printing the completion marker".to_string())
        }
        Ok(Ok(status)) => Err(describe_failure(status.code(), stderr)),
    }
}

fn describe_failure(code: Option<i32>, stderr: &str) -> String {
    let detail = stderr.trim();
    let detail: String = detail.chars().rev().take(400).collect::<Vec<_>>().into_iter().rev().collect();
    match (code, detail.is_empty()) {
        (_, false) => detail,
        (Some(code), true) => format!("the restore wrapper exited {code}"),
        (None, true) => "the restore wrapper was killed by a signal".to_string(),
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
    fn event(&self, phase: pb::ServiceOperationPhase) -> pb::RestoreEvent {
        pb::RestoreEvent {
            job_id: crate::jobs::id_of(&self.journal),
            phase: phase as i32,
            service_id: self.service_id.clone(),
            text: String::new(),
            stream: String::new(),
            status: None,
        }
    }

    async fn send(&self, event: pb::RestoreEvent) -> Result<(), ()> {
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

    fn decode_data_frame(bytes: &Bytes) -> pb::RestoreEvent {
        assert_eq!(bytes[0], 0x00, "expected a data frame, got flags {:#x}", bytes[0]);
        pb::RestoreEvent::decode(&bytes[5..]).expect("valid RestoreEvent frame")
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

    fn stub_status(installed: bool) -> impl FnOnce(String) -> std::future::Ready<Result<pb::ServiceStatusResponse, String>> {
        move |_id| {
            std::future::ready(Ok(pb::ServiceStatusResponse {
                service: Some(pb::Service {
                    installed_outside: false,
                    id: "nextcloud".to_string(),
                    display_name: "Nextcloud".to_string(),
                    status: if installed { pb::ServiceStatus::Running as i32 } else { pb::ServiceStatus::Unspecified as i32 },
                    version: String::new(),
                    containers: Vec::new(),
                }),
                installed,
            }))
        }
    }

    #[test]
    fn a_path_that_is_wrong_on_every_machine_is_refused_by_shape() {
        for bad in ["relative/path.tar.gz", "/opt/backups/x/../../etc/passwd", ".."] {
            let rejection = malformed_archive_path(bad);
            assert!(rejection.is_some(), "{bad} should be refused by shape");
            let (status, code, _) = rejection.unwrap().parts();
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(code, "invalid_argument", "a caller's path is not a server fault");
        }
        assert!(malformed_archive_path("/etc/shadow").is_none());
        assert!(malformed_archive_path("/opt/backups/open-webui/x.tar.gz.gpg").is_none());
    }

    #[test]
    fn an_empty_archive_path_is_refused_by_its_own_name() {
        let (status, code, message) = Rejection::NoArchive.parts();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(code, "invalid_argument");
        assert!(message.contains("no archive named"), "{message}");
        // And it must not repeat the wrapper's misleading wording.
        assert!(!message.contains("outside the backup directories"), "{message}");
    }

    #[tokio::test]
    async fn run_restore_refuses_a_request_with_no_archive() {
        let request = pb::RunRestoreRequest {
            service_id: "vaultwarden".to_string(),
            archive_path: "   ".to_string(),
            passphrase: String::new(),
        };
        let response = run_restore(Codec::Json, request).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn resolve_rejects_a_service_the_agent_does_not_know() {
        assert_eq!(
            resolve("not-a-real-service"),
            Err(Rejection::UnknownService("not-a-real-service".to_string()))
        );
    }

    #[test]
    fn resolve_maps_the_vpn_aggregate_to_the_panel_label_like_backup_does() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("restore-test-vpn-{}", std::process::id()));
        let script = write_stub(&dir, "restore.sh", "#!/bin/bash\ntrue\n");
        std::env::set_var("GRYONIXNEXUSD_RESTORE_WRAPPER", &script);
        let result = resolve("vpn");
        std::env::remove_var("GRYONIXNEXUSD_RESTORE_WRAPPER");
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(result, Ok("vpn-panel"));
    }

    #[test]
    fn resolve_reports_a_missing_wrapper_by_name_not_as_unknown_service() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("GRYONIXNEXUSD_RESTORE_WRAPPER", "/nonexistent/gryonixnexus-restore.sh");
        let result = resolve("nextcloud");
        std::env::remove_var("GRYONIXNEXUSD_RESTORE_WRAPPER");
        assert_eq!(result, Err(Rejection::NoWrapper));
    }

    #[tokio::test]
    async fn a_successful_restore_streams_started_progress_completed_and_ends_cleanly() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("restore-test-ok-{}", std::process::id()));
        let script = write_stub(
            &dir,
            "restore.sh",
            "#!/bin/bash\necho \"restoring $1 from $2\"\necho GRYONIXNEXUS_RESTORE_DONE\n",
        );
        std::env::set_var("GRYONIXNEXUSD_RESTORE_WRAPPER", &script);

        let (tx, mut rx) = tokio::sync::mpsc::channel::<Bytes>(16);
        run_with(
            "nextcloud",
            &["nextcloud".to_string(), "/opt/backups/nextcloud/2026.tar.gz".to_string()],
            "",
            Codec::Proto,
            tx,
            stub_status(true),
        )
        .await;

        std::env::remove_var("GRYONIXNEXUSD_RESTORE_WRAPPER");
        let _ = std::fs::remove_dir_all(&dir);

        let frames = drain(&mut rx).await;
        assert!(frames.iter().all(|f| !is_trailer(f)), "a clean restore must not send a trailer");
        let events: Vec<_> = frames.iter().map(decode_data_frame).collect();

        assert_eq!(events.first().unwrap().phase, pb::ServiceOperationPhase::Started as i32);
        assert!(events
            .iter()
            .any(|e| e.phase == pb::ServiceOperationPhase::Progress as i32
                && e.text.contains("restoring nextcloud from /opt/backups/nextcloud/2026.tar.gz")));
        let progressed_marker = events
            .iter()
            .any(|e| e.phase == pb::ServiceOperationPhase::Progress as i32 && e.text.contains(DONE_MARKER));
        assert!(progressed_marker, "the marker line must have been streamed as progress");
        let completed = events.last().unwrap();
        assert_eq!(completed.phase, pb::ServiceOperationPhase::Completed as i32);
        assert!(completed.status.is_some());
    }

    #[tokio::test]
    async fn the_passphrase_never_appears_in_the_wrappers_arguments() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("restore-test-argv-{}", std::process::id()));
        let script = write_stub(
            &dir,
            "restore.sh",
            "#!/bin/bash\necho \"args: $*\"\nread -r fed\necho \"stdin: $fed\"\necho GRYONIXNEXUS_RESTORE_DONE\n",
        );
        std::env::set_var("GRYONIXNEXUSD_RESTORE_WRAPPER", &script);

        let (tx, mut rx) = tokio::sync::mpsc::channel::<Bytes>(16);
        run_with(
            "vaultwarden",
            &["vaultwarden".to_string(), "/opt/backups/vaultwarden/2026.tar.gz.gpg".to_string()],
            "hunter2-the-secret-phrase",
            Codec::Proto,
            tx,
            stub_status(true),
        )
        .await;

        std::env::remove_var("GRYONIXNEXUSD_RESTORE_WRAPPER");
        let _ = std::fs::remove_dir_all(&dir);

        let frames = drain(&mut rx).await;
        let mut lines = String::new();
        for frame in &frames {
            if is_trailer(frame) {
                continue;
            }
            let event = decode_data_frame(frame);
            lines.push_str(&event.text);
            lines.push('\n');
        }

        let args_line = lines.lines().find(|l| l.starts_with("args:")).expect("wrapper echoed its argv");
        assert_eq!(args_line, "args: vaultwarden /opt/backups/vaultwarden/2026.tar.gz.gpg");
        assert!(!args_line.contains("hunter2-the-secret-phrase"), "the passphrase leaked into argv");
        let stdin_line = lines.lines().find(|l| l.starts_with("stdin:")).expect("wrapper echoed its stdin");
        assert_eq!(stdin_line, "stdin: hunter2-the-secret-phrase", "the passphrase must arrive on stdin");
    }

    #[tokio::test]
    async fn an_empty_passphrase_still_closes_stdin_instead_of_hanging() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("restore-test-noargv-{}", std::process::id()));
        let script = write_stub(
            &dir,
            "restore.sh",
            "#!/bin/bash\ncat >/dev/null\necho GRYONIXNEXUS_RESTORE_DONE\n",
        );
        std::env::set_var("GRYONIXNEXUSD_RESTORE_WRAPPER", &script);

        let (tx, mut rx) = tokio::sync::mpsc::channel::<Bytes>(16);
        let outcome = tokio::time::timeout(
            Duration::from_secs(10),
            run_with(
                "nextcloud",
                &["nextcloud".to_string(), "/opt/backups/nextcloud/plain.tar.gz".to_string()],
                "",
                Codec::Proto,
                tx,
                stub_status(true),
            ),
        )
        .await;

        std::env::remove_var("GRYONIXNEXUSD_RESTORE_WRAPPER");
        let _ = std::fs::remove_dir_all(&dir);

        assert!(outcome.is_ok(), "an unclosed stdin pipe hung the run");
        let frames = drain(&mut rx).await;
        assert!(frames.iter().all(|f| !is_trailer(f)), "closing stdin with no passphrase must still succeed");
    }

    #[tokio::test]
    async fn a_wrapper_that_exits_zero_without_the_marker_is_reported_as_a_failure() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("restore-test-nomarker-{}", std::process::id()));
        let script = write_stub(&dir, "restore.sh", "#!/bin/bash\necho short-circuited\n");
        std::env::set_var("GRYONIXNEXUSD_RESTORE_WRAPPER", &script);

        let (tx, mut rx) = tokio::sync::mpsc::channel::<Bytes>(16);
        run_with(
            "nextcloud",
            &["nextcloud".to_string(), "/opt/backups/nextcloud/x.tar.gz".to_string()],
            "",
            Codec::Proto,
            tx,
            stub_status(true),
        )
        .await;

        std::env::remove_var("GRYONIXNEXUSD_RESTORE_WRAPPER");
        let _ = std::fs::remove_dir_all(&dir);

        let frames = drain(&mut rx).await;
        assert!(frames.len() >= 2, "expected at least a COMPLETED event and a trailer");
        let (last, rest) = frames.split_last().unwrap();
        assert!(is_trailer(last), "the LAST frame must be the error trailer");
        let completed = rest
            .iter()
            .map(decode_data_frame)
            .find(|e| e.phase == pb::ServiceOperationPhase::Completed as i32)
            .expect("a COMPLETED event must precede the trailer");
        assert!(completed.status.is_some(), "COMPLETED must carry a status even on failure");
    }

    #[tokio::test]
    async fn a_wrapper_that_exits_nonzero_reports_its_stderr() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("restore-test-fail-{}", std::process::id()));
        let script = write_stub(
            &dir,
            "restore.sh",
            "#!/bin/bash\necho 'the backup archive is not readable' >&2\nexit 1\n",
        );
        std::env::set_var("GRYONIXNEXUSD_RESTORE_WRAPPER", &script);

        let (tx, mut rx) = tokio::sync::mpsc::channel::<Bytes>(16);
        run_with(
            "nextcloud",
            &["nextcloud".to_string(), "/opt/backups/nextcloud/corrupt.tar.gz".to_string()],
            "",
            Codec::Proto,
            tx,
            stub_status(true),
        )
        .await;

        std::env::remove_var("GRYONIXNEXUSD_RESTORE_WRAPPER");
        let _ = std::fs::remove_dir_all(&dir);

        let frames = drain(&mut rx).await;
        let last = frames.last().unwrap();
        assert!(is_trailer(last), "a nonzero exit must end in an error trailer");
        let trailer = String::from_utf8_lossy(&last[5..]);
        assert!(
            trailer.contains("the backup archive is not readable"),
            "the wrapper's own words are the explanation, not a generic failure message: {trailer}"
        );
    }
}
