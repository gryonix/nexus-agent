//! The shared machinery behind the Containers section's destructive verbs

use std::process::Stdio;
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc::Sender;

pub(crate) struct Captured {
    pub stdout: String,
    pub stderr: String,
    pub success: bool,
}

pub(crate) async fn run_streaming(
    bin: &str,
    args: &[String],
    timeout_secs: u64,
    tx: &Sender<Bytes>,
    encode: &(dyn Fn(&'static str, String) -> Bytes + Sync),
) -> Result<(), String> {
    let mut child = Command::new(bin)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|err| format!("could not run {bin}: {err}"))?;

    let mut out = child.stdout.take().map(|s| BufReader::new(s).lines());
    let mut err = child.stderr.take().map(|s| BufReader::new(s).lines());

    let outcome = tokio::time::timeout(Duration::from_secs(timeout_secs), async {
        loop {
            tokio::select! {
                line = async { out.as_mut().unwrap().next_line().await }, if out.is_some() => {
                    match line {
                        Ok(Some(text)) => { let _ = tx.send(encode("stdout", text)).await; }
                        _ => out = None,
                    }
                }
                line = async { err.as_mut().unwrap().next_line().await }, if err.is_some() => {
                    match line {
                        Ok(Some(text)) => { let _ = tx.send(encode("stderr", text)).await; }
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
        Err(_) => Err(format!("timed out after {timeout_secs}s")),
        Ok(Err(io)) => Err(format!("{bin} did not finish: {io}")),
        Ok(Ok(status)) if status.success() => Ok(()),
        Ok(Ok(status)) => Err(match status.code() {
            Some(code) => format!("{bin} exited {code}"),
            None => format!("{bin} was killed by a signal"),
        }),
    }
}

/// Run a child and keep its output
pub(crate) async fn capture(bin: &str, args: &[String], timeout_secs: u64) -> Result<Captured, String> {
    let child = Command::new(bin)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|err| format!("could not run {bin}: {err}"))?;

    let output = tokio::time::timeout(Duration::from_secs(timeout_secs), child.wait_with_output())
        .await
        .map_err(|_| format!("{bin} timed out after {timeout_secs}s"))?
        .map_err(|err| format!("{bin} did not finish: {err}"))?;

    Ok(Captured {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        success: output.status.success(),
    })
}

pub(crate) async fn capture_to_file(
    bin: &str,
    args: &[String],
    dest: &std::path::Path,
    timeout_secs: u64,
) -> Result<u64, String> {
    use std::os::unix::fs::OpenOptionsExt;
    let partial = std::path::PathBuf::from(format!("{}.partial", dest.display()));
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&partial)
        .map_err(|err| format!("could not write {}: {err}", partial.display()))?;
    let outcome = run_into(bin, args, file, timeout_secs).await;
    let result = match outcome {
        Ok(()) => std::fs::rename(&partial, dest)
            .map_err(|err| format!("could not write {}: {err}", dest.display()))
            .and_then(|()| {
                std::fs::metadata(dest).map(|meta| meta.len()).map_err(|err| format!("could not read {}: {err}", dest.display()))
            }),
        Err(why) => Err(why),
    };
    if result.is_err() {
        let _ = std::fs::remove_file(&partial);
    }
    result
}

async fn run_into(bin: &str, args: &[String], file: std::fs::File, timeout_secs: u64) -> Result<(), String> {
    let child = Command::new(bin)
        .args(args)
        .stdout(Stdio::from(file))
        .stderr(Stdio::piped())
        .stdin(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|err| format!("could not run {bin}: {err}"))?;
    let output = tokio::time::timeout(Duration::from_secs(timeout_secs), child.wait_with_output())
        .await
        .map_err(|_| format!("{bin} timed out after {timeout_secs}s"))?
        .map_err(|err| format!("{bin} did not finish: {err}"))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let why = stderr.trim();
    Err(first_lines(if why.is_empty() { "no output" } else { why }, 3))
}

pub(crate) fn first_lines(text: &str, n: usize) -> String {
    text.lines().take(n).collect::<Vec<_>>().join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn capture_keeps_the_two_streams_apart() {
        let out = capture("sh", &["-c".into(), "echo mine; echo theirs 1>&2".into()], 10)
            .await
            .expect("sh runs");
        assert!(out.success);
        assert_eq!(out.stdout.trim(), "mine");
        assert_eq!(out.stderr.trim(), "theirs");
    }

    #[tokio::test]
    async fn a_failed_capture_writes_no_file() {
        let dir = std::env::temp_dir().join(format!("gdc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dest = dir.join("dump.sql");
        let _ = std::fs::remove_file(&dest);

        let err = capture_to_file("sh", &["-c".into(), "echo boom 1>&2; exit 1".into()], &dest, 10)
            .await
            .expect_err("a failing command is an error");
        assert!(err.contains("boom"), "{err}");
        assert!(!dest.exists(), "a failed dump must not leave a file behind");

        // ...and a succeeding one does write.
        capture_to_file("sh", &["-c".into(), "echo rows".into()], &dest, 10).await.expect("writes");
        assert_eq!(std::fs::read_to_string(&dest).unwrap().trim(), "rows");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_dump_with_bytes_that_are_not_utf8_comes_back_exact() {
        let dir = std::env::temp_dir().join(format!("gdc-bin-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dest = dir.join("dump.bin");
        let size = capture_to_file("sh", &["-c".into(), "printf 'PG\\377\\376\\000end'".into()], &dest, 10)
            .await
            .expect("writes");
        assert_eq!(std::fs::read(&dest).unwrap(), b"PG\xff\xfe\x00end");
        assert_eq!(size, 8);
        assert!(!dir.join("dump.bin.partial").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn streaming_forwards_both_pipes_and_reports_the_exit_status() {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Bytes>(64);
        let encode = |stream: &'static str, text: String| Bytes::from(format!("{stream}:{text}"));
        let err = run_streaming("sh", &["-c".into(), "echo a; echo b 1>&2; exit 3".into()], 10, &tx, &encode)
            .await
            .expect_err("exit 3 is a failure");
        assert!(err.contains("exited 3"), "{err}");
        drop(tx);

        let mut seen = Vec::new();
        while let Some(frame) = rx.recv().await {
            seen.push(String::from_utf8_lossy(&frame).into_owned());
        }
        assert!(seen.contains(&"stdout:a".to_string()), "{seen:?}");
        assert!(seen.contains(&"stderr:b".to_string()), "{seen:?}");
    }
}
