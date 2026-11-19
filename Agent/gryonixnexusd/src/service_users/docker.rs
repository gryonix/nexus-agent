//! One docker call whose secrets travel on its stdin

use std::process::Stdio;

use tokio::io::AsyncWriteExt;

use super::Refusal;

pub struct Call {
    pub args: Vec<String>,
    pub stdin: Option<String>,
}

impl Call {
    pub fn new(args: &[&str]) -> Call {
        Call { args: args.iter().map(|arg| arg.to_string()).collect(), stdin: None }
    }

    pub fn with_stdin(mut self, text: String) -> Call {
        self.stdin = Some(text);
        self
    }
}

pub fn refusal_of_stderr(stderr: &str) -> Refusal {
    let text = stderr.to_lowercase();
    if text.contains("is not running") || text.contains("no such container") {
        Refusal::ServiceDown
    } else {
        Refusal::Failed
    }
}

pub async fn run(call: &Call) -> Result<String, Refusal> {
    let mut child = tokio::process::Command::new("docker")
        .args(&call.args)
        .stdin(if call.stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| Refusal::ServiceDown)?;
    if let (Some(text), Some(mut pipe)) = (&call.stdin, child.stdin.take()) {
        pipe.write_all(text.as_bytes()).await.map_err(|_| Refusal::Failed)?;
        pipe.shutdown().await.map_err(|_| Refusal::Failed)?;
    }
    let output = child.wait_with_output().await.map_err(|_| Refusal::Failed)?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(refusal_of_stderr(&String::from_utf8_lossy(&output.stderr)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stopped_container_is_service_down() {
        assert_eq!(refusal_of_stderr("Error response: container x is not running"), Refusal::ServiceDown);
        assert_eq!(refusal_of_stderr("Error: No such container: x"), Refusal::ServiceDown);
        assert_eq!(refusal_of_stderr("boom"), Refusal::Failed);
    }

    #[test]
    fn stdin_is_kept_apart_from_the_arguments() {
        let call = Call::new(&["exec", "-i", "c", "tool"]).with_stdin("secret-text".into());
        assert!(call.args.iter().all(|arg| !arg.contains("secret-text")));
        assert_eq!(call.stdin.as_deref(), Some("secret-text"));
    }
}
