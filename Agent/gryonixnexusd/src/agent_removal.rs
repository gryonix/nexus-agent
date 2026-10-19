//! Takes the agent off the host and keeps everything it looked after

use hyper::StatusCode;

use crate::api::{connect_error, Codec, Resp};
use crate::pb;

const UNIT: &str = "gryonixnexus-agent-removal";

/// The shell steps, run after the answer went out
pub fn script() -> String {
    [
        "sleep 2",
        "systemctl disable --now gryonixnexusd.service >/dev/null 2>&1 || true",
        "rm -f /etc/systemd/system/gryonixnexusd.service",
        "systemctl daemon-reload || true",
        "rm -f /usr/local/bin/gryonixnexusd /run/gryonixnexusd.sock",
        "rm -rf /opt/gryonixnexus-agent-src",
    ]
    .join("\n")
}

fn systemd_run_bin() -> String {
    std::env::var("GRYONIXNEXUSD_REMOVAL_SYSTEMD_RUN_BIN").unwrap_or_else(|_| "systemd-run".to_string())
}

pub async fn remove(codec: Codec) -> Resp {
    let unit = format!("--unit={UNIT}");
    let started = tokio::process::Command::new(systemd_run_bin())
        .args(["--quiet", "--collect", &unit, "--service-type=oneshot", "/bin/bash", "-c", &script()])
        .stdin(std::process::Stdio::null())
        .status()
        .await;
    match started {
        Ok(status) if status.success() => {
            tracing::info!("agent removal scheduled; state directory kept");
            codec
                .encode(&pb::RemoveAgentResponse { scheduled: true })
                .unwrap_or_else(|err| connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string()))
        }
        Ok(status) => connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &format!("systemd-run failed: {status}")),
        Err(err) => connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &format!("systemd-run: {err}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_removal_keeps_state_and_services() {
        let text = script();
        assert!(text.contains("disable --now gryonixnexusd.service"));
        assert!(text.contains("rm -f /usr/local/bin/gryonixnexusd"));
        for kept in ["/var/lib/gryonixnexus", "caddy", "mdns", "docker", "sudoers", "nftables", "bootstrap"] {
            assert!(!text.contains(kept), "the removal touches {kept}");
        }
    }
}
