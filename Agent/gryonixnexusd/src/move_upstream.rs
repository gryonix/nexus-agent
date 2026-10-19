//! The front machine's half of a service move: pointing the service's
//! Caddy site at the machine that runs it, and asking the site if it answers.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use hyper::StatusCode;

use crate::api::{connect_error, Codec, Resp};
use crate::install::caddy_upstream::{self as upstream, LocalProxy, Upstream, UpstreamError};
use crate::{discover, pb};

const CADDYFILE_ENV: &str = "GRYONIXNEXUSD_CADDYFILE";
const CADDYFILE_FALLBACK: &str = "/etc/caddy/Caddyfile";
const SYSTEMCTL_ENV: &str = "GRYONIXNEXUSD_INSTALL_SYSTEMCTL_BIN";
const CADDY_ENV: &str = "GRYONIXNEXUSD_MOVE_CADDY";
const CURL_ENV: &str = "GRYONIXNEXUSD_MOVE_CURL";
const PROBE_DELAY_ENV: &str = "GRYONIXNEXUSD_MOVE_PROBE_DELAY_MS";
const PROBE_ATTEMPTS: u32 = 6;
const PROBE_DEFAULT_DELAY_MS: u64 = 5000;
const PREVIOUS_SUFFIX: &str = ".gryonixnexus-previous";

fn caddyfile_path() -> PathBuf {
    PathBuf::from(std::env::var(CADDYFILE_ENV).unwrap_or_else(|_| CADDYFILE_FALLBACK.to_string()))
}

fn bin(env: &str, fallback: &str) -> String {
    std::env::var(env).unwrap_or_else(|_| fallback.to_string())
}

fn refuse(message: &str) -> Resp {
    connect_error(StatusCode::BAD_REQUEST, "invalid_argument", message)
}

fn precondition(message: &str) -> Resp {
    connect_error(StatusCode::UNPROCESSABLE_ENTITY, "failed_precondition", message)
}

fn encode<T>(codec: Codec, message: &T) -> Resp
where
    T: prost::Message + serde::Serialize,
{
    codec.encode(message).unwrap_or_else(|err| connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string()))
}

fn state_of(found: Result<Upstream, UpstreamError>, changed: bool) -> pb::ServiceUpstreamState {
    let (current, remote_address) = match found {
        Ok(Upstream::Local) => ("local", String::new()),
        Ok(Upstream::Remote { address, .. }) => ("remote", address),
        Err(UpstreamError::NoSite) => ("missing", String::new()),
        Err(_) => ("unknown", String::new()),
    };
    pb::ServiceUpstreamState { current: current.to_string(), remote_address, changed }
}

fn local_proxy(req: &pb::SetServiceUpstreamRequest) -> Option<LocalProxy> {
    let port = u16::try_from(req.local_port).ok().filter(|p| *p != 0)?;
    Some(LocalProxy { port, https: req.local_https, overwrite_forwarded_for: req.overwrite_forwarded_for })
}

pub async fn set_upstream(codec: Codec, req: pb::SetServiceUpstreamRequest) -> Resp {
    let Some(owner) = discover::known_service_id(&req.service_id) else {
        return refuse("unknown service");
    };
    let Some(local) = local_proxy(&req) else { return refuse("the service's local port is missing") };
    let path = caddyfile_path();
    let Ok(text) = std::fs::read_to_string(&path) else {
        return precondition("this machine has no Caddyfile");
    };
    if req.dry_run {
        return encode(codec, &state_of(upstream::current(&text, owner, &local), false));
    }
    let target = match req.remote_address.trim() {
        "" => Upstream::Local,
        address => Upstream::Remote { address: address.to_string(), port: upstream::remote_port(req.remote_port) },
    };
    match upstream::with_upstream(&text, owner, &local, &target) {
        Err(why) => precondition(&why.message()),
        Ok(None) => encode(codec, &state_of(upstream::current(&text, owner, &local), false)),
        Ok(Some(changed)) => match apply(&path, &text, &changed).await {
            Ok(()) => encode(codec, &state_of(upstream::current(&changed, owner, &local), true)),
            Err(why) => precondition(&why),
        },
    }
}

async fn run_ok(program: &str, args: &[&str]) -> Result<bool, std::io::Error> {
    let status = tokio::process::Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await?;
    Ok(status.success())
}

async fn caddy_accepts(path: &std::path::Path) -> bool {
    let file = path.to_string_lossy().to_string();
    let validated = tokio::process::Command::new(bin(CADDY_ENV, "caddy"))
        .args(["validate", "--config", &file, "--adapter", "caddyfile"])
        .envs(crate::install::caddy_check::cli_env())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map(|status| status.success());
    match validated {
        Ok(accepted) => accepted,
        Err(err) => err.kind() == std::io::ErrorKind::NotFound,
    }
}

async fn reload_caddy() -> bool {
    run_ok(&bin(SYSTEMCTL_ENV, "systemctl"), &["reload", "caddy"]).await.unwrap_or(false)
}

async fn apply(path: &std::path::Path, before: &str, after: &str) -> Result<(), String> {
    let previous = PathBuf::from(format!("{}{PREVIOUS_SUFFIX}", path.display()));
    std::fs::write(&previous, before).map_err(|e| format!("could not keep the previous Caddyfile: {e}"))?;
    std::fs::write(path, after).map_err(|e| format!("could not write the Caddyfile: {e}"))?;
    if !caddy_accepts(path).await {
        std::fs::write(path, before).map_err(|e| format!("Caddy refused the site and the Caddyfile could not be put back: {e}"))?;
        return Err("Caddy refused the new site, so the previous one was put back".to_string());
    }
    if !reload_caddy().await {
        std::fs::write(path, before).map_err(|e| format!("Caddy did not reload and the Caddyfile could not be put back: {e}"))?;
        let _ = reload_caddy().await;
        return Err("Caddy did not take the new site, so the previous one was put back".to_string());
    }
    let _ = std::fs::remove_file(previous);
    Ok(())
}

pub async fn probe_upstream(codec: Codec, req: pb::ProbeServiceUpstreamRequest) -> Resp {
    let Some(owner) = discover::known_service_id(&req.service_id) else {
        return refuse("unknown service");
    };
    let text = std::fs::read_to_string(caddyfile_path()).unwrap_or_default();
    let Some(name) = upstream::site_name(&text, owner) else {
        return precondition("this machine has no site for the service");
    };
    let delay = Duration::from_millis(
        std::env::var(PROBE_DELAY_ENV).ok().and_then(|v| v.parse().ok()).unwrap_or(PROBE_DEFAULT_DELAY_MS),
    );
    encode(codec, &probe(&name, delay).await)
}

fn answered(status: i32) -> bool {
    (100..500).contains(&status)
}

async fn probe(name: &str, delay: Duration) -> pb::ServiceUpstreamProbe {
    let mut last = 0;
    for attempt in 0..PROBE_ATTEMPTS {
        match ask_site(name).await {
            Err(unavailable) => return pb::ServiceUpstreamProbe { unavailable: true, detail: unavailable, ..Default::default() },
            Ok(status) if answered(status) => {
                return pb::ServiceUpstreamProbe { answered: true, status, ..Default::default() };
            }
            Ok(status) => last = status,
        }
        if attempt + 1 < PROBE_ATTEMPTS {
            tokio::time::sleep(delay).await;
        }
    }
    pb::ServiceUpstreamProbe { status: last, detail: format!("{name} answered {last}, not an application answer"), ..Default::default() }
}

async fn ask_site(name: &str) -> Result<i32, String> {
    let resolve = format!("{name}:443:127.0.0.1");
    let url = format!("https://{name}/");
    let output = tokio::process::Command::new(bin(CURL_ENV, "curl"))
        .args(["-sS", "-k", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "15", "--resolve", &resolve, &url])
        .stdin(Stdio::null())
        .output()
        .await
        .map_err(|e| format!("curl could not run: {e}"))?;
    let text = String::from_utf8_lossy(&output.stdout);
    Ok(text.trim().parse().unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::install::caddy::site;
    use crate::util::STATE_DIR_ENV_LOCK;
    use std::os::unix::fs::PermissionsExt;

    fn rig(tag: &str, caddyfile: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("gnx-up-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("Caddyfile"), caddyfile).unwrap();
        std::env::set_var(CADDYFILE_ENV, root.join("Caddyfile"));
        root
    }

    fn script(root: &std::path::Path, name: &str, body: &str) -> PathBuf {
        let path = root.join(name);
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    fn cleanup() {
        for var in [CADDYFILE_ENV, SYSTEMCTL_ENV, CADDY_ENV, CURL_ENV, PROBE_DELAY_ENV] {
            std::env::remove_var(var);
        }
    }

    async fn text(resp: Resp) -> (StatusCode, String) {
        use http_body_util::BodyExt;
        let status = resp.status();
        (status, String::from_utf8_lossy(&resp.into_body().collect().await.unwrap().to_bytes()).to_string())
    }

    fn request(address: &str, dry_run: bool) -> pb::SetServiceUpstreamRequest {
        pb::SetServiceUpstreamRequest {
            service_id: "vaultwarden".into(),
            local_port: 8222,
            remote_address: address.into(),
            dry_run,
            ..Default::default()
        }
    }

    fn vault() -> String {
        site("vaultwarden", "vault.example.com", 8222, false, false, false)
    }

    #[tokio::test]
    async fn a_site_is_pointed_at_another_machine_and_caddy_is_reloaded() {
        let _guard = STATE_DIR_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = rig("move", &vault());
        let log = root.join("reload.log");
        std::env::set_var(SYSTEMCTL_ENV, script(&root, "systemctl.sh", &format!("#!/bin/sh\necho \"$@\" >> '{}'\n", log.display())));
        std::env::set_var(CADDY_ENV, script(&root, "caddy.sh", "#!/bin/sh\nexit 0\n"));
        let (status, body) = text(set_upstream(Codec::Json, request("10.8.0.5", false)).await).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.contains("\"remote\"") && body.contains("10.8.0.5") && body.contains("true"), "{body}");
        let written = std::fs::read_to_string(root.join("Caddyfile")).unwrap();
        assert!(written.contains("reverse_proxy https://10.8.0.5:443 {"));
        assert_eq!(std::fs::read_to_string(&log).unwrap().trim(), "reload caddy");
        let (_, back) = text(set_upstream(Codec::Json, request("", false)).await).await;
        assert!(back.contains("\"local\""), "{back}");
        assert_eq!(std::fs::read_to_string(root.join("Caddyfile")).unwrap(), vault());
        cleanup();
    }

    #[tokio::test]
    async fn a_dry_run_only_reports_and_a_repeat_changes_nothing() {
        let _guard = STATE_DIR_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = rig("dry", &vault());
        let (_, dry) = text(set_upstream(Codec::Json, request("10.8.0.5", true)).await).await;
        assert!(dry.contains("\"local\"") && !dry.contains("true"), "{dry}");
        assert_eq!(std::fs::read_to_string(root.join("Caddyfile")).unwrap(), vault());
        std::env::set_var(SYSTEMCTL_ENV, script(&root, "systemctl.sh", "#!/bin/sh\nexit 0\n"));
        std::env::set_var(CADDY_ENV, script(&root, "caddy.sh", "#!/bin/sh\nexit 0\n"));
        let (_, same) = text(set_upstream(Codec::Json, request("", false)).await).await;
        assert!(same.contains("\"local\"") && !same.contains("true"), "{same}");
        cleanup();
    }

    #[tokio::test]
    async fn a_site_caddy_refuses_is_put_back() {
        let _guard = STATE_DIR_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = rig("refuse", &vault());
        std::env::set_var(CADDY_ENV, script(&root, "caddy.sh", "#!/bin/sh\nexit 1\n"));
        std::env::set_var(SYSTEMCTL_ENV, script(&root, "systemctl.sh", "#!/bin/sh\nexit 0\n"));
        let (status, body) = text(set_upstream(Codec::Json, request("10.8.0.5", false)).await).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(body.contains("put back"), "{body}");
        assert_eq!(std::fs::read_to_string(root.join("Caddyfile")).unwrap(), vault());
        cleanup();
    }

    #[tokio::test]
    async fn a_reload_that_fails_puts_the_old_site_back_and_reloads_again() {
        let _guard = STATE_DIR_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = rig("reload", &vault());
        let log = root.join("reload.log");
        std::env::set_var(CADDY_ENV, script(&root, "caddy.sh", "#!/bin/sh\nexit 0\n"));
        let body = format!("#!/bin/sh\necho x >> '{}'\n[ $(wc -l < '{}') -gt 1 ] && exit 0\nexit 1\n", log.display(), log.display());
        std::env::set_var(SYSTEMCTL_ENV, script(&root, "systemctl.sh", &body));
        let (status, body) = text(set_upstream(Codec::Json, request("10.8.0.5", false)).await).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert_eq!(std::fs::read_to_string(root.join("Caddyfile")).unwrap(), vault());
        assert_eq!(std::fs::read_to_string(&log).unwrap().lines().count(), 2);
        cleanup();
    }

    #[tokio::test]
    async fn a_machine_without_the_site_is_told_so() {
        let _guard = STATE_DIR_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _root = rig("nosite", &site("nextcloud", "cloud.example.com", 8080, false, false, false));
        let (status, body) = text(set_upstream(Codec::Json, request("10.8.0.5", false)).await).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(body.contains("no site"), "{body}");
        let (_, dry) = text(set_upstream(Codec::Json, request("", true)).await).await;
        assert!(dry.contains("missing"), "{dry}");
        cleanup();
    }

    #[test]
    fn only_application_answers_count_as_an_answer() {
        assert!(answered(200) && answered(302) && answered(401) && answered(404));
        assert!(!answered(502) && !answered(503) && !answered(504) && !answered(0) && !answered(500));
    }

    #[tokio::test]
    async fn the_probe_retries_until_the_site_answers() {
        let _guard = STATE_DIR_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = rig("probe", &vault());
        let counter = root.join("count");
        let body = format!(
            "#!/bin/sh\necho x >> '{0}'\nif [ $(wc -l < '{0}') -ge 3 ]; then printf 200; else printf 502; fi\n",
            counter.display()
        );
        std::env::set_var(CURL_ENV, script(&root, "curl.sh", &body));
        std::env::set_var(PROBE_DELAY_ENV, "1");
        let (_, answer) = text(probe_upstream(Codec::Json, pb::ProbeServiceUpstreamRequest { service_id: "vaultwarden".into() }).await).await;
        assert!(answer.contains("\"answered\":true") && answer.contains("200"), "{answer}");
        cleanup();
    }

    #[tokio::test]
    async fn a_site_that_only_returns_gateway_errors_is_reported_as_not_answering() {
        let _guard = STATE_DIR_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = rig("dead", &vault());
        std::env::set_var(CURL_ENV, script(&root, "curl.sh", "#!/bin/sh\nprintf 502\n"));
        std::env::set_var(PROBE_DELAY_ENV, "1");
        let (_, answer) = text(probe_upstream(Codec::Json, pb::ProbeServiceUpstreamRequest { service_id: "vaultwarden".into() }).await).await;
        assert!(!answer.contains("\"answered\":true") && answer.contains("502"), "{answer}");
        cleanup();
    }

    #[tokio::test]
    async fn a_machine_without_curl_says_it_could_not_check() {
        let _guard = STATE_DIR_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = rig("nocurl", &vault());
        std::env::set_var(CURL_ENV, root.join("missing-curl"));
        let (_, answer) = text(probe_upstream(Codec::Json, pb::ProbeServiceUpstreamRequest { service_id: "vaultwarden".into() }).await).await;
        assert!(answer.contains("\"unavailable\":true"), "{answer}");
        cleanup();
    }
}
