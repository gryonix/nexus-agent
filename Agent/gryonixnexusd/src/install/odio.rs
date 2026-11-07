//! odio's declarative install artifacts — a port of `Packages/gryonixNexus/Sources/ServiceCatalog/Services/OdioService.swift`

use super::caddy::WebIngress;
use super::context::Input;

pub const SERVICE_ID: &str = "odio";

pub const VERSION: &str = "2026.10.0b3";
pub const INSTALLER_URL: &str = "https://github.com/b0bbywan/odios/releases/download/2026.10.0b3/install.sh";
pub const INSTALLER_SHA256: &str = "1f1aafe4ef853ae10c9f6f134f24988b2943b6d5c50c388f8177103045c0f569";
pub const ACCOUNT: &str = "odio";
pub const WEB_UI_PORT: u16 = 8018;
pub const CONTROL_PATH: &str = "/usr/local/sbin/gryonixnexus-odio-ctl";
pub const AUTH_SNIPPET_PATH: &str = "/etc/caddy/gryonixnexus-odio-auth";
pub const LEFTOVER_PACKAGES: &str = "mpd, myMPD, Spotifyd, Snapcast, upmpdcli, BlueZ, PulseAudio, odio-api, odioctl";
const USER_UNITS: &[&str] = &[
    "odio-api.service",
    "mpd.service",
    "mympd.service",
    "spotifyd.service",
    "snapclient.service",
    "upmpdcli.service",
    "shairport-sync.service",
];

const INSTALL_UNIT: &str = "gryonixnexusd-odio-install";
const INSTALL_LIMIT: std::time::Duration = std::time::Duration::from_secs(30 * 60);

fn install_log() -> std::path::PathBuf {
    crate::util::state_dir().join("odio-install.log")
}

fn systemd_run_bin() -> String {
    std::env::var("GRYONIXNEXUSD_INSTALL_SYSTEMD_RUN_BIN").unwrap_or_else(|_| "systemd-run".to_string())
}

/// Runs the script in a transient unit with a log
pub async fn run_installer(script: &str, sink: &super::execute::EventSink) -> Result<(), String> {
    let log = install_log();
    let _ = std::fs::remove_file(&log);
    let wrapped = format!("exec >'{}' 2>&1\n{script}", log.display());
    let args = [
        "--quiet".to_string(),
        "--collect".to_string(),
        "--wait".to_string(),
        format!("--unit={INSTALL_UNIT}"),
        "--service-type=oneshot".to_string(),
        format!("--property=TimeoutStartSec={}", INSTALL_LIMIT.as_secs()),
        "/bin/bash".to_string(),
        "-c".to_string(),
        wrapped,
    ];
    let mut child = tokio::process::Command::new(systemd_run_bin())
        .args(&args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(false)
        .spawn()
        .map_err(|err| format!("could not start systemd-run: {err}"))?;
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(10));
    let status = loop {
        tokio::select! {
            status = child.wait() => break status.map_err(|err| format!("the odio installer did not finish: {err}"))?,
            _ = tick.tick() => {
                if let Some(line) = last_line(&log) {
                    let _ = sink.step(line).await;
                }
            }
        }
    };
    if status.success() {
        return Ok(());
    }
    Err(format!("the odio installer failed: {}", tail(&log)))
}

fn last_line(log: &std::path::Path) -> Option<String> {
    let text = std::fs::read_to_string(log).ok()?;
    let line = text.lines().rev().find(|line| !line.trim().is_empty())?;
    Some(line.chars().take(200).collect())
}

fn tail(log: &std::path::Path) -> String {
    let text = std::fs::read_to_string(log).unwrap_or_default();
    let lines: Vec<&str> = text.lines().filter(|line| !line.trim().is_empty()).collect();
    lines[lines.len().saturating_sub(3)..].join(" ").chars().take(300).collect()
}

/// A port of `OdioService.hostname(_:)`
pub fn hostname(input: &Input) -> String {
    if input.odio_hostname.is_empty() {
        super::hostnames::default_hostname(SERVICE_ID, &input.domain, &input.installed_services)
    } else {
        input.odio_hostname.clone()
    }
}

/// A port of `OdioService.webIngress(_:)`, without the password snippet
pub fn web_ingress(input: &Input) -> WebIngress {
    WebIngress {
        hostname: hostname(input),
        upstream_port: WEB_UI_PORT,
        admin_guard: true,
        upstream_https: false,
        public_paths: Vec::new(),
    }
}

/// The Caddy site NAMES this ingress publishes.
pub fn caddy_site_names(input: &Input) -> Vec<String> {
    let mut names = vec![hostname(input)];
    names.extend(input.mirrored_hostnames(&hostname(input)));
    names
}

/// The site, with the guard and the password snippet
pub fn caddy_site(input: &Input) -> String {
    super::caddy::site_with_basic_auth(
        SERVICE_ID,
        &caddy_site_names(input).join(", "),
        WEB_UI_PORT,
        input.local_only,
        AUTH_SNIPPET_PATH,
    )
}

/// A port of `OdioService.controlScript()`
pub fn control_script() -> String {
    let units = USER_UNITS.join(" ");
    format!(
        "#!/bin/bash\nset -eu\nuser={ACCOUNT}\nunits=\"{units}\"\nuid=\"$(id -u \"$user\")\"\nas_user() {{ runuser -u \"$user\" -- env XDG_RUNTIME_DIR=\"/run/user/$uid\" \"$@\"; }}\neach_unit() {{\n  for unit in $units; do\n    if as_user systemctl --user cat \"$unit\" >/dev/null 2>&1; then\n      as_user systemctl --user \"$@\" \"$unit\"\n    fi\n  done\n}}\ncase \"${{1:-}}\" in\n  status) as_user systemctl --user show $units --property=Id,LoadState,ActiveState ;;\n  logs) journalctl \"_UID=$uid\" -n 500 --no-pager -o short-iso ;;\n  start|restart) each_unit \"$1\" ;;\n  stop) each_unit stop; as_user systemctl --user stop mpd.socket || true ;;\n  disable) each_unit disable --now; as_user systemctl --user disable --now mpd.socket || true ;;\n  *) exit 2 ;;\nesac"
    )
}

/// Downloads, verifies and runs the pinned installer; takes minutes
pub fn installer_script(airplay_taken: bool) -> String {
    let airplay = if airplay_taken { "N" } else { "Y" };
    format!(
        "set -e\nodio_tmp=\"$(mktemp -d)\"\ncurl -fsSL -o \"$odio_tmp/install.sh\" '{INSTALLER_URL}'\necho '{INSTALLER_SHA256}  '\"$odio_tmp/install.sh\" | sha256sum -c - >/dev/null || {{ echo 'the odio installer does not match its pinned checksum'; exit 1; }}\nprintf 'APT::Get::Assume-Yes \"true\";\\n' > \"$odio_tmp/apt.conf\"\nTARGET_USER={ACCOUNT} ODIOS_VERSION={VERSION} INSTALL_BRANDING=N INSTALL_SHAIRPORT_SYNC={airplay} APT_CONFIG=\"$odio_tmp/apt.conf\" DEBIAN_FRONTEND=noninteractive bash -s < \"$odio_tmp/install.sh\"\nrm -rf \"$odio_tmp\"\nid -u {ACCOUNT} >/dev/null 2>&1 || {{ echo 'the odio installer finished without creating the {ACCOUNT} user'; exit 1; }}\n"
    )
}

/// Binds the API to loopback, sets the password, restarts
pub fn finish_script(input: &Input) -> String {
    let path = &input.odio_path;
    let ctl = control_script();
    format!(
        "set -e\nodio_home=\"$(getent passwd {ACCOUNT} | cut -d: -f6)\"\ninstall -d -m 700 -o {ACCOUNT} -g {ACCOUNT} \"$odio_home/.config/odio-api/conf.d\"\nprintf 'bind: lo\\n' > \"$odio_home/.config/odio-api/conf.d/20-gryonixnexus.yml\"\nchown {ACCOUNT}:{ACCOUNT} \"$odio_home/.config/odio-api/conf.d/20-gryonixnexus.yml\"\ncat > {CONTROL_PATH} <<'EOF_ODIO_CTL'\n{ctl}\nEOF_ODIO_CTL\nchmod 755 {CONTROL_PATH}\nif [ ! -f {path}/.env ]; then\n  install -m 600 /dev/null {path}/.env\n  printf 'ODIO_WEB_USER={ACCOUNT}\\nODIO_WEB_PASSWORD=%s\\n' \"$(openssl rand -hex 12)\" > {path}/.env\nfi\n. {path}/.env\nprintf 'basic_auth {{\\n    %s %s\\n}}\\n' \"$ODIO_WEB_USER\" \"$(caddy hash-password --plaintext \"$ODIO_WEB_PASSWORD\")\" > {AUTH_SNIPPET_PATH}\nchmod 644 {AUTH_SNIPPET_PATH}\n{CONTROL_PATH} restart\n"
    )
}

/// The uninstall steps, before the web address goes
pub fn uninstall_steps(input: &Input) -> Vec<String> {
    vec![
        format!("[ -x {CONTROL_PATH} ] && {CONTROL_PATH} disable || true"),
        format!("rm -f {CONTROL_PATH} {AUTH_SNIPPET_PATH}"),
        format!(
            "echo \"odio: {}\"",
            super::host::report::l10n::odio_leftovers(input.language, LEFTOVER_PACKAGES, ACCOUNT)
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Input {
        Input { domain: "example.com".to_string(), ..Input::default() }
    }

    #[test]
    fn the_site_is_guarded_and_asks_for_the_password() {
        let site = caddy_site(&base());
        assert!(site.contains("odio.example.com {"));
        assert!(site.contains("import /etc/caddy/gryonixnexus-admin-guard\n    import /etc/caddy/gryonixnexus-odio-auth\n    reverse_proxy 127.0.0.1:8018"), "{site}");
    }

    #[test]
    fn the_installer_is_pinned_and_checked() {
        let text = installer_script(false);
        assert!(text.contains(INSTALLER_URL) && text.contains(INSTALLER_SHA256));
        assert!(text.contains("sha256sum -c -"));
        assert!(text.contains("INSTALL_SHAIRPORT_SYNC=Y"));
        assert!(installer_script(true).contains("INSTALL_SHAIRPORT_SYNC=N"));
        assert!(text.contains("bash -s < \"$odio_tmp/install.sh\""), "the installer reads itself from stdin");
        assert!(text.contains("id -u odio"), "a silent no-op run must fail");
        assert!(text.contains("APT::Get::Assume-Yes"), "apt must not stop to ask");
    }

    #[test]
    fn loopback_binding_password_and_helper_are_written() {
        let text = finish_script(&base());
        assert!(text.contains("printf 'bind: lo\\n'"));
        assert!(text.contains("caddy hash-password --plaintext"));
        assert!(text.contains("/opt/odio/.env"));
    }

    #[test]
    fn uninstall_says_what_is_left() {
        let steps = uninstall_steps(&base());
        assert!(steps.iter().any(|s| s.contains("left in place")));
        assert!(steps[0].contains("disable"));
    }
}

/// Byte-for-byte parity against the Swift-dumped catalog golden.
#[cfg(test)]
mod golden_parity {
    use super::*;

    #[test]
    fn the_helper_matches_what_swift_writes() {
        let step = super::super::golden::setup_step(SERVICE_ID);
        let marker = "<<'EOF_ODIO_CTL'\n";
        let from = step.find(marker).expect("heredoc") + marker.len();
        let to = step.find("\nEOF_ODIO_CTL").expect("heredoc end");
        assert_eq!(&step[from..to], control_script());
    }
}
