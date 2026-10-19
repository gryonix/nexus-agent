//! The two packages every install stands on: docker and Caddy

use std::path::Path;
use std::time::Duration;

use super::execute::EventSink;

const CADDY_RELEASES_URL: &str = "https://github.com/caddyserver/caddy/releases";
const STALE_CADDY_REPOSITORY_FILES: &str =
    "/etc/apt/sources.list.d/caddy-stable.list /usr/share/keyrings/caddy-stable-archive-keyring.gpg";
/// Docker's own convenience script, as `ServiceInfraSections.installDocker` uses it
const DOCKER_INSTALL_URL: &str = "https://get.docker.com";

pub(crate) const APT_OPTIONS: &str =
    "-o DPkg::Lock::Timeout=600 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold";

/// Non-interactive apt-get with the shared options
pub(crate) fn apt_quiet() -> String {
    format!("DEBIAN_FRONTEND=noninteractive apt-get {APT_OPTIONS}")
}

/// Drops sources that would fail every apt-get update
pub(crate) fn drop_retired_sources() -> String {
    format!("rm -f {STALE_CADDY_REPOSITORY_FILES}")
}

const PACKAGE_TIMEOUT: Duration = Duration::from_secs(900);

/// Is this binary already on the host?
pub(crate) fn have_binary(name: &str) -> bool {
    let Some(path) = search_path() else { return false };
    path.split(':').filter(|dir| !dir.is_empty()).any(|dir| {
        let candidate = Path::new(dir).join(name);
        std::fs::metadata(&candidate).map(|meta| meta.is_file()).unwrap_or(false)
    })
}

fn search_path() -> Option<String> {
    if cfg!(test) {
        if let Ok(stubbed) = std::env::var(BIN_PATH_OVERRIDE) {
            return Some(stubbed);
        }
    }
    std::env::var("PATH").ok()
}

/// Test-only override for the binary search path
const BIN_PATH_OVERRIDE: &str = "GRYONIXNEXUSD_INSTALL_BIN_PATH";

pub(super) async fn ensure_present(sink: &EventSink) -> Result<(), String> {
    ensure_docker(sink).await?;
    ensure_caddy(sink).await
}

/// A relay needs docker only; its web traffic goes home
pub(super) async fn ensure_for(relay: bool, sink: &EventSink) -> Result<(), String> {
    if relay { ensure_docker(sink).await } else { ensure_present(sink).await }
}

async fn ensure_docker(sink: &EventSink) -> Result<(), String> {
    if have_binary("docker") {
        return Ok(());
    }
    let _ = sink.step("docker is not installed on this host — installing it").await;
    require_apt()?;
    run_outside_sandbox(
        &format!("curl -fsSL {DOCKER_INSTALL_URL} | sh"),
        "installing docker",
        sink,
    )
    .await?;
    run_outside_sandbox("systemctl enable --now docker", "enabling docker", sink).await?;
    if !have_binary("docker") {
        return Err("docker still is not on PATH after installing it".to_string());
    }
    let _ = sink.step("docker is installed and running").await;
    Ok(())
}

pub(in crate::install) async fn ensure_nvidia_container_toolkit(sink: &EventSink) -> Result<(), String> {
    let _ = sink
        .step("teaching docker about the graphics card (NVIDIA container toolkit)")
        .await;
    require_apt()?;
    let script = format!(
        "set -e\n\
         export DEBIAN_FRONTEND=noninteractive\n\
         rm -f {STALE_CADDY_REPOSITORY_FILES}\n\
         apt-get {APT_OPTIONS} install -y ca-certificates curl gnupg\n\
         curl -fsSL {GPU_KEY_URL} | gpg --batch --yes --dearmor -o {GPU_KEYRING_PATH}\n\
         curl -fsSL {GPU_SOURCE_LIST_URL} | sed 's#deb https://#deb [signed-by={GPU_KEYRING_PATH}] https://#g' > {GPU_SOURCE_LIST_PATH}\n\
         apt-get {APT_OPTIONS} update\n\
         apt-get {APT_OPTIONS} install -y nvidia-container-toolkit\n\
         nvidia-ctk runtime configure --runtime=docker\n\
         systemctl restart docker\n",
        GPU_KEY_URL = crate::install::ollama::GPU_KEY_URL,
        GPU_KEYRING_PATH = crate::install::ollama::GPU_KEYRING_PATH,
        GPU_SOURCE_LIST_URL = crate::install::ollama::GPU_SOURCE_LIST_URL,
        GPU_SOURCE_LIST_PATH = crate::install::ollama::GPU_SOURCE_LIST_PATH,
    );
    run_outside_sandbox(&script, "installing the NVIDIA container toolkit", sink).await
}

async fn ensure_caddy(sink: &EventSink) -> Result<(), String> {
    if have_binary("caddy") && caddy_user_exists() {
        return Ok(());
    }
    let _ = sink.step("Caddy is not installed on this host — installing it").await;
    require_apt()?;
    run_outside_sandbox(&caddy_install_script(), "installing Caddy", sink).await?;
    run_outside_sandbox("systemctl enable --now caddy", "enabling Caddy", sink).await?;
    if !have_binary("caddy") {
        return Err("caddy still is not on PATH after installing it".to_string());
    }
    let _ = sink.step("Caddy is installed and running").await;
    Ok(())
}

fn caddy_user_exists() -> bool {
    let path = std::env::var("GRYONIXNEXUSD_INSTALL_PASSWD").unwrap_or_else(|_| "/etc/passwd".to_string());
    std::fs::read_to_string(path)
        .map(|passwd| passwd.lines().any(|line| line.starts_with("caddy:")))
        .unwrap_or(false)
}

fn caddy_install_script() -> String {
    format!(
        "set -e\n\
         export DEBIAN_FRONTEND=noninteractive\n\
         rm -f {STALE_CADDY_REPOSITORY_FILES}\n\
         arch=\"$(dpkg --print-architecture)\"\n\
         case \"$arch\" in armhf) arch=armv6 ;; armel) arch=armv5 ;; esac\n\
         tag=\"$(curl -fsSLI -o /dev/null -w '%{{url_effective}}' {CADDY_RELEASES_URL}/latest)\"\n\
         tag=\"${{tag##*/}}\"\n\
         deb=\"caddy_${{tag#v}}_linux_${{arch}}.deb\"\n\
         tmp=\"$(mktemp -d)\"\n\
         curl -fsSL -o \"$tmp/$deb\" \"{CADDY_RELEASES_URL}/download/$tag/$deb\"\n\
         curl -fsSL -o \"$tmp/sums\" \"{CADDY_RELEASES_URL}/download/$tag/caddy_${{tag#v}}_checksums.txt\"\n\
         (cd \"$tmp\" && grep \"  $deb\\$\" sums | sha512sum -c -)\n\
         apt-get {APT_OPTIONS} install -y --reinstall \"$tmp/$deb\"\n\
         id caddy >/dev/null\n\
         rm -rf \"$tmp\"\n"
    )
}

fn require_apt() -> Result<(), String> {
    if have_binary("apt-get") {
        return Ok(());
    }
    Err("this host has no apt-get, and the agent only knows how to install packages on \
         Debian/Ubuntu — install docker and Caddy by hand, or run the setup script"
        .to_string())
}

pub(super) async fn run_outside_sandbox(script: &str, what: &str, sink: &EventSink) -> Result<(), String> {
    let args: Vec<String> = vec![
        "--quiet".into(),
        "--collect".into(),
        "--wait".into(),
        "--pipe".into(),
        "--service-type=oneshot".into(),
        "/bin/sh".into(),
        "-c".into(),
        script.to_string(),
    ];
    super::execute::run_child_streaming(
        Path::new(&systemd_run_bin()),
        &args,
        None,
        &[],
        None,
        PACKAGE_TIMEOUT,
        sink,
    )
    .await
    .map_err(|err| format!("{what} failed: {err}"))
}

pub(super) async fn run_outside_sandbox_from_file(
    script: &str,
    what: &str,
    sink: &EventSink,
) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    static STAGED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let serial = STAGED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = std::path::PathBuf::from(format!("/run/gryonixnexusd-install-{}-{serial}.sh", std::process::id()));
    let staged = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o700)
        .open(&path)
        .and_then(|mut file| file.write_all(script.as_bytes()));
    staged.map_err(|err| format!("{what} failed: could not stage the script: {err}"))?;
    let outcome = run_outside_sandbox(&format!("/bin/sh {}", path.display()), what, sink).await;
    let _ = std::fs::remove_file(&path);
    outcome
}

fn systemd_run_bin() -> String {
    std::env::var("GRYONIXNEXUSD_INSTALL_SYSTEMD_RUN_BIN").unwrap_or_else(|_| "systemd-run".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    static BIN_PATH_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn a_binary_that_exists_is_found_and_a_made_up_one_is_not() {
        assert!(have_binary("sh"));
        assert!(!have_binary("gryonixnexus-definitely-not-a-binary"));
    }

    fn stub_host(name: &str, stubs: &[(&str, &str)]) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-pkg-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("stub dir");
        for (binary, body) in stubs {
            let path = dir.join(binary);
            std::fs::write(&path, body).expect("stub");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
        }
        dir
    }

    #[tokio::test]
    async fn a_host_with_neither_binary_gets_both_through_systemd_run() {
        let _guard = BIN_PATH_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let log = std::env::temp_dir().join(format!("gryonixnexusd-pkg-log-{}", std::process::id()));
        let _ = std::fs::remove_file(&log);
        let dir = stub_host(
            "bare",
            &[
                ("apt-get", "#!/bin/sh\nexit 0\n"),
                (
                    "systemd-run",
                    &format!(
                        "#!/bin/sh\necho \"$@\" >> '{}'\ncase \"$*\" in\n  *get.docker.com*) : > \"$(dirname \"$0\")/docker\"; chmod 755 \"$(dirname \"$0\")/docker\" ;;\n  *caddy*) : > \"$(dirname \"$0\")/caddy\"; chmod 755 \"$(dirname \"$0\")/caddy\" ;;\nesac\nexit 0\n",
                        log.display()
                    ),
                ),
            ],
        );
        std::env::set_var(BIN_PATH_OVERRIDE, &dir);
        std::env::set_var("GRYONIXNEXUSD_INSTALL_SYSTEMD_RUN_BIN", dir.join("systemd-run"));

        let (tx, _rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(64);
        let sink = crate::install::execute::EventSink::for_test(tx, "vaultwarden");
        let result = ensure_present(&sink).await;

        std::env::remove_var(BIN_PATH_OVERRIDE);
        std::env::remove_var("GRYONIXNEXUSD_INSTALL_SYSTEMD_RUN_BIN");
        assert_eq!(result, Ok(()), "both packages must be installable on a bare host");
        let calls = std::fs::read_to_string(&log).unwrap_or_default();
        assert!(calls.contains("get.docker.com"), "docker must be installed: {calls}");
        assert!(calls.contains("caddy"), "caddy must be installed: {calls}");
        assert!(calls.contains("--pipe"), "the work must go through a transient unit: {calls}");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&log);
    }

    #[tokio::test]
    async fn a_host_that_already_has_both_runs_nothing() {
        let _guard = BIN_PATH_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let log = std::env::temp_dir().join(format!("gryonixnexusd-pkg-log2-{}", std::process::id()));
        let _ = std::fs::remove_file(&log);
        let dir = stub_host(
            "ready",
            &[
                ("docker", "#!/bin/sh\nexit 0\n"),
                ("caddy", "#!/bin/sh\nexit 0\n"),
                ("apt-get", "#!/bin/sh\nexit 0\n"),
                ("systemd-run", &format!("#!/bin/sh\necho \"$@\" >> '{}'\nexit 0\n", log.display())),
            ],
        );
        std::env::set_var(BIN_PATH_OVERRIDE, &dir);
        std::env::set_var("GRYONIXNEXUSD_INSTALL_SYSTEMD_RUN_BIN", dir.join("systemd-run"));
        std::fs::write(dir.join("passwd"), "root:x:0:0::/root:/bin/sh\ncaddy:x:998:998::/var/lib/caddy:/usr/sbin/nologin\n").unwrap();
        std::env::set_var("GRYONIXNEXUSD_INSTALL_PASSWD", dir.join("passwd"));

        let (tx, _rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(64);
        let sink = crate::install::execute::EventSink::for_test(tx, "vaultwarden");
        let result = ensure_present(&sink).await;

        std::env::remove_var(BIN_PATH_OVERRIDE);
        std::env::remove_var("GRYONIXNEXUSD_INSTALL_SYSTEMD_RUN_BIN");
        std::env::remove_var("GRYONIXNEXUSD_INSTALL_PASSWD");
        assert_eq!(result, Ok(()));
        assert!(!log.exists(), "nothing should have been run: {:?}", std::fs::read_to_string(&log));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_caddy_binary_without_its_user_is_reinstalled() {
        let _guard = BIN_PATH_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let log = std::env::temp_dir().join(format!("gryonixnexusd-pkg-log3-{}", std::process::id()));
        let _ = std::fs::remove_file(&log);
        let dir = stub_host(
            "no-user",
            &[
                ("docker", "#!/bin/sh\nexit 0\n"),
                ("caddy", "#!/bin/sh\nexit 0\n"),
                ("apt-get", "#!/bin/sh\nexit 0\n"),
                ("systemd-run", &format!("#!/bin/sh\necho \"$@\" >> '{}'\nexit 0\n", log.display())),
            ],
        );
        std::env::set_var(BIN_PATH_OVERRIDE, &dir);
        std::env::set_var("GRYONIXNEXUSD_INSTALL_SYSTEMD_RUN_BIN", dir.join("systemd-run"));
        std::fs::write(dir.join("passwd"), "root:x:0:0::/root:/bin/sh\n").unwrap();
        std::env::set_var("GRYONIXNEXUSD_INSTALL_PASSWD", dir.join("passwd"));

        let (tx, _rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(64);
        let sink = crate::install::execute::EventSink::for_test(tx, "vaultwarden");
        let _ = ensure_present(&sink).await;

        std::env::remove_var(BIN_PATH_OVERRIDE);
        std::env::remove_var("GRYONIXNEXUSD_INSTALL_SYSTEMD_RUN_BIN");
        std::env::remove_var("GRYONIXNEXUSD_INSTALL_PASSWD");
        let calls = std::fs::read_to_string(&log).unwrap_or_default();
        assert!(calls.contains("--reinstall"), "caddy must be reinstalled: {calls}");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&log);
    }

    #[tokio::test]
    async fn a_host_without_apt_is_told_so_instead_of_being_guessed_at() {
        let _guard = BIN_PATH_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = stub_host("noapt", &[("systemd-run", "#!/bin/sh\nexit 0\n")]);
        std::env::set_var(BIN_PATH_OVERRIDE, &dir);
        std::env::set_var("GRYONIXNEXUSD_INSTALL_SYSTEMD_RUN_BIN", dir.join("systemd-run"));

        let (tx, _rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(64);
        let sink = crate::install::execute::EventSink::for_test(tx, "vaultwarden");
        let result = ensure_present(&sink).await;

        std::env::remove_var(BIN_PATH_OVERRIDE);
        std::env::remove_var("GRYONIXNEXUSD_INSTALL_SYSTEMD_RUN_BIN");
        let err = result.expect_err("no apt means no automatic install");
        assert!(err.contains("apt-get"), "the refusal must name what is missing: {err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn caddy_comes_from_github_releases_and_is_checksummed() {
        assert_eq!(CADDY_RELEASES_URL, "https://github.com/caddyserver/caddy/releases");
        assert_eq!(DOCKER_INSTALL_URL, "https://get.docker.com");
        let script = caddy_install_script();
        assert!(script.contains("sha512sum -c -"), "{script}");
        assert!(script.contains("rm -f /etc/apt/sources.list.d/caddy-stable.list"), "{script}");
        assert!(!script.contains("cloudsmith"), "{script}");
    }
}
