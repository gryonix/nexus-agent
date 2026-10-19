use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

/// Where the generator's `include` glob looks
pub fn drop_in_dir_display() -> String {
    drop_in_dir().display().to_string()
}

fn drop_in_dir() -> PathBuf {
    std::env::var("GRYONIXNEXUSD_INSTALL_NFTABLES_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/etc/nftables.d"))
}

pub(crate) fn nft_bin() -> String {
    std::env::var("GRYONIXNEXUSD_INSTALL_NFT_BIN").unwrap_or_else(|_| "nft".to_string())
}

/// `NftablesConfig.agentChainName`, and the table it lives in
pub const TABLE: &str = "inet filter";
pub const CHAIN: &str = "gryonixnexus_services";

/// The glob `/etc/nftables.conf` includes
pub const DROP_IN_GLOB: &str = "gryonixnexus-*.nft";

/// One `nft` invocation's budget
const NFT_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Proto {
    Tcp,
    Udp,
}

impl fmt::Display for Proto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Port {
    pub proto: Proto,
    pub port: u16,
}

impl Port {
    pub const fn tcp(port: u16) -> Self {
        Self { proto: Proto::Tcp, port }
    }

    pub const fn udp(port: u16) -> Self {
        Self { proto: Proto::Udp, port }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Applied,
    Cleared,
    SkippedNoDropInDir,
}

fn is_safe_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 64
        && label.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

pub fn drop_in_path(label: &str) -> PathBuf {
    drop_in_dir().join(format!("gryonixnexus-svc-{label}.nft"))
}

pub fn drop_in_contents(label: &str, ports: &[Port]) -> String {
    let mut out = String::new();
    out.push_str("# Managed by gryonixNexus — ports opened for ");
    out.push_str(label);
    out.push_str(" by gryonixnexusd.\n");
    out.push_str("# Included by /etc/nftables.conf; do not edit by hand.\n");
    for proto in [Proto::Tcp, Proto::Udp] {
        let mut set: Vec<u16> =
            ports.iter().filter(|p| p.proto == proto).map(|p| p.port).collect();
        set.sort_unstable();
        set.dedup();
        if set.is_empty() {
            continue;
        }
        let list = set.iter().map(u16::to_string).collect::<Vec<_>>().join(", ");
        out.push_str(&format!(
            "add rule {TABLE} {CHAIN} {proto} dport {{ {list} }} accept comment \"{label}\"\n"
        ));
    }
    out
}

/// The transaction handed to `nft -f -`
pub fn apply_script(dir: &Path) -> String {
    format!(
        "flush chain {TABLE} {CHAIN}\ninclude \"{}/{DROP_IN_GLOB}\"\n",
        dir.display()
    )
}

/// Write `label`'s drop-in and make the live ruleset match it
pub async fn apply_service_ports(label: &str, ports: &[Port]) -> Result<Outcome, String> {
    if !is_safe_label(label) {
        return Err(format!("refusing to build a firewall drop-in for the label {label:?}"));
    }
    let dir = drop_in_dir();
    if !dir.is_dir() {
        return Ok(Outcome::SkippedNoDropInDir);
    }

    let path = drop_in_path(label);
    let outcome = if ports.is_empty() {
        match std::fs::remove_file(&path) {
            Ok(()) => Outcome::Cleared,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Outcome::Cleared,
            Err(err) => return Err(format!("could not remove {}: {err}", path.display())),
        }
    } else {
        std::fs::write(&path, drop_in_contents(label, ports))
            .map_err(|err| format!("could not write {}: {err}", path.display()))?;
        set_mode(&path, 0o644)
            .map_err(|err| format!("could not set the mode of {}: {err}", path.display()))?;
        Outcome::Applied
    };

    apply(&dir).await?;
    Ok(outcome)
}

pub async fn apply_rules(label: &str, rules: &str) -> Result<Outcome, String> {
    if !is_safe_label(label) {
        return Err(format!("refusing to build a firewall drop-in for the label {label:?}"));
    }
    let dir = drop_in_dir();
    if !dir.is_dir() {
        return Ok(Outcome::SkippedNoDropInDir);
    }
    let path = drop_in_path(label);
    let current = std::fs::read_to_string(&path).ok();
    let wanted = (!rules.is_empty()).then_some(rules);
    if current.as_deref() == wanted {
        return Ok(Outcome::Applied);
    }
    match wanted {
        None => {
            let _ = std::fs::remove_file(&path);
        }
        Some(rules) => {
            std::fs::write(&path, rules).map_err(|err| format!("could not write {}: {err}", path.display()))?;
            set_mode(&path, 0o644).map_err(|err| format!("could not set the mode of {}: {err}", path.display()))?;
        }
    }
    apply(&dir).await?;
    Ok(if wanted.is_some() { Outcome::Applied } else { Outcome::Cleared })
}

/// Rebuild the live chain from every drop-in
async fn apply(dir: &Path) -> Result<(), String> {
    let script = apply_script(dir);
    let mut child = tokio::process::Command::new(nft_bin())
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("could not run nft: {err}"))?;

    if let Some(mut stdin) = child.stdin.take() {
        use tokio::io::AsyncWriteExt;
        stdin
            .write_all(script.as_bytes())
            .await
            .map_err(|err| format!("could not feed the ruleset to nft: {err}"))?;
        stdin.shutdown().await.ok();
        drop(stdin);
    }

    let output = tokio::time::timeout(NFT_TIMEOUT, child.wait_with_output())
        .await
        .map_err(|_| format!("nft timed out after {}s", NFT_TIMEOUT.as_secs()))?
        .map_err(|err| format!("could not run nft: {err}"))?;

    if output.status.success() {
        return Ok(());
    }

    let mut detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if detail.is_empty() {
        detail = String::from_utf8_lossy(&output.stdout).trim().to_string();
    }
    Err(format!(
        "could not apply the firewall drop-in: {detail}. If the chain {CHAIN} does not exist, \
         this host's ruleset predates it — re-run setup on the host to install the current one."
    ))
}

fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drop_in_names_stay_inside_the_generators_include_glob() {
        let path = drop_in_path("docker-mailserver");
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        assert!(name.starts_with("gryonixnexus-"), "{name} is outside the include glob");
        assert!(name.ends_with(".nft"), "{name} is outside the include glob");
        assert_ne!(name, "gryonixnexus-00-placeholder.nft");
    }

    #[test]
    fn contents_group_ports_by_protocol_sorted_and_deduplicated() {
        let ports = [
            Port::tcp(465),
            Port::tcp(25),
            Port::udp(51820),
            Port::tcp(25),
        ];
        let text = drop_in_contents("docker-mailserver", &ports);
        assert!(
            text.contains("add rule inet filter gryonixnexus_services tcp dport { 25, 465 } accept comment \"docker-mailserver\"\n"),
            "{text}"
        );
        assert!(
            text.contains("add rule inet filter gryonixnexus_services udp dport { 51820 } accept comment \"docker-mailserver\"\n"),
            "{text}"
        );
        let shuffled = [Port::udp(51820), Port::tcp(25), Port::tcp(465)];
        assert_eq!(text, drop_in_contents("docker-mailserver", &shuffled));
    }

    #[test]
    fn contents_omit_a_protocol_with_no_ports() {
        let text = drop_in_contents("wireguard-vpn", &[Port::udp(51820)]);
        assert!(!text.contains(" tcp dport "), "{text}");
    }

    #[test]
    fn the_transaction_flushes_one_chain_and_includes_every_drop_in() {
        let script = apply_script(Path::new("/etc/nftables.d"));
        assert_eq!(
            script,
            "flush chain inet filter gryonixnexus_services\ninclude \"/etc/nftables.d/gryonixnexus-*.nft\"\n"
        );
        assert!(!script.contains("flush ruleset"));
        assert!(!script.contains("/etc/nftables.conf"));
    }

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-fw-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn stub_nft(dir: &Path, code: i32) -> (PathBuf, PathBuf, PathBuf) {
        let argv = dir.join("argv.txt");
        let stdin = dir.join("stdin.txt");
        let script = dir.join("nft");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" > {}\ncat > {}\n[ {code} -eq 0 ] || echo 'Error: No such file or directory' 1>&2\nexit {code}\n",
                argv.display(),
                stdin.display()
            ),
        )
        .unwrap();
        set_mode(&script, 0o755).unwrap();
        (script, argv, stdin)
    }

    #[tokio::test]
    async fn a_host_without_the_drop_in_directory_is_skipped_without_running_nft() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tmp("nodir");
        let (script, argv, _) = stub_nft(&dir, 0);
        std::env::set_var("GRYONIXNEXUSD_INSTALL_NFT_BIN", &script);
        std::env::set_var("GRYONIXNEXUSD_INSTALL_NFTABLES_DIR", dir.join("absent"));

        let outcome = apply_service_ports("vpn", &[Port::udp(51820)]).await;

        std::env::remove_var("GRYONIXNEXUSD_INSTALL_NFT_BIN");
        std::env::remove_var("GRYONIXNEXUSD_INSTALL_NFTABLES_DIR");
        assert_eq!(outcome, Ok(Outcome::SkippedNoDropInDir));
        assert!(!argv.exists(), "nft must not run on a host with no ruleset of ours");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn applying_writes_the_drop_in_and_feeds_nft_the_whole_transaction_on_stdin() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tmp("apply");
        let nftd = dir.join("nftables.d");
        std::fs::create_dir_all(&nftd).unwrap();
        let (script, argv, stdin) = stub_nft(&dir, 0);
        std::env::set_var("GRYONIXNEXUSD_INSTALL_NFT_BIN", &script);
        std::env::set_var("GRYONIXNEXUSD_INSTALL_NFTABLES_DIR", &nftd);

        let outcome = apply_service_ports("vpn", &[Port::udp(51820)]).await;
        let second = apply_service_ports("docker-mailserver", &[Port::tcp(25), Port::tcp(465)]).await;

        std::env::remove_var("GRYONIXNEXUSD_INSTALL_NFT_BIN");
        std::env::remove_var("GRYONIXNEXUSD_INSTALL_NFTABLES_DIR");

        assert_eq!(outcome, Ok(Outcome::Applied));
        assert_eq!(second, Ok(Outcome::Applied));
        assert_eq!(std::fs::read_to_string(&argv).unwrap().trim(), "-f -");

        let vpn_file = nftd.join("gryonixnexus-svc-vpn.nft");
        let mail_file = nftd.join("gryonixnexus-svc-docker-mailserver.nft");
        assert!(vpn_file.exists() && mail_file.exists(), "both services keep their own drop-in");
        assert!(std::fs::read_to_string(&vpn_file).unwrap().contains("udp dport { 51820 }"));

        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&vpn_file).unwrap().permissions().mode() & 0o777, 0o644);

        let fed = std::fs::read_to_string(&stdin).unwrap();
        assert_eq!(fed, apply_script(&nftd));
        assert!(fed.starts_with("flush chain inet filter gryonixnexus_services\n"), "{fed}");
        assert!(fed.contains("gryonixnexus-*.nft"), "{fed}");
        assert!(!fed.contains("flush ruleset"), "{fed}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn no_ports_removes_the_drop_in_and_still_rebuilds_the_chain() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tmp("clear");
        let nftd = dir.join("nftables.d");
        std::fs::create_dir_all(&nftd).unwrap();
        let (script, _argv, stdin) = stub_nft(&dir, 0);
        std::env::set_var("GRYONIXNEXUSD_INSTALL_NFT_BIN", &script);
        std::env::set_var("GRYONIXNEXUSD_INSTALL_NFTABLES_DIR", &nftd);

        let _ = apply_service_ports("vpn", &[Port::udp(51820)]).await;
        let file = nftd.join("gryonixnexus-svc-vpn.nft");
        assert!(file.exists());
        let cleared = apply_service_ports("vpn", &[]).await;
        // Idempotent: clearing what is already clear is not an error.
        let again = apply_service_ports("vpn", &[]).await;

        std::env::remove_var("GRYONIXNEXUSD_INSTALL_NFT_BIN");
        std::env::remove_var("GRYONIXNEXUSD_INSTALL_NFTABLES_DIR");

        assert_eq!(cleared, Ok(Outcome::Cleared));
        assert_eq!(again, Ok(Outcome::Cleared));
        assert!(!file.exists());
        assert!(std::fs::read_to_string(&stdin).unwrap().contains("flush chain"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_failing_nft_reports_its_own_output_and_names_the_remedy() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tmp("fail");
        let nftd = dir.join("nftables.d");
        std::fs::create_dir_all(&nftd).unwrap();
        let (script, _, _) = stub_nft(&dir, 1);
        std::env::set_var("GRYONIXNEXUSD_INSTALL_NFT_BIN", &script);
        std::env::set_var("GRYONIXNEXUSD_INSTALL_NFTABLES_DIR", &nftd);

        let outcome = apply_service_ports("vpn", &[Port::udp(51820)]).await;

        std::env::remove_var("GRYONIXNEXUSD_INSTALL_NFT_BIN");
        std::env::remove_var("GRYONIXNEXUSD_INSTALL_NFTABLES_DIR");

        let err = outcome.expect_err("a failing nft must not read as success");
        assert!(err.contains("No such file or directory"), "{err}");
        assert!(err.contains("re-run setup"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn labels_that_could_escape_the_filename_are_refused() {
        assert!(is_safe_label("docker-mailserver"));
        assert!(is_safe_label("vpn"));
        assert!(!is_safe_label(""));
        assert!(!is_safe_label("../etc/passwd"));
        assert!(!is_safe_label("svc name"));
        assert!(!is_safe_label("Svc"));
    }
}
