//! AmneziaWG in the kernel: the module, its switch and the fallback.

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};

const STATE_FILE: &str = "awg-kernel.json";
const CONTAINER: &str = "awgvpn";
/// Free disk the module, headers and compiler need
pub const NEEDED_FREE_BYTES: i64 = 1 << 30;
const RUN_LIMIT: Duration = Duration::from_secs(20 * 60);

static WORKING: AtomicBool = AtomicBool::new(false);

/// The kernel switch and its outcome
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    /// The choice made; none while nobody chose
    pub wanted: Option<bool>,
    /// off, working, on or failed
    pub status: String,
    pub note: String,
    /// Packages this agent installed, removed again when switched off
    #[serde(default)]
    pub installed: Vec<String>,
}

fn state_path() -> PathBuf {
    crate::util::state_dir().join(STATE_FILE)
}

pub fn load() -> State {
    std::fs::read_to_string(state_path()).ok().and_then(|text| serde_json::from_str(&text).ok()).unwrap_or_default()
}

fn save(state: &State) {
    if let Ok(text) = serde_json::to_string(state) {
        let _ = crate::util::write_file_atomic(&state_path(), text.as_bytes(), 0o600);
    }
}

/// Debian or Ubuntu with apt
pub fn supported(os_release: &str) -> bool {
    let id = os_field(os_release, "ID");
    let like = os_field(os_release, "ID_LIKE");
    (id == "debian" || id == "ubuntu" || like.split_whitespace().any(|word| word == "debian"))
        && std::path::Path::new("/usr/bin/apt-get").exists()
}

fn os_field(os_release: &str, key: &str) -> String {
    os_release
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{key}=")))
        .map(|value| value.trim_matches('"').to_string())
        .unwrap_or_default()
}

/// The PPA suite: Ubuntu's own, focal on Debian
pub fn suite(os_release: &str) -> String {
    if os_field(os_release, "ID") == "ubuntu" {
        os_field(os_release, "VERSION_CODENAME")
    } else {
        "focal".to_string()
    }
}

/// The module is loaded on this host
pub fn module_loaded() -> bool {
    std::path::Path::new("/sys/module/amneziawg").exists()
}

fn free_bytes() -> i64 {
    crate::move_transfer::free_bytes(std::path::Path::new("/")).unwrap_or(0)
}

/// Installs the module and moves AmneziaWG onto it
pub fn enable_script(suite: &str) -> String {
    format!(
        r#"set -eu
export DEBIAN_FRONTEND=noninteractive
step() {{ echo "STEP $*"; }}
missing() {{ for p in "$@"; do dpkg -s "$p" >/dev/null 2>&1 || printf '%s ' "$p"; done; }}
step "installing kernel headers and build tools"
apt-get update -qq
NEW="$(missing "linux-headers-$(uname -r)" dkms build-essential curl ca-certificates)"
[ -z "$NEW" ] || apt-get install -y -qq $NEW >/dev/null
echo "INSTALLED $NEW"
step "adding the Amnezia package source"
install -d -m 0755 /etc/apt/keyrings
curl -fsSL 'https://launchpad.net/api/1.0/~amnezia/+archive/ubuntu/ppa?ws.op=getSigningKeyData' \
  | sed -e 's/^"//' -e 's/"$//' -e 's/\\n/\n/g' > /etc/apt/keyrings/amnezia-ppa.asc
echo "deb [signed-by=/etc/apt/keyrings/amnezia-ppa.asc] https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu {suite} main" \
  > /etc/apt/sources.list.d/gryonixnexus-amnezia.list
apt-get update -qq
step "building the AmneziaWG module"
NEW="$(missing amneziawg)"
[ -z "$NEW" ] || apt-get install -y -qq $NEW >/dev/null
echo "INSTALLED $NEW"
modprobe amneziawg
[ -d /sys/module/amneziawg ]
step "restarting AmneziaWG on the module"
docker restart {CONTAINER} >/dev/null
for _ in $(seq 30); do
  docker exec {CONTAINER} ip link show wg0 >/dev/null 2>&1 && break
  sleep 1
done
docker exec {CONTAINER} ip link show wg0 >/dev/null
if docker exec {CONTAINER} pgrep amneziawg-go >/dev/null 2>&1; then echo "still a program" >&2; exit 3; fi
echo "DONE"
"#
    )
}

/// The script that puts AmneziaWG back on the program
pub fn disable_script(installed: &[String]) -> String {
    let packages = installed.join(" ");
    format!(
        r#"set -u
export DEBIAN_FRONTEND=noninteractive
echo "STEP moving AmneziaWG back to the program"
docker stop {CONTAINER} >/dev/null 2>&1 || true
modprobe -r amneziawg 2>/dev/null || true
rm -f /etc/apt/sources.list.d/gryonixnexus-amnezia.list /etc/apt/keyrings/amnezia-ppa.asc
[ -n "{packages}" ] && apt-get purge -y -qq {packages} >/dev/null 2>&1 || true
apt-get autoremove -y -qq >/dev/null 2>&1 || true
docker start {CONTAINER} >/dev/null
echo "DONE"
"#
    )
}

/// Packages the script installed
pub fn installed_in(output: &str) -> Vec<String> {
    output
        .lines()
        .filter_map(|line| line.strip_prefix("INSTALLED "))
        .flat_map(|rest| rest.split_whitespace().map(str::to_string))
        .collect()
}

/// The last step the script reached, for the note
pub fn last_step(output: &str) -> String {
    output.lines().rev().find_map(|line| line.strip_prefix("STEP ")).unwrap_or("").to_string()
}

async fn run(script: &str) -> (bool, String) {
    let child = tokio::process::Command::new("bash")
        .args(["-c", script])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn();
    let Ok(child) = child else { return (false, "could not start bash".to_string()) };
    match tokio::time::timeout(RUN_LIMIT, child.wait_with_output()).await {
        Ok(Ok(output)) => {
            let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
            text.push_str(&String::from_utf8_lossy(&output.stderr));
            (output.status.success(), text)
        }
        Ok(Err(err)) => (false, err.to_string()),
        Err(_) => (false, "it took longer than 20 minutes".to_string()),
    }
}

fn tail(text: &str) -> String {
    let lines: Vec<&str> = text.lines().filter(|line| !line.starts_with("STEP ") && !line.starts_with("INSTALLED ")).collect();
    lines[lines.len().saturating_sub(3)..].join(" ").chars().take(300).collect()
}

/// Turns the module on or off in the background
pub fn switch(enabled: bool) -> State {
    let mut state = load();
    state.wanted = Some(enabled);
    if WORKING.swap(true, Ordering::SeqCst) {
        save(&state);
        return state;
    }
    state.status = "working".to_string();
    state.note = String::new();
    save(&state);
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        WORKING.store(false, Ordering::SeqCst);
        return state;
    };
    runtime.spawn(async move {
        if enabled { enable().await } else { disable().await }
        WORKING.store(false, Ordering::SeqCst);
    });
    state
}

async fn enable() {
    let os = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
    let mut state = load();
    if !supported(&os) {
        state.status = "failed".to_string();
        state.note = "only Debian and Ubuntu servers can build the module".to_string();
        return save(&state);
    }
    if free_bytes() < NEEDED_FREE_BYTES {
        state.status = "failed".to_string();
        state.note = "less than 1 GB free on the disk".to_string();
        return save(&state);
    }
    let (ok, output) = run(&enable_script(&suite(&os))).await;
    state.installed = installed_in(&output);
    if ok {
        state.status = "on".to_string();
        state.note = String::new();
        return save(&state);
    }
    let step = last_step(&output);
    let (_, _) = run(&disable_script(&state.installed)).await;
    state.installed.clear();
    state.status = "failed".to_string();
    state.note = format!("{step}: {}", tail(&output));
    save(&state);
}

async fn disable() {
    let mut state = load();
    let (ok, output) = run(&disable_script(&state.installed)).await;
    state.installed.clear();
    state.status = if ok { "off" } else { "failed" }.to_string();
    state.note = if ok { String::new() } else { tail(&output) };
    save(&state);
}

/// Turns the module on once for a server with AmneziaWG
pub async fn refresh() {
    let state = load();
    if state.wanted.is_some() || WORKING.load(Ordering::SeqCst) || module_loaded() {
        return;
    }
    let running = tokio::process::Command::new("docker")
        .args(["inspect", "-f", "{{.State.Running}}", CONTAINER])
        .stdin(Stdio::null())
        .output()
        .await
        .is_ok_and(|output| String::from_utf8_lossy(&output.stdout).trim() == "true");
    let os = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
    if running && supported(&os) && free_bytes() >= NEEDED_FREE_BYTES {
        tracing::info!("putting AmneziaWG into the kernel");
        switch(true);
    }
}

/// Socket buffers a one-core server drops UDP packets without
pub const UDP_SYSCTL: &str = "# Managed by gryonixNexus: room for VPN packets\n\
net.core.rmem_max = 7500000\n\
net.core.wmem_max = 7500000\n\
net.core.netdev_max_backlog = 5000\n";
const UDP_SYSCTL_PATH: &str = "/etc/sysctl.d/90-gryonixnexus-vpn.conf";

/// Writes the buffers once and applies them; whether it changed
pub async fn refresh_udp_buffers() -> bool {
    if std::fs::read_to_string(UDP_SYSCTL_PATH).is_ok_and(|text| text == UDP_SYSCTL) {
        return false;
    }
    if crate::util::write_file_atomic(std::path::Path::new(UDP_SYSCTL_PATH), UDP_SYSCTL.as_bytes(), 0o644).is_err() {
        return false;
    }
    tokio::process::Command::new("sysctl")
        .args(["-q", "-p", UDP_SYSCTL_PATH])
        .stdin(Stdio::null())
        .status()
        .await
        .is_ok_and(|status| status.success())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEBIAN: &str = "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian\nVERSION_CODENAME=bookworm\n";
    const UBUNTU: &str = "NAME=\"Ubuntu\"\nID=ubuntu\nID_LIKE=debian\nVERSION_CODENAME=noble\n";

    #[test]
    fn the_ppa_suite_follows_the_system() {
        assert_eq!(suite(UBUNTU), "noble");
        assert_eq!(suite(DEBIAN), "focal");
    }

    #[test]
    fn the_enable_script_checks_before_it_counts_as_done() {
        let script = enable_script("noble");
        assert!(script.contains("ppa.launchpadcontent.net/amnezia/ppa/ubuntu noble main"));
        assert!(script.contains("modprobe amneziawg"));
        assert!(script.contains("pgrep amneziawg-go"), "a container still on the program is not a success");
        assert!(script.contains("dpkg -s"), "only packages the server lacked are counted as ours");
        assert!(script.trim_end().ends_with("echo \"DONE\""));
    }

    #[test]
    fn switching_off_removes_only_what_was_installed() {
        let script = disable_script(&["amneziawg".to_string(), "dkms".to_string()]);
        assert!(script.contains("apt-get purge -y -qq amneziawg dkms"));
        assert!(script.contains("modprobe -r amneziawg"));
        assert!(script.contains("docker start awgvpn"));
    }

    #[test]
    fn the_output_names_what_it_installed_and_where_it_stopped() {
        let output = "STEP installing kernel headers\nINSTALLED linux-headers-6.1.0-26-amd64 dkms build-essential\nSTEP building the AmneziaWG module\nE: Unable to locate package amneziawg\n";
        assert_eq!(installed_in(output), vec!["linux-headers-6.1.0-26-amd64", "dkms", "build-essential"]);
        assert_eq!(last_step(output), "building the AmneziaWG module");
        assert_eq!(tail(output), "E: Unable to locate package amneziawg");
    }

    #[test]
    fn a_kept_state_reads_back() {
        let state = State { wanted: Some(true), status: "on".into(), note: String::new(), installed: vec!["amneziawg".into()] };
        let text = serde_json::to_string(&state).unwrap();
        assert_eq!(serde_json::from_str::<State>(&text).unwrap(), state);
        assert_eq!(serde_json::from_str::<State>("{\"status\":\"off\",\"note\":\"\"}").unwrap().wanted, None);
    }

    #[test]
    fn both_scripts_parse_as_bash() {
        for script in [enable_script("focal"), disable_script(&["amneziawg".to_string()])] {
            let out = std::process::Command::new("bash").args(["-n", "-c", &script]).output().expect("bash runs");
            assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        }
    }
}
