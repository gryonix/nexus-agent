//! AmneziaWG in the kernel: the module, its switch and the fallback.

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};

const STATE_FILE: &str = "awg-kernel.json";
const LOG_FILE: &str = "awg-kernel.log";
/// The scripts' own unit, which outlives an agent restart
const UNIT: &str = "gryonixnexusd-awg-kernel";
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

fn log_path() -> PathBuf {
    crate::util::state_dir().join(LOG_FILE)
}

/// The switch is being worked on by this agent
pub fn busy() -> bool {
    WORKING.load(Ordering::SeqCst)
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
step 1/4 "installing kernel headers and build tools"
apt-get update -qq
NEW="$(missing "linux-headers-$(uname -r)" dkms build-essential curl ca-certificates)"
[ -z "$NEW" ] || apt-get install -y -qq $NEW >/dev/null
echo "INSTALLED $NEW"
step 2/4 "adding the Amnezia package source"
install -d -m 0755 /etc/apt/keyrings
curl -fsSL 'https://launchpad.net/api/1.0/~amnezia/+archive/ubuntu/ppa?ws.op=getSigningKeyData' \
  | sed -e 's/^"//' -e 's/"$//' -e 's/\\n/\n/g' > /etc/apt/keyrings/amnezia-ppa.asc
echo "deb [signed-by=/etc/apt/keyrings/amnezia-ppa.asc] https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu {suite} main" \
  > /etc/apt/sources.list.d/gryonixnexus-amnezia.list
apt-get update -qq
step 3/4 "building the AmneziaWG module"
NEW="$(missing amneziawg)"
[ -z "$NEW" ] || apt-get install -y -qq $NEW >/dev/null
echo "INSTALLED $NEW"
modprobe amneziawg
[ -d /sys/module/amneziawg ]
step 4/4 "restarting AmneziaWG on the module"
docker restart {CONTAINER} >/dev/null
for _ in $(seq 30); do
  docker exec {CONTAINER} ip link show wg0 >/dev/null 2>&1 && break
  sleep 1
done
docker exec {CONTAINER} ip link show wg0 >/dev/null
if docker exec {CONTAINER} pgrep amneziawg-go >/dev/null 2>&1; then echo "still a program" >&2; exit 3; fi
echo "{DONE_ON}"
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
echo "{DONE_OFF}"
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
    let step = output.lines().rev().find_map(|line| line.strip_prefix("STEP ")).unwrap_or("");
    match step.split_once(' ') {
        Some((count, name)) if is_count(count) => name.to_string(),
        _ => step.to_string(),
    }
}

/// How far the script got, as "3/4"
pub fn progress(output: &str) -> String {
    let step = output.lines().rev().find_map(|line| line.strip_prefix("STEP ")).unwrap_or("");
    step.split_whitespace().next().filter(|count| is_count(count)).unwrap_or("").to_string()
}

fn is_count(word: &str) -> bool {
    word.split_once('/')
        .is_some_and(|(n, m)| n.parse::<u8>().is_ok() && m.parse::<u8>().is_ok())
}

/// How far the switch got, from the script's log
pub fn current_progress() -> String {
    std::fs::read_to_string(log_path()).map(|log| progress(&log)).unwrap_or_default()
}

const DONE_ON: &str = "DONE on";
const DONE_OFF: &str = "DONE off";

fn systemd_run_bin() -> String {
    std::env::var("GRYONIXNEXUSD_AWG_SYSTEMD_RUN_BIN").unwrap_or_else(|_| "systemd-run".to_string())
}

fn systemctl_bin() -> String {
    std::env::var("GRYONIXNEXUSD_AWG_SYSTEMCTL_BIN").unwrap_or_else(|_| "systemctl".to_string())
}

async fn unit_active() -> bool {
    tokio::process::Command::new(systemctl_bin())
        .args(["is-active", "--quiet", UNIT])
        .stdin(Stdio::null())
        .status()
        .await
        .is_ok_and(|status| status.success())
}

/// Waits for a running unit; false when stopped
async fn wait_for_unit() -> bool {
    let deadline = tokio::time::Instant::now() + RUN_LIMIT;
    while unit_active().await {
        if tokio::time::Instant::now() >= deadline {
            let _ = tokio::process::Command::new(systemctl_bin()).args(["stop", UNIT]).stdin(Stdio::null()).status().await;
            return false;
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    true
}

/// The log ends with the line the script prints last
fn finished(log: &str, done: &str) -> bool {
    log.lines().rev().find(|line| !line.trim().is_empty()) == Some(done)
}

/// Runs the script outside the sandbox, where apt can write
async fn run(script: &str, done: &str) -> (bool, String) {
    let log = log_path();
    // A unit still running is a restarted agent's: await it
    if !unit_active().await {
        let _ = std::fs::remove_file(&log);
        let wrapped = format!("exec >'{}' 2>&1\n{script}", log.display());
        let started = tokio::process::Command::new(systemd_run_bin())
            .args([
                "--quiet".to_string(),
                "--collect".to_string(),
                "--wait".to_string(),
                format!("--unit={UNIT}"),
                "--service-type=oneshot".to_string(),
                format!("--property=TimeoutStartSec={}", RUN_LIMIT.as_secs()),
                "/bin/bash".to_string(),
                "-c".to_string(),
                wrapped,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .output();
        match tokio::time::timeout(RUN_LIMIT + Duration::from_secs(60), started).await {
            Ok(Ok(output)) if !log.exists() => {
                let why = String::from_utf8_lossy(&output.stderr).trim().to_string();
                return (false, if why.is_empty() { "the script did not start".to_string() } else { why });
            }
            Ok(Ok(_)) => {}
            Ok(Err(err)) => return (false, format!("could not start systemd-run: {err}")),
            Err(_) => {}
        }
    }
    if !wait_for_unit().await {
        return (false, "it took longer than 20 minutes".to_string());
    }
    let text = std::fs::read_to_string(&log).unwrap_or_default();
    if finished(&text, done) {
        return (true, text);
    }
    if text.lines().all(|line| line.starts_with("STEP ") || line.starts_with("INSTALLED ")) {
        return (false, format!("{text}it stopped, maybe after 20 minutes"));
    }
    (false, text)
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
    let (ok, output) = run(&enable_script(&suite(&os)), DONE_ON).await;
    for package in installed_in(&output) {
        if !state.installed.contains(&package) {
            state.installed.push(package);
        }
    }
    save(&state);
    if ok {
        state.status = "on".to_string();
        state.note = String::new();
        return save(&state);
    }
    let step = last_step(&output);
    let (_, _) = run(&disable_script(&state.installed), DONE_OFF).await;
    state.installed.clear();
    state.status = "failed".to_string();
    state.note = format!("{step}: {}", tail(&output));
    save(&state);
}

async fn disable() {
    let mut state = load();
    let (ok, output) = run(&disable_script(&state.installed), DONE_OFF).await;
    state.installed.clear();
    state.status = if ok { "off" } else { "failed" }.to_string();
    state.note = if ok { String::new() } else { tail(&output) };
    save(&state);
}

/// Turns the module on once; finishes a switch left working
pub async fn refresh() {
    let state = load();
    if state.status == "working" && !WORKING.load(Ordering::SeqCst) {
        tracing::info!("finishing the AmneziaWG kernel switch the last agent started");
        switch(state.wanted.unwrap_or(true));
        return;
    }
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
        assert!(script.trim_end().ends_with("echo \"DONE on\""));
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
        let output = "STEP 1/4 installing kernel headers\nINSTALLED linux-headers-6.1.0-26-amd64 dkms build-essential\nSTEP 3/4 building the AmneziaWG module\nE: Unable to locate package amneziawg\n";
        assert_eq!(installed_in(output), vec!["linux-headers-6.1.0-26-amd64", "dkms", "build-essential"]);
        assert_eq!(last_step(output), "building the AmneziaWG module");
        assert_eq!(progress(output), "3/4");
        assert_eq!(progress("STEP moving AmneziaWG back to the program\n"), "", "a step without a count shows none");
        assert_eq!(last_step("STEP moving AmneziaWG back to the program\n"), "moving AmneziaWG back to the program");
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
    fn only_the_expected_last_line_counts_as_done() {
        assert!(finished("STEP 4/4 restarting\nDONE on\n\n", DONE_ON));
        assert!(!finished("STEP moving back\nDONE off\n", DONE_ON), "a finished rollback is not a finished switch-on");
        assert!(!finished("STEP 3/4 building\nDONE on\nE: late\n", DONE_ON));
    }

    fn stub(dir: &std::path::Path, name: &str, body: &str) -> String {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(name);
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path.display().to_string()
    }

    /// Runs the script in place; no unit is ever active
    fn stub_host(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("gryonixnexusd-awg-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("GRYONIXNEXUSD_STATE_DIR", &dir);
        std::env::set_var(
            "GRYONIXNEXUSD_AWG_SYSTEMD_RUN_BIN",
            stub(&dir, "systemd-run", "#!/bin/sh\necho \"$@\" > \"$(dirname \"$0\")/args\"\nwhile [ \"$1\" != /bin/bash ]; do shift; done\nexec \"$@\"\n"),
        );
        std::env::set_var("GRYONIXNEXUSD_AWG_SYSTEMCTL_BIN", stub(&dir, "systemctl", "#!/bin/sh\nexit 3\n"));
        dir
    }

    #[tokio::test]
    async fn the_script_runs_in_its_own_unit_and_its_log_decides() {
        let _guard = crate::util::STATE_DIR_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = stub_host("run");
        let (ok, output) = run("echo 'STEP 1/4 headers'\necho 'INSTALLED dkms'\necho 'DONE on'\n", DONE_ON).await;
        assert!(ok, "{output}");
        assert_eq!(installed_in(&output), vec!["dkms"]);
        let args = std::fs::read_to_string(dir.join("args")).unwrap();
        assert!(args.contains("--unit=gryonixnexusd-awg-kernel"), "{args}");
        assert!(args.contains("--wait"), "{args}");
        assert!(args.contains("TimeoutStartSec=1200"), "{args}");
        assert_eq!(current_progress(), "1/4");

        let (ok, output) = run("echo 'STEP 3/4 building'\necho 'E: no package' >&2\nexit 100\n", DONE_ON).await;
        assert!(!ok);
        assert_eq!(last_step(&output), "building");
        assert_eq!(tail(&output), "E: no package");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_unit_an_earlier_agent_started_is_waited_for_not_started_again() {
        let _guard = crate::util::STATE_DIR_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = stub_host("adopt");
        std::fs::write(dir.join(LOG_FILE), "STEP 4/4 restarting\nINSTALLED amneziawg\nDONE on\n").unwrap();
        // Active on the first ask, finished on the next
        let systemctl = stub(&dir, "systemctl", "#!/bin/sh\nf=\"$(dirname \"$0\")/asked\"\n[ -e \"$f\" ] && exit 3\ntouch \"$f\"\nexit 0\n");
        std::env::set_var("GRYONIXNEXUSD_AWG_SYSTEMCTL_BIN", systemctl);
        let (ok, output) = run("echo 'DONE off'\n", DONE_ON).await;
        assert!(ok, "{output}");
        assert_eq!(installed_in(&output), vec!["amneziawg"]);
        assert!(!dir.join("args").exists(), "no second run was started");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_switch_left_working_by_an_earlier_agent_is_picked_up() {
        let _guard = crate::util::STATE_DIR_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = stub_host("resume");
        save(&State { wanted: Some(false), status: "working".into(), note: String::new(), installed: vec![] });
        assert!(!busy());
        refresh().await;
        for _ in 0..100 {
            if !busy() && load().status != "working" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let state = load();
        assert_ne!(state.status, "working", "the stale switch was finished: {state:?}");
        assert!(dir.join("args").exists(), "the switch ran again");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn both_scripts_parse_as_bash() {
        for script in [enable_script("focal"), disable_script(&["amneziawg".to_string()])] {
            let out = std::process::Command::new("bash").args(["-n", "-c", &script]).output().expect("bash runs");
            assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        }
    }
}
