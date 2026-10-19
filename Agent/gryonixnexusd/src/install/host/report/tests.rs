//! Parity harness for `install-report.txt` — see this module's parent doc for why source-text comparison (what every other `install::host` file uses) cannot verify this one: the fixtures are shell SOURCE, but what has to match is shell OUTPUT

use super::*;
use crate::language::Language;
use crate::install::context::Input;
use crate::install::host::HostRole;
use crate::install::mail::mailcow;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

// ============================================================================ Sandbox ============================================================================

struct Sandbox {
    root: PathBuf,
    root_str: String,
    bin: PathBuf,
    mailcow_key: String,
    mailcow_dkim_dir: PathBuf,
    dkim_call_log: PathBuf,
    script_counter: AtomicU32,
}

impl Sandbox {
    fn new() -> Self {
        let out = Command::new("mktemp").arg("-d").output().expect("mktemp must be on PATH");
        assert!(out.status.success(), "mktemp failed: {out:?}");
        let root = PathBuf::from(String::from_utf8(out.stdout).unwrap().trim().to_string());
        let bin = root.join("stub-bin");
        std::fs::create_dir_all(&bin).unwrap();
        let mailcow_dkim_dir = root.join("mailcow-dkim-seed");
        std::fs::create_dir_all(&mailcow_dkim_dir).unwrap();
        let dkim_call_log = root.join("dkim-call-log.txt");
        std::fs::write(&dkim_call_log, "").unwrap();
        let root_str = root.to_str().expect("mktemp path must be utf8").to_string();
        let sandbox = Sandbox {
            root,
            root_str,
            bin,
            mailcow_key: "REAL-mailcow-key-9f8e7d".to_string(),
            mailcow_dkim_dir,
            dkim_call_log,
            script_counter: AtomicU32::new(0),
        };
        sandbox.install_stub_binaries();
        sandbox
    }

    fn reroot(&self, path: &str) -> PathBuf {
        if path.starts_with(&self.root_str) {
            PathBuf::from(path)
        } else {
            self.root.join(path.trim_start_matches('/'))
        }
    }

    fn rewrite(&self, text: &str) -> String {
        text.replace("/opt/", &format!("{}/opt/", self.root.display()))
            .replace("/etc/gryonixnexus/", &format!("{}/etc/gryonixnexus/", self.root.display()))
    }

    fn write_file(&self, path: &str, contents: &str) {
        let full = self.reroot(path);
        std::fs::create_dir_all(full.parent().expect("path must have a parent")).unwrap();
        std::fs::write(&full, contents).unwrap();
    }

    fn write_executable(&self, path: &str, script: &str) {
        self.write_file(path, script);
        Self::chmod_x(&self.reroot(path));
    }

    fn install_stub(&self, name: &str, script: &str) {
        let full = self.bin.join(name);
        std::fs::write(&full, script).unwrap();
        Self::chmod_x(&full);
    }

    fn chmod_x(path: &std::path::Path) {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(path, perms).unwrap();
    }

    const UNIT_STATUSES: &'static [(&'static str, &'static str, i32)] = &[
        ("nftables", "active", 0),
        ("docker", "active", 0),
        ("caddy", "inactive", 3),
        ("wg-quick@wg0", "failed", 1),
    ];

    /// `wg show wg0` — one interface block, no peers
    const WG_SHOW_TEXT: &'static str =
        "interface: wg0\n  public key: TESTPUBKEY0000000000000000000000000000000=\n  listening port: 51820\n";

    fn install_stub_binaries(&self) {
        let mut systemctl = String::from("#!/bin/bash\nif [ \"$1\" != \"is-active\" ]; then exit 1; fi\ncase \"$2\" in\n");
        for (unit, status, code) in Self::UNIT_STATUSES {
            systemctl.push_str(&format!("  {unit}) echo {status}; exit {code} ;;\n"));
        }
        systemctl.push_str("  *) echo unknown; exit 4 ;;\nesac\n");
        self.install_stub("systemctl", &systemctl);

        let curl = format!(
            "#!/bin/bash\n\
             key=\"\"\n\
             url=\"\"\n\
             config=\"$(cat)\"\n\
             case \"$config\" in\n\
             \x20 *'header = \"X-API-Key: '*) key=\"${{config#*X-API-Key: }}\"; key=\"${{key%%\\\"*}}\" ;;\n\
             esac\n\
             for a in \"$@\"; do\n\
             \x20 case \"$a\" in\n\
             \x20   https://*) url=\"$a\" ;;\n\
             \x20 esac\n\
             done\n\
             domain=\"${{url##*/}}\"\n\
             if [ \"$key\" = \"{key}\" ]; then\n\
             \x20 seed=\"{dir}/$domain.txt\"\n\
             \x20 [ -f \"$seed\" ] && cat \"$seed\"\n\
             fi\n\
             exit 0\n",
            key = self.mailcow_key,
            dir = self.mailcow_dkim_dir.display(),
        );
        self.install_stub("curl", &curl);
        self.install_stub("jq", "#!/bin/bash\ncat\nexit 0\n");

        let wg = format!("#!/bin/bash\nif [ \"$1\" = \"show\" ]; then\n  printf '%s' '{}'\nfi\n", Self::WG_SHOW_TEXT);
        self.install_stub("wg", &wg);
    }

    fn run(&self, body: &str) -> String {
        let n = self.script_counter.fetch_add(1, Ordering::Relaxed);
        let prelude = format!(
            "set -euo pipefail\nset +e\nlog() {{ printf '\\n==> %s\\n' \"$*\"; }}\nexport PATH=\"{}:$PATH\"\n",
            self.bin.display()
        );
        let full_script = format!("{prelude}{body}");
        let script_path = self.root.join(format!("report-{n}.sh"));
        std::fs::write(&script_path, &full_script).unwrap();
        let out = Command::new("bash")
            .arg(&script_path)
            .output()
            .unwrap_or_else(|e| panic!("could not run bash: {e}"));
        String::from_utf8(out.stdout).unwrap_or_else(|e| {
            panic!("report block wrote non-utf8 stdout: {e}\nscript:\n{full_script}")
        })
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

// ============================================================================ Facts ============================================================================

#[test]
fn every_catalogued_service_renders_a_report_block() {
    let sandbox = Sandbox::new();
    let facts = TestFacts::new(&sandbox);
    for id in crate::install::host::CATALOG_ORDER {
        let input = host_input(&[id], HostRole::SingleHost, Language::En, Input::default());
        let _ = service_block(id, &input, &facts);
    }
}

#[test]
fn an_unpinned_minecraft_version_is_named_in_the_report() {
    let sandbox = Sandbox::new();
    let facts = TestFacts::new(&sandbox);

    let floating = host_input(&["minecraft-java"], HostRole::SingleHost, Language::En,
                              Input::default());
    let text = service_block("minecraft-java", &floating, &facts);
    assert!(
        text.contains(&l10n::minecraft_version_follows_latest(Language::En)),
        "an unpinned version is not named: {text}"
    );

    let pinned = host_input(
        &["minecraft-java"],
        HostRole::SingleHost,
        Language::En,
        Input { minecraft_java_version: "1.21.4".to_string(), ..Input::default() },
    );
    let text = service_block("minecraft-java", &pinned, &facts);
    assert!(
        !text.contains(&l10n::minecraft_version_follows_latest(Language::En)),
        "a pinned version was told its world will move: {text}"
    );
}

struct TestFacts<'a> {
    sandbox: &'a Sandbox,
}

impl<'a> TestFacts<'a> {
    fn new(sandbox: &'a Sandbox) -> Self {
        TestFacts { sandbox }
    }
}

impl Facts for TestFacts<'_> {
    fn systemctl_is_active(&self, unit: &str) -> String {
        Sandbox::UNIT_STATUSES
            .iter()
            .find(|(u, _, _)| *u == unit)
            .map(|(_, status, _)| status.to_string())
            .unwrap_or_else(|| "unknown".to_string())
    }

    fn read_file(&self, path: &str) -> Option<String> {
        std::fs::read_to_string(self.sandbox.reroot(path)).ok()
    }

    fn dkim_wrapper(&self, path: &str) -> String {
        match Command::new(self.sandbox.reroot(path)).output() {
            Ok(out) => String::from_utf8_lossy(&out.stdout).into_owned(),
            Err(_) => String::new(),
        }
    }

    fn mailcow_dkim(&self, api_key: &str, domain: &str, https_port: u16) -> String {
        let curl = self.sandbox.bin.join("curl");
        let mut child = Command::new(&curl)
            .args([
                "-fsSk",
                "--max-time",
                "20",
                "-K",
                "-",
                &format!("https://127.0.0.1:{https_port}/api/v1/get/dkim/{domain}"),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("stub curl must run");
        child.stdin.take().unwrap().write_all(mailcow::curl_config(api_key, None).as_bytes()).unwrap();
        let out = child.wait_with_output().unwrap();
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    fn wg_show(&self, _interface: &str) -> String {
        Sandbox::WG_SHOW_TEXT.to_string()
    }
}

fn seed_common_files(sandbox: &Sandbox) {
    sandbox.write_file(
        "/opt/mailcow-dockerized/mailcow.conf",
        &format!("API_KEY=decoy-key-from-first-boot\nAPI_KEY={}\n", sandbox.mailcow_key),
    );
    sandbox.write_file("/opt/vaultwarden/.env", "ADMIN_TOKEN=VW-TOKEN-1\n");
    sandbox.write_file("/etc/gryonixnexus/autobackup.pass", "AUTOBACKUP-PASS-1");
    sandbox.write_file("/opt/psono/.env", "PSONO_ADMIN_PASSWORD=PSONO-PW-1\n");
    sandbox.write_file("/opt/nextcloud/.env", "NEXTCLOUD_ADMIN_PASSWORD=NC-PW=1\n");
    sandbox.write_file("/opt/seafile/.env", "SEAFILE_ADMIN_PASSWORD=SEAFILE-PW-1\n");
    sandbox.write_file("/opt/photoprism/.env", "PHOTOPRISM_ADMIN_PASSWORD=PP-PW-1\n");
    sandbox.write_file("/opt/gitlab-ce/.env", "GITLAB_ROOT_PASSWORD=GITLAB-PW-1\n");
    sandbox.write_file("/opt/forgejo/.env", "FORGEJO_ADMIN_PASSWORD=FORGEJO-PW-1\n");
    sandbox.write_file("/opt/adguardhome/.env", "ADGUARD_ADMIN_PASSWORD=ADGUARD-PW-1\n");
    sandbox.write_file("/opt/mailu/.env", "INITIAL_ADMIN_PW=MAILU-PW-1\n");
    sandbox.write_file("/opt/docker-mailserver/.env", "FIRST_MAILBOX_PASSWORD=DMS-PW-1\n");
    sandbox.write_file("/opt/gryonix-vpn-panel/.env", "ADMIN_USER=vpnadmin\nADMIN_PASSWORD=VPNPANEL-PW-1\n");
    // A password containing all three SIP002-escaped characters at once.
    sandbox.write_file(
        "/opt/shadowsocks/config.json",
        "{\n  \"server\": \"0.0.0.0\",\n  \"server_port\": 8388,\n  \"password\": \"abcDEF123+/=\",\n  \"method\": \"2022-blake3-aes-256-gcm\"\n}\n",
    );
    sandbox.write_file("/opt/xray/link.txt", "vless://uuid@vpn.example.com:8443?security=reality#gryonixNexus\n");
    sandbox.write_file(
        "/opt/openvpn/gryonixnexus.ovpn",
        "client\ndev tun\nremote vpn.example.com 1194 udp\n<ca>\nTESTCERT\n</ca>",
    );
}

// ============================================================================ HostInput / Topology builders ============================================================================

fn base_input() -> Input {
    Input {
        domain: "example.com".to_string(),
        wireguard_vpn_port: 51821,
        xray_reality_port: 8443,
        ..Input::default()
    }
}

fn multidomain_input() -> Input {
    Input {
        domain: "example.com".to_string(),
        additional_domains: vec!["example.org".to_string(), "example.net".to_string()],
        wireguard_vpn_port: 51821,
        xray_reality_port: 8443,
        ..Input::default()
    }
}

fn host_input(services: &[&str], role: HostRole, language: Language, install: Input) -> HostInput {
    HostInput {
        services: services.iter().map(|s| s.to_string()).collect(),
        install,
        language,
        ssh_user: Some("admin".to_string()),
        role,
    }
}

/// Scenario A / scenario B home-half topology
fn services_host_topology(tunnel_endpoint: Option<&str>) -> Topology {
    Topology::ServicesHost {
        ptr_ip: Some("203.0.113.10".to_string()),
        ptr_hostname: "relay.example.com".to_string(),
        tunnel_endpoint: tunnel_endpoint.map(|s| s.to_string()),
    }
}

fn reroot_input(sandbox: &Sandbox, mut input: Input) -> Input {
    let r = |s: &str| -> String { format!("{}{s}", sandbox.root.display()) };
    input.adguard_path = r(&input.adguard_path);
    input.jellyfin_path = r(&input.jellyfin_path);
    input.photoprism_path = r(&input.photoprism_path);
    input.immich_path = r(&input.immich_path);
    input.nextcloud_path = r(&input.nextcloud_path);
    input.forgejo_path = r(&input.forgejo_path);
    input.gitlab_path = r(&input.gitlab_path);
    input.seafile_path = r(&input.seafile_path);
    input.psono_path = r(&input.psono_path);
    input.passbolt_path = r(&input.passbolt_path);
    input.amnezia_wg_path = r(&input.amnezia_wg_path);
    input.shadowsocks_path = r(&input.shadowsocks_path);
    input.xray_reality_path = r(&input.xray_reality_path);
    input.openvpn_path = r(&input.openvpn_path);
    input.mailcow_path = r(&input.mailcow_path);
    input.docker_mailserver_path = r(&input.docker_mailserver_path);
    input.mailu_path = r(&input.mailu_path);
    input
}

fn fixture(subdir: &str, name: &str) -> String {
    let path = format!("{}/tests/fixtures/install/host/{subdir}/{name}.txt", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

const SERVICE_SETS: &[(&str, &[&str])] = &[
    ("bare", &[]),
    ("mailcow", &["mailcow"]),
    ("nomail", &["vaultwarden", "nextcloud", "immich", "forgejo", "gitlab"]),
    ("mailcow-wg", &["mailcow", "vaultwarden", "nextcloud", "immich", "wireguard-vpn"]),
    ("mailcow-awg", &["mailcow", "vaultwarden", "nextcloud", "immich", "forgejo", "amnezia-wg"]),
    ("nomail-ss", &["vaultwarden", "shadowsocks"]),
    ("mailcow-xray", &["mailcow", "vaultwarden", "xray-reality"]),
    ("nomail-ovpn", &["vaultwarden", "openvpn"]),
    ("mailu", &["mailu"]),
    ("dms", &["docker-mailserver"]),
    ("dms-full", &["docker-mailserver", "vaultwarden", "forgejo", "wireguard-vpn"]),
    ("mailu-full", &["mailu", "vaultwarden", "nextcloud", "immich", "forgejo", "wireguard-vpn"]),
    ("jellyfin", &["jellyfin"]),
    ("jellyfin-full", &["jellyfin", "vaultwarden", "nextcloud", "wireguard-vpn"]),
    ("adguard", &["adguard-home"]),
    ("adguard-full", &["adguard-home", "vaultwarden", "nextcloud", "wireguard-vpn"]),
    ("photoprism", &["photoprism"]),
    ("photoprism-immich", &["photoprism", "immich", "vaultwarden"]),
    ("seafile", &["seafile"]),
    ("seafile-nextcloud", &["seafile", "nextcloud", "vaultwarden"]),
    ("psono", &["psono"]),
    ("psono-vaultwarden", &["psono", "vaultwarden"]),
    ("passbolt", &["passbolt"]),
    ("passwords-shelf", &["passbolt", "psono", "vaultwarden"]),
];

fn run_services_host_fixture_parity(subdir: &str, prefix: &str, role: HostRole, tunnel: Option<&str>) {
    let sandbox = Sandbox::new();
    seed_common_files(&sandbox);
    let topology = services_host_topology(tunnel);

    for (set_name, services) in SERVICE_SETS {
        for (lang_suffix, language) in [("en", Language::En), ("ru", Language::Ru)] {
            let install = reroot_input(&sandbox, base_input());
            let input = host_input(services, role, language, install);
            let actual = render(&input, &topology, &TestFacts::new(&sandbox));

            let fixture_name = format!("{prefix}-{set_name}-access-{lang_suffix}");
            let body = sandbox.rewrite(&fixture(subdir, &fixture_name));
            let expected = sandbox.run(&body);

            assert_eq!(actual, expected, "fixture {fixture_name} ({subdir})");
        }
    }

    let services: &[&str] =
        &["mailcow", "vaultwarden", "nextcloud", "immich", "forgejo", "gitlab", "amnezia-wg"];
    let install = reroot_input(&sandbox, multidomain_input());
    let input = host_input(services, role, Language::En, install);
    let actual = render(&input, &topology, &TestFacts::new(&sandbox));
    let fixture_name = format!("{prefix}-multidomain");
    let body = sandbox.rewrite(&fixture(subdir, &fixture_name));
    let expected = sandbox.run(&body);
    assert_eq!(actual, expected, "fixture {fixture_name} ({subdir})");
}

#[test]
fn fixture_parity_single_host() {
    run_services_host_fixture_parity("report_single", "A", HostRole::SingleHost, None);
}

#[test]
fn fixture_parity_home_backend() {
    run_services_host_fixture_parity("report_home", "B", HostRole::HomeBackend, Some("203.0.113.10:51820"));
}

const VPS_CASES: &[(&str, &[u16])] = &[
    ("B-adguard-access", &[80, 443]),
    ("B-bare-access", &[80]),
    ("B-dms-access", &[25, 80, 143, 443, 465, 587, 993, 4190]),
    ("B-dms-full-access", &[25, 80, 143, 443, 465, 587, 993, 2222, 4190]),
    ("B-mailcow-xray-access", &[25, 80, 143, 443, 465, 587, 993, 4190, 8443]),
    ("B-mailu-access", &[25, 80, 443, 465, 993, 4190]),
    ("B-mailu-full-access", &[25, 80, 443, 465, 993, 2222, 4190]),
    ("B-nomail-access", &[80, 443, 2222, 2223]),
    ("B-nomail-ss-access", &[80, 443, 8388]),
];

#[test]
fn fixture_parity_vps_relay() {
    let sandbox = Sandbox::new();

    for (base_name, ports) in VPS_CASES {
        for (lang_suffix, language) in [("en", Language::En), ("ru", Language::Ru)] {
            let topology = Topology::Relay {
                wg_port: 51820,
                forwarded_ports: ports.to_vec(),
                home_wg_address: "10.8.0.2".to_string(),
                ptr_hostname: "relay.example.com".to_string(),
            };
            let input = host_input(&[], HostRole::VpsRelay, language, base_input());
            let actual = render(&input, &topology, &TestFacts::new(&sandbox));

            let fixture_name = format!("{base_name}-{lang_suffix}");
            let body = sandbox.rewrite(&fixture("report_vps", &fixture_name));
            let expected = sandbox.run(&body);
            assert_eq!(actual, expected, "fixture {fixture_name}");
        }
    }

    let topology = Topology::Relay {
        wg_port: 51820,
        forwarded_ports: vec![25, 80, 143, 443, 465, 587, 993, 2222, 2223, 4190],
        home_wg_address: "10.8.0.2".to_string(),
        ptr_hostname: "relay.example.com".to_string(),
    };
    let input = host_input(&[], HostRole::VpsRelay, Language::En, base_input());
    let actual = render(&input, &topology, &TestFacts::new(&sandbox));
    let body = sandbox.rewrite(&fixture("report_vps", "B-multidomain"));
    let expected = sandbox.run(&body);
    assert_eq!(actual, expected, "fixture B-multidomain");
}

/// mailcow DKIM ready vs
#[test]
fn mailcow_dkim_ready_vs_not_ready() {
    let sandbox = Sandbox::new();
    seed_common_files(&sandbox);
    let install = reroot_input(&sandbox, base_input());
    let input = host_input(&["mailcow"], HostRole::SingleHost, Language::En, install);
    let topology = services_host_topology(None);
    let body = sandbox.rewrite(&fixture("report_single", "A-mailcow-access-en"));

    let actual_not_ready = render(&input, &topology, &TestFacts::new(&sandbox));
    let expected_not_ready = sandbox.run(&body);
    assert_eq!(actual_not_ready, expected_not_ready, "not-ready branch");
    assert!(actual_not_ready.contains("DKIM is not ready yet"));
    assert!(!actual_not_ready.contains("GRYONIXNEXUS_DKIM"));

    std::fs::write(sandbox.mailcow_dkim_dir.join("example.com.txt"), "v=DKIM1; k=rsa; p=TESTVALUE123").unwrap();
    let actual_ready = render(&input, &topology, &TestFacts::new(&sandbox));
    let expected_ready = sandbox.run(&body);
    assert_eq!(actual_ready, expected_ready, "ready branch");
    assert!(actual_ready.contains("GRYONIXNEXUS_DKIM dkim._domainkey.example.com v=DKIM1; k=rsa; p=TESTVALUE123"));
}

#[test]
fn mailcow_admin_password_default_vs_stored() {
    let sandbox = Sandbox::new();
    seed_common_files(&sandbox);
    let install = reroot_input(&sandbox, base_input());
    let input = host_input(&["mailcow"], HostRole::SingleHost, Language::En, install);
    let topology = services_host_topology(None);
    let body = sandbox.rewrite(&fixture("report_single", "A-mailcow-access-en"));

    let default = render(&input, &topology, &TestFacts::new(&sandbox));
    assert_eq!(default, sandbox.run(&body), "default branch");
    assert!(default.contains("Password: moohoo"));
    assert!(default.contains("change it after the first sign-in"));

    sandbox.write_file("/opt/mailcow-dockerized/.gryonixnexus-admin-password", "a1b2c3d4e5f6a7b8c9d0e1f2\n");
    let stored = render(&input, &topology, &TestFacts::new(&sandbox));
    assert_eq!(stored, sandbox.run(&body), "stored branch");
    assert!(stored.contains("Password: a1b2c3d4e5f6a7b8c9d0e1f2\n"));
    assert!(!stored.contains("moohoo"));
    assert!(!stored.contains("change it after the first sign-in"));
}

#[test]
fn dkim_wrapper_missing_vs_printing_vs_printing_nothing() {
    let sandbox = Sandbox::new();
    seed_common_files(&sandbox);
    let install = reroot_input(&sandbox, base_input());
    let input = host_input(&["docker-mailserver"], HostRole::SingleHost, Language::En, install);
    let topology = services_host_topology(None);
    let body = sandbox.rewrite(&fixture("report_single", "A-dms-access-en"));

    let actual_missing = render(&input, &topology, &TestFacts::new(&sandbox));
    let expected_missing = sandbox.run(&body);
    assert_eq!(actual_missing, expected_missing, "missing wrapper");
    assert!(actual_missing.contains("not ready yet — run the DKIM setup again on the server"));

    // Present and printing a real record.
    sandbox.write_executable(
        "/opt/gryonixnexus-dms-dkim.sh",
        "#!/bin/bash\nprintf 'GRYONIXNEXUS_DKIM dkim._domainkey.example.com v=DKIM1; k=rsa; p=ABC\\n'\n",
    );
    let actual_printing = render(&input, &topology, &TestFacts::new(&sandbox));
    let expected_printing = sandbox.run(&body);
    assert_eq!(actual_printing, expected_printing, "printing wrapper");
    assert!(actual_printing.contains("dkim._domainkey.example.com TXT v=DKIM1; k=rsa; p=ABC"));
    assert!(!actual_printing.contains("not ready yet"));

    sandbox.write_executable("/opt/gryonixnexus-dms-dkim.sh", "#!/bin/bash\necho 'no keys yet'\nexit 0\n");
    let actual_empty = render(&input, &topology, &TestFacts::new(&sandbox));
    let expected_empty = sandbox.run(&body);
    assert_eq!(actual_empty, expected_empty, "wrapper ran, printed nothing matching");
    assert!(actual_empty.contains("not ready yet — run the DKIM setup again on the server"));
}

#[test]
fn dkim_wrapper_lines_calls_the_wrapper_at_most_once() {
    let sandbox = Sandbox::new();
    sandbox.write_executable(
        "/opt/gryonixnexus-dms-dkim.sh",
        &format!(
            "#!/bin/bash\necho x >> \"{}\"\nprintf 'GRYONIXNEXUS_DKIM dkim._domainkey.example.com v=DKIM1; k=rsa; p=ABC\\n'\n",
            sandbox.dkim_call_log.display()
        ),
    );
    let facts = TestFacts::new(&sandbox);
    let out = dkim_wrapper_lines(&facts, DMS_DKIM_WRAPPER, "pending note");
    assert!(out.contains("dkim._domainkey.example.com TXT v=DKIM1; k=rsa; p=ABC"));

    let calls = std::fs::read_to_string(&sandbox.dkim_call_log).unwrap_or_default();
    let call_count = calls.lines().count();
    assert_eq!(call_count, 1, "dkim wrapper invoked {call_count} times, expected exactly 1: {calls:?}");
}

#[test]
fn passbolt_registration_url_absent_vs_empty_vs_present() {
    let sandbox = Sandbox::new();
    seed_common_files(&sandbox);
    let install = reroot_input(&sandbox, base_input());
    let input = host_input(&["passbolt"], HostRole::SingleHost, Language::En, install);
    let topology = services_host_topology(None);
    let body = sandbox.rewrite(&fixture("report_single", "A-passbolt-access-en"));

    // Absent (the default — nothing written).
    let actual_absent = render(&input, &topology, &TestFacts::new(&sandbox));
    let expected_absent = sandbox.run(&body);
    assert_eq!(actual_absent, expected_absent, "absent");
    assert!(actual_absent.contains("No setup link available here"));

    // Empty file.
    sandbox.write_file("/opt/passbolt/.registration-url", "");
    let actual_empty = render(&input, &topology, &TestFacts::new(&sandbox));
    let expected_empty = sandbox.run(&body);
    assert_eq!(actual_empty, expected_empty, "empty");
    assert!(actual_empty.contains("No setup link available here"));

    sandbox.write_file(
        "/opt/passbolt/.registration-url",
        "https://passbolt.example.com/setup/install/00000000-0000-0000-0000-000000000000/TOKEN\n",
    );
    let actual_present = render(&input, &topology, &TestFacts::new(&sandbox));
    let expected_present = sandbox.run(&body);
    assert_eq!(actual_present, expected_present, "present");
    assert!(actual_present.contains("https://passbolt.example.com/setup/install/"));
    assert!(!actual_present.contains("No setup link available here"));
}

#[test]
fn forgejo_and_gitlab_ssh_port_zero_disables_the_git_over_ssh_line() {
    let sandbox = Sandbox::new();
    seed_common_files(&sandbox);
    let mut install = reroot_input(&sandbox, base_input());
    install.forgejo_ssh_port = 0;
    install.gitlab_ssh_port = 0;
    let input = host_input(&["forgejo", "gitlab"], HostRole::SingleHost, Language::En, install);
    let topology = services_host_topology(None);
    let out = render(&input, &topology, &TestFacts::new(&sandbox));

    assert!(out.contains("Git over SSH is off — clone and push over HTTPS with an access token."));
    assert!(!out.contains("Git over SSH: port"));

    let mut install_nonzero = reroot_input(&sandbox, base_input());
    install_nonzero.forgejo_ssh_port = 2222;
    install_nonzero.gitlab_ssh_port = 2223;
    let input_nonzero = host_input(&["forgejo", "gitlab"], HostRole::SingleHost, Language::En, install_nonzero);
    let out_nonzero = render(&input_nonzero, &topology, &TestFacts::new(&sandbox));
    assert!(out_nonzero.contains("Git over SSH: port 2222"));
    assert!(out_nonzero.contains("Git over SSH: port 2223"));
    assert!(!out_nonzero.contains("Git over SSH is off"));
}

/// Vaultwarden signups open vs
#[test]
fn vaultwarden_signups_open_vs_closed() {
    let sandbox = Sandbox::new();
    seed_common_files(&sandbox);
    let topology = services_host_topology(None);

    let mut install_closed = reroot_input(&sandbox, base_input());
    install_closed.vaultwarden_allow_signups = false;
    let input_closed = host_input(&["vaultwarden"], HostRole::SingleHost, Language::En, install_closed);
    let out_closed = render(&input_closed, &topology, &TestFacts::new(&sandbox));
    assert!(out_closed.contains("Signups: closed — invite users from the admin panel"));
    assert!(!out_closed.contains("Signups: open"));

    let mut install_open = reroot_input(&sandbox, base_input());
    install_open.vaultwarden_allow_signups = true;
    let input_open = host_input(&["vaultwarden"], HostRole::SingleHost, Language::En, install_open);
    let out_open = render(&input_open, &topology, &TestFacts::new(&sandbox));
    assert!(out_open.contains("Signups: open"));
}

#[test]
fn local_only_drops_the_ptr_and_dns_reminder_lines() {
    let sandbox = Sandbox::new();
    seed_common_files(&sandbox);
    let mut install = reroot_input(&sandbox, base_input());
    install.local_only = true;
    let input = host_input(&["vaultwarden"], HostRole::SingleHost, Language::En, install);
    let topology = Topology::ServicesHost {
        ptr_ip: None,
        ptr_hostname: "irrelevant".to_string(),
        tunnel_endpoint: None,
    };
    let out = render(&input, &topology, &TestFacts::new(&sandbox));
    assert!(!out.contains("PTR at your provider"));
    assert!(!out.contains("Remember the DNS records"));
}

// ============================================================================ Small structural pins — cheap to state directly, expensive to lose. ============================================================================

#[test]
fn the_report_path_is_the_one_the_app_reads() {
    assert_eq!(REPORT_PATH, "/var/lib/gryonixnexus/install-report.txt");
}

#[test]
fn the_dkim_marker_line_is_ascii_and_identically_shaped_in_every_language() {
    let sandbox = Sandbox::new();
    seed_common_files(&sandbox);
    std::fs::write(sandbox.mailcow_dkim_dir.join("example.com.txt"), "v=DKIM1; k=rsa; p=TESTVALUE123").unwrap();
    let topology = services_host_topology(None);

    for language in [
        Language::En,
        Language::De,
        Language::Fr,
        Language::Es,
        Language::Ru,
        Language::Uk,
        Language::It,
        Language::Ja,
        Language::Zh,
    ] {
        let install = reroot_input(&sandbox, base_input());
        let input = host_input(&["mailcow"], HostRole::SingleHost, language, install);
        let out = render(&input, &topology, &TestFacts::new(&sandbox));
        let marker_line = out
            .lines()
            .find(|l| l.starts_with("GRYONIXNEXUS_DKIM "))
            .unwrap_or_else(|| panic!("no marker line for {language:?} in:\n{out}"));
        assert_eq!(
            marker_line, "GRYONIXNEXUS_DKIM dkim._domainkey.example.com v=DKIM1; k=rsa; p=TESTVALUE123",
            "marker line differs by language ({language:?}), which DKIMRecordParser cannot cope with"
        );
        assert!(marker_line.is_ascii(), "marker line is not ASCII for {language:?}: {marker_line}");
    }
}

#[test]
#[should_panic(expected = "report topology does not match the host role")]
fn render_panics_when_role_and_topology_disagree() {
    let sandbox = Sandbox::new();
    let install = reroot_input(&sandbox, base_input());
    let input = host_input(&[], HostRole::SingleHost, Language::En, install);
    let topology = Topology::Relay {
        wg_port: 51820,
        forwarded_ports: vec![80],
        home_wg_address: "10.8.0.2".to_string(),
        ptr_hostname: "relay.example.com".to_string(),
    };
    let _ = render(&input, &topology, &TestFacts::new(&sandbox));
}
