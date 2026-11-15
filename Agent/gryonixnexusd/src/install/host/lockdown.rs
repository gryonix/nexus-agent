//! Port of the admin-guard control — `/opt/gryonixnexus-admin-lockdown.sh`

use crate::install::caddy::ADMIN_GUARD_PATH;
use crate::install::vpn::panel::{ADMIN_LOCKDOWN_SH, LOCKDOWN_SCRIPT_PATH};

pub const SCRIPT_PATH: &str = LOCKDOWN_SCRIPT_PATH;

pub const GUARD_PATH: &str = ADMIN_GUARD_PATH;

const VERBS: &[&str] = &["on", "only", "off", "status"];

pub fn render() -> String {
    ADMIN_LOCKDOWN_SH.trim_end_matches('\n').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> String {
        let path = format!(
            "{}/tests/fixtures/install/host/lockdown/{name}.txt",
            env!("CARGO_MANIFEST_DIR")
        );
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
    }

    /// Byte-for-byte parity against a real generated script
    #[test]
    fn fixture_parity() {
        let expected = fixture("A-adguard-full-access-en");
        assert_eq!(render(), expected.trim_end_matches('\n'));
    }

    #[test]
    fn every_verb_has_its_own_case_arm() {
        let script = render();
        for verb in VERBS {
            let arm = format!("  {verb})");
            assert!(script.contains(&arm), "missing case arm for {verb:?}:\n{script}");
        }
        assert!(script.contains("usage: $0 on|off|only host... [--no-vpn host...]|status"));
        assert!(script.contains("exit 64"));
    }

    #[test]
    fn a_bare_invocation_defaults_to_status_not_a_mutation() {
        assert!(render().contains(r#"case "${1:-status}" in"#));
    }

    #[test]
    fn an_empty_guard_file_means_public() {
        let script = render();
        assert!(script.contains(r#": > "$GUARD""#), "the `off` verb must truncate the guard file to empty");
        assert!(
            script.contains(r#"[ ! -s "$GUARD" ]"#),
            "`status` must read emptiness as the public state"
        );
    }

    #[test]
    fn only_rejects_an_empty_or_malformed_host_list() {
        let script = render();
        assert!(script.contains(r#"[ "$#" -ge 1 ]"#), "`only` with zero hosts must be rejected");
        assert!(
            script.contains(r#"*[!A-Za-z0-9.-]*|"") echo "invalid host: $h" >&2; exit 64 ;;"#),
            "each host must be validated against a fixed character class"
        );
    }

    #[test]
    fn the_guard_path_matches_caddys_own_constant() {
        assert!(render().contains(&format!("GUARD={GUARD_PATH}\n")));
    }

    #[test]
    fn script_path_matches_the_panel_installers_own_constant() {
        assert_eq!(SCRIPT_PATH, crate::install::vpn::panel::LOCKDOWN_SCRIPT_PATH);
    }

    fn run_sandboxed(dir: &std::path::Path, args: &[&str]) -> String {
        use std::os::unix::fs::PermissionsExt;
        let bin = dir.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        for (name, body) in [("ip", "#!/bin/sh\necho '2: eth0 inet 203.0.113.5/24 scope global eth0'\n"), ("systemctl", "#!/bin/sh\nexit 0\n")] {
            std::fs::write(bin.join(name), body).unwrap();
            std::fs::set_permissions(bin.join(name), std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let guard = dir.join("guard");
        let script = render().replace(crate::install::caddy::ADMIN_GUARD_PATH, guard.to_str().unwrap());
        std::fs::write(dir.join("wrapper.sh"), script).unwrap();
        let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap_or_default());
        let out = std::process::Command::new("bash").arg(dir.join("wrapper.sh")).args(args).env("PATH", path).output().unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    #[test]
    fn the_no_vpn_block_denies_vpn_ranges_for_listed_hosts_only() {
        let dir = std::env::temp_dir().join(format!("gnx-lockdown-novpn-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let said = run_sandboxed(&dir, &["only", "a.example.net", "b.example.net", "--no-vpn", "b.example.net"]);
        assert_eq!(said, "only a.example.net b.example.net");
        let guard = std::fs::read_to_string(dir.join("guard")).unwrap();
        let block = guard.split("@gryonixnexus_novpn {").nth(1).expect("no-vpn block");
        assert!(block.contains("host b.example.net\n"));
        assert!(!block.contains("a.example.net"));
        assert!(block.contains("remote_ip 10.8.0.0/24 10.9.0.0/24 10.10.0.0/24 10.11.0.0/24 203.0.113.5/32"));
        assert_eq!(run_sandboxed(&dir, &["status"]), "only a.example.net b.example.net");
        run_sandboxed(&dir, &["only", "a.example.net", "b.example.net"]);
        assert!(std::fs::read_to_string(dir.join("guard")).unwrap().contains("@gryonixnexus_novpn"));
        run_sandboxed(&dir, &["only", "a.example.net", "--no-vpn"]);
        assert!(!std::fs::read_to_string(dir.join("guard")).unwrap().contains("@gryonixnexus_novpn"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
