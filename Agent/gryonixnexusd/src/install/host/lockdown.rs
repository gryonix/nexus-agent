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
        assert!(script.contains("usage: $0 on|off|only host...|status"));
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
}
