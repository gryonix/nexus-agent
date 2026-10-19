//! The root-owned wrapper the APP calls to install or update the agent

pub fn archive_path(user: &str) -> String {
    if user == "root" {
        format!("/root/{ARCHIVE_NAME}")
    } else {
        format!("/home/{user}/{ARCHIVE_NAME}")
    }
}

pub const ARCHIVE_NAME: &str = "gryonixnexus-agent-src.tar.gz";

pub const UNPACK_ROOT: &str = "/opt/gryonixnexus-agent-src";

/// The wrapper body, exactly as it lands on disk.
pub fn script(user: &str) -> String {
    format!(
        r#"#!/bin/bash
# Managed by gryonixNexus — installs or updates the control-plane agent
# from the archive the app uploaded into the control user's home.
#
# No arguments, deliberately: this runs under sudo, and an argument is
# an argument that reached root.
set -euo pipefail
ARCHIVE='{archive}'
UNPACK='{unpack}'

# The sudo caller's own upload wins; sudo sets SUDO_USER
caller_home="$(getent passwd "${{SUDO_USER:-root}}" | cut -d: -f6)"
if [ -n "$caller_home" ] && [ -s "$caller_home/{name}" ]; then
  ARCHIVE="$caller_home/{name}"
fi

[ -s "$ARCHIVE" ] || {{ echo "no agent sources uploaded ($ARCHIVE)" >&2; exit 1; }}

# --no-same-owner: the archive is written on a Mac, so its uids mean
# nothing here, and tar honouring them fails in ways that read like a
# corrupt archive.
rm -rf "$UNPACK"
install -d -m 700 "$UNPACK"
tar -xzf "$ARCHIVE" -C "$UNPACK" --no-same-owner
rm -f "$ARCHIVE"

[ -x "$UNPACK/Agent/bootstrap/install-agent.sh" ] \
  || {{ echo "the uploaded archive carries no bootstrap script" >&2; exit 1; }}
cd "$UNPACK/Agent"
exec bash bootstrap/install-agent.sh
"#,
        archive = archive_path(user),
        unpack = UNPACK_ROOT,
        name = ARCHIVE_NAME
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_generators_wrapper() {
        let fixture = include_str!("../../../tests/fixtures/install/host/agent_bootstrap/admin.txt");
        assert_eq!(script("admin"), fixture);
    }

    #[test]
    fn root_reads_its_own_home() {
        assert_eq!(archive_path("root"), "/root/gryonixnexus-agent-src.tar.gz");
        assert_eq!(archive_path("server-user"), "/home/server-user/gryonixnexus-agent-src.tar.gz");
    }

    #[test]
    fn the_wrapper_takes_no_arguments() {
        let body = script("admin");
        assert!(!body.contains("$1"), "an argument here is an argument that reached root");
        assert!(!body.contains("\"$@\""));
    }
}
