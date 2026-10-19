//! Every `/etc` path this crate names must have been THOUGHT ABOUT against the unit's sandbox

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// `/etc` paths the crate only ever READS
const READ_ONLY_ETC_PATHS: &[(&str, &str)] = &[
    (
        "/etc/passwd",
        "read to see whether the caddy user exists; the .deb that creates it \
         installs through systemd-run, outside this sandbox",
    ),
    (
        "/etc/fstab",
        "read to see which folders sit on the cache disk; the disk tasks \
         that write it run through systemd-run, outside this sandbox",
    ),
    (
        "/etc/os-release",
        "distribution detection — read to answer GetState, never written",
    ),
    (
        "/etc/hostname",
        "the FALLBACK for the host name; the kernel is asked first, because \
         cloud-init leaves this file EMPTY on first boot",
    ),
    (
        "/etc/nftables.conf",
        "named only to say the drop-in glob it includes; install/firewall.rs \
         never re-reads or rewrites it — rewriting it would be how docker's \
         NAT rules get erased",
    ),
    (
        "/etc/shadow",
        "referenced when checking whether a local account exists; the agent \
         never edits it",
    ),
    (
        "/etc/localtime",
        "named in the Containers section's never-archived list: a mount of it \
         is the HOST's clock leaking into a container's backup, not the \
         container's data. Compared against, never opened",
    ),
    (
        "/etc/timezone",
        "same list, same reason as /etc/localtime",
    ),
];

const NOT_A_WRITABLE_HOST_PATH: &[(&str, &str)] = &[
    (
        "/etc/passbolt",
        "a path INSIDE the Passbolt container, named only in comments quoting \
         the error its own server prints; the host side of that mount is \
         /opt/passbolt/secrets and is created by the executor",
    ),
    (
        "/etc/headscale",
        "the configuration directory INSIDE the Headscale container — the host \
         side is <headscale_path>/config, bind-mounted onto it, and that is \
         where both the agent's installer and its PublishMeshNames verb write. \
         The verb finds it through `docker inspect`'s mount list precisely \
         because the in-container path is NOT reachable from here",
    ),
    (
        "/etc/shadowsocks-rust",
        "the config path INSIDE the shadowsocks-rust container — the host side \
         is <shadowsocks_path>/config.json, mounted read-only onto it. The \
         agent writes the host side and never this one",
    ),
    (
        "/etc/openvpn",
        "the data directory INSIDE the OpenVPN container (its whole PKI, \
         server.conf and tls-crypt key live there); the host side is \
         <openvpn_path>/data. Listed even though the scanner does not see it \
         today — it only matches a literal that STARTS with a quote, and every \
         mention of this one sits mid-string (a mount spec, a shim's `PKI=` \
         line). A path that is excused only by the scanner's blind spot is \
         excused by accident",
    ),
    (
        "/etc/nftables.conf.bak.*",
        "Not a grant. Unlinking a file directly under /etc needs /etc ITSELF \
         writable, which ProtectSystem=full exists to prevent and no \
         ReadWritePaths= entry short of undoing the hardening could give. Two \
         things were then measured on a live host (2026-08-13) and both belong \
         here. First, this glob sits ONLY in the wrapper's --all branch, and \
         --all never reaches the agent (it would kill the agent mid-stream, so \
         ServiceRemovalRouting sends it over SSH) — so the file was never the \
         agent's to leave behind, and the earlier note claiming otherwise was \
         wrong about the path, not about the sandbox. Second, the sandbox part \
         was right and is now fixed at the class level: \
         uninstall::wrapper_command runs the wrapper as a TRANSIENT UNIT \
         (systemd-run), which has no ProtectSystem, so no path inside any of \
         its branches needs a grant. A host with no systemd-run keeps the old \
         direct spawn.",
    ),
    (
        "/etc/apt",
        "Not a grant, and for the class-level reason the two entries below \
         reach: install/packages.rs writes /etc/apt/sources.list.d/... for \
         Caddy and for NVIDIA's container toolkit, and both do it inside a \
         TRANSIENT UNIT (systemd-run), which has no ProtectSystem at all. \
         Granting /etc/apt here would widen the agent's own namespace for \
         writes the agent process never performs — and apt itself could not \
         run in that namespace anyway, which is why the escape exists.",
    ),
    (
        "/etc/ssh",
        "Not a grant, and deliberately not one. install/ssh_password.rs names \
         /etc/ssh/sshd_config.d/10-gryonixnexus-no-password.conf and \
         trusted_sources.rs names 60-gryonixnexus-tunnel.conf, but the agent \
         process writes neither (the trusted-source list goes through a \
         transient unit too): the whole step — the guard that reads \
         the control user's authorized_keys, the write, `sshd -t` and the \
         reload — runs in a TRANSIENT UNIT, which has no ProtectSystem and \
         needs no entry here (the same class-level answer the nftables backup \
         glob above arrived at). Adding /etc/ssh/sshd_config.d to \
         ReadWritePaths= would not even have worked: ProtectHome=true empties \
         /home and /root inside this namespace, so the key the guard has to \
         prove is unreadable from here no matter what /etc grants say — and a \
         grant only reaches hosts whose unit file is rewritten, which is the \
         fleet minus everyone who has not reinstalled the agent.",
    ),
];

fn repo_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is Agent/gryonixnexusd; the unit lives in Agent/systemd.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("Agent/")
        .to_path_buf()
}

/// Every `ReadWritePaths=` entry, still carrying its optional-marker.
fn unit_writable_entries() -> Vec<String> {
    let unit = std::fs::read_to_string(repo_root().join("systemd/gryonixnexusd.service"))
        .expect("the unit file must be readable from the crate");
    unit.lines()
        .filter_map(|line| line.trim().strip_prefix("ReadWritePaths="))
        .flat_map(|value| value.split_whitespace())
        .map(str::to_string)
        .collect()
}

/// The same entries as plain paths
fn unit_writable_paths() -> Vec<String> {
    unit_writable_entries()
        .iter()
        .map(|entry| entry.trim_start_matches('-').to_string())
        .collect()
}

fn etc_prefixes_in_sources() -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let mut stack = vec![Path::new(env!("CARGO_MANIFEST_DIR")).join("src")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("src/ must be readable") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("source file");
            for (index, _) in text.match_indices("\"/etc/") {
                let rest = &text[index + 1..];
                let literal: String = rest
                    .chars()
                    .take_while(|c| !matches!(c, '"' | '{' | '\n'))
                    .collect();
                let mut components = literal.split('/').filter(|c| !c.is_empty());
                let (etc, component) = (components.next(), components.next());
                if let (Some("etc"), Some(component)) = (etc, component) {
                    let prefix = if component == "systemd" {
                        "/etc/systemd/system".to_string()
                    } else {
                        format!("/etc/{component}")
                    };
                    found.insert(prefix);
                }
            }
        }
    }
    found
}

#[test]
fn every_etc_path_the_crate_names_is_writable_or_explicitly_read_only() {
    let writable = unit_writable_paths();
    let read_only: Vec<&str> = READ_ONLY_ETC_PATHS.iter().map(|(path, _)| *path).collect();

    let excused: Vec<&str> = NOT_A_WRITABLE_HOST_PATH.iter().map(|(path, _)| *path).collect();

    let mut unaccounted = Vec::new();
    for prefix in etc_prefixes_in_sources() {
        let covered_by_unit = writable.iter().any(|w| prefix.starts_with(w.as_str()));
        let declared_read_only = read_only.iter().any(|r| r.starts_with(prefix.as_str()));
        let declared_excused = excused.iter().any(|e| e.starts_with(prefix.as_str()));
        if !covered_by_unit && !declared_read_only && !declared_excused {
            unaccounted.push(prefix);
        }
    }

    assert!(
        unaccounted.is_empty(),
        "these /etc paths are used by the crate but are neither in the unit's \
         ReadWritePaths nor declared read-only in this test: {unaccounted:?}. \
         Under ProtectSystem=full a write to any of them returns EROFS at \
         runtime — decide which list it belongs in rather than finding out \
         from a live install."
    );
}

#[test]
fn the_firewall_dropin_directory_is_writable() {
    assert!(
        unit_writable_paths()
            .iter()
            .any(|p| p == "/etc/nftables.d"),
        "install/firewall.rs writes /etc/nftables.d/gryonixnexus-svc-<service>.nft, \
         and for VPN and mail a firewall failure is fatal by design"
    );
}

#[test]
fn only_a_guaranteed_directory_may_be_listed_without_the_optional_marker() {
    const GUARANTEED: &[&str] = &["/etc/systemd/system"];

    let bare: Vec<String> = unit_writable_entries()
        .into_iter()
        .filter(|entry| !entry.starts_with('-'))
        .filter(|entry| !GUARANTEED.contains(&entry.as_str()))
        .collect();

    assert!(
        bare.is_empty(),
        "these ReadWritePaths entries are listed bare but nothing guarantees they \
         exist: {bare:?}. A missing entry does not degrade — systemd fails the \
         whole mount namespace (226/NAMESPACE) and the agent never starts. \
         Prefix each with `-` unless you can say what created it."
    );
}

#[test]
fn the_sshd_dropin_directory_is_deliberately_not_granted() {
    let granted: Vec<String> = unit_writable_paths();
    assert!(
        !granted.iter().any(|p| p.starts_with("/etc/ssh")),
        "install/ssh_password.rs does its writing in a transient unit precisely \
         so this grant is unnecessary; ProtectHome would still hide the key its \
         guard has to prove. Granted paths: {granted:?}"
    );
}
