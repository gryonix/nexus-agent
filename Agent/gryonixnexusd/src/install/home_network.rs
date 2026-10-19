//! A plain HTTP door for apps on a server without a trusted certificate.
//!
//! Phone and desktop apps refuse Caddy's own certificate, so each service
//! with apps also answers at `http://<server>:<port>`, open to private
//! addresses only. Every web service states whether it gets one, and why not.

use super::caddy;
use super::firewall;

pub const SNIPPET_PATH: &str = "/etc/caddy/gryonixnexus-home-network.caddy";
pub const FIREWALL_LABEL: &str = "home-network";
const OWNER_PREFIX: &str = "# gryonixnexus-home: ";

/// What a web service offers apps in the home network
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LanAccess {
    /// Apps connect over plain HTTP on this port
    Apps { port: u16 },
    /// A browser is the only client; the reason says why
    BrowserOnly(&'static str),
}

const HTTPS_BOUND: &str = "its sign-in and links are tied to its HTTPS name";

/// The decision for each web service of the catalog
pub fn lan_access(id: &str) -> Option<LanAccess> {
    use LanAccess::{Apps, BrowserOnly};
    Some(match id {
        "immich" => Apps { port: 12283 },
        "jellyfin" => Apps { port: 18096 },
        "home-assistant" => Apps { port: 18123 },
        "photoprism" => Apps { port: 12342 },
        "vaultwarden" => Apps { port: 18082 },
        "forgejo" => Apps { port: 18083 },
        "open-webui" => Apps { port: 18097 },
        "litellm" => Apps { port: 18098 },
        "anythingllm" => Apps { port: 18100 },
        "nextcloud" => Apps { port: 18081 },
        "seafile" => Apps { port: 18088 },
        "gitlab" => Apps { port: 18084 },
        "psono" => Apps { port: 18089 },
        "passbolt" => BrowserOnly(HTTPS_BOUND),
        "mailcow" | "mailu" | "docker-mailserver" => BrowserOnly("mail apps use IMAP and SMTP"),
        "headscale" => BrowserOnly("Tailscale clients need its HTTPS control address"),
        "authelia" => BrowserOnly("it signs people in for other sites"),
        "zigbee2mqtt" | "crafty-controller" | "adguard-home" | "pihole" | "homepage" | "vpn-panel" | "n8n"
        | "openclaw" => BrowserOnly("it has no apps"),
        _ => return None,
    })
}

/// One service's home-network door
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HomeSite {
    pub owner: String,
    pub port: u16,
    pub upstream: u16,
    pub guarded: bool,
}

/// The top-level blocks of a Caddyfile, as written
pub fn blocks(caddyfile: &str) -> Vec<String> {
    let mut out = Vec::new();
    let (mut depth, mut current) = (0i32, String::new());
    for line in caddyfile.lines() {
        if depth == 0 && line.trim().is_empty() {
            continue;
        }
        current.push_str(line);
        current.push('\n');
        depth += line.matches('{').count() as i32 - line.matches('}').count() as i32;
        if depth <= 0 {
            out.push(std::mem::take(&mut current));
            depth = 0;
        }
    }
    out
}

/// Sites on Caddy's own certificate whose service has apps
pub fn home_sites(caddyfile: &str) -> Vec<HomeSite> {
    let mut sites: Vec<HomeSite> = blocks(caddyfile).iter().filter_map(|block| home_site(block)).collect();
    sites.sort_by_key(|site| site.port);
    sites.dedup_by_key(|site| site.port);
    sites
}

fn home_site(block: &str) -> Option<HomeSite> {
    let owner = caddy::owner_of(block)?;
    let Some(LanAccess::Apps { port }) = lan_access(&owner) else { return None };
    let internal = block.lines().any(|l| l.trim() == "tls internal");
    let signed_on = block.contains("forward_auth");
    if !internal || signed_on {
        return None;
    }
    let site_upstream = block.lines().find_map(|l| {
        l.trim().strip_prefix("reverse_proxy 127.0.0.1:")?.split_whitespace().next()?.parse().ok()
    })?;
    let upstream = link_rewriter(&owner).unwrap_or(site_upstream);
    let guarded = block.contains(caddy::ADMIN_GUARD_PATH);
    Some(HomeSite { owner, port, upstream, guarded })
}

/// Services whose links need rewriting go through their rewriter
pub fn link_rewriter(owner: &str) -> Option<u16> {
    (owner == "seafile").then_some(super::seafile::HOME_DOOR_PORT)
}

/// A door is kept only while its upstream answers
fn answering(site: &HomeSite) -> bool {
    if link_rewriter(&site.owner).is_none() {
        return true;
    }
    let address = std::net::SocketAddr::from(([127, 0, 0, 1], site.upstream));
    std::net::TcpStream::connect_timeout(&address, std::time::Duration::from_millis(300)).is_ok()
}

/// The Caddy file with one plain HTTP site per door
pub fn snippet(sites: &[HomeSite]) -> String {
    let mut out = String::from("# Managed by gryonixNexus: plain HTTP for apps in the home network.\n");
    for site in sites {
        let guard = if site.guarded { format!("    import {}\n", caddy::ADMIN_GUARD_PATH) } else { String::new() };
        out.push_str(&format!(
            "\nhttp://:{} {{\n    {OWNER_PREFIX}{}\n{guard}    reverse_proxy 127.0.0.1:{}\n}}\n",
            site.port, site.owner, site.upstream
        ));
    }
    out
}

/// The Caddyfile importing the snippet, once
pub fn with_import(caddyfile: &str) -> String {
    let line = format!("import {SNIPPET_PATH}");
    if caddyfile.lines().any(|l| l.trim() == line) {
        return caddyfile.to_string();
    }
    format!("{}\n{line}\n", caddyfile.trim_end())
}

/// Firewall rules letting only private addresses reach the doors
pub fn firewall_rules(sites: &[HomeSite]) -> String {
    if sites.is_empty() {
        return String::new();
    }
    let ports = sites.iter().map(|s| s.port.to_string()).collect::<Vec<_>>().join(", ");
    let (table, chain) = (firewall::TABLE, firewall::CHAIN);
    format!(
        "# Managed by gryonixNexus: app ports for the home network only.\n\
         add rule {table} {chain} ip saddr {{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10 }} \
         tcp dport {{ {ports} }} accept comment \"{FIREWALL_LABEL}\"\n\
         add rule {table} {chain} ip6 saddr {{ fc00::/7, fe80::/10 }} tcp dport {{ {ports} }} accept comment \"{FIREWALL_LABEL}\"\n"
    )
}

/// Matches doors to the Caddyfile; true if Caddy must reload
pub fn write_files(caddyfile_path: &str, tunnel: bool) -> Result<bool, String> {
    let caddyfile = std::fs::read_to_string(caddyfile_path).unwrap_or_default();
    let sites: Vec<HomeSite> =
        if tunnel { Vec::new() } else { home_sites(&caddyfile).into_iter().filter(answering).collect() };
    let wanted = snippet(&sites);
    let mut changed = false;
    if std::fs::read_to_string(SNIPPET_PATH).ok().as_deref() != Some(wanted.as_str()) {
        std::fs::write(SNIPPET_PATH, &wanted).map_err(|err| format!("could not write {SNIPPET_PATH}: {err}"))?;
        changed = true;
    }
    let imported = with_import(&caddyfile);
    if !caddyfile.is_empty() && imported != caddyfile {
        std::fs::write(caddyfile_path, imported).map_err(|err| format!("could not write {caddyfile_path}: {err}"))?;
        changed = true;
    }
    Ok(changed)
}

/// Opens exactly the doors the Caddyfile now has
pub async fn apply_firewall(caddyfile_path: &str, tunnel: bool) -> Result<(), String> {
    let caddyfile = std::fs::read_to_string(caddyfile_path).unwrap_or_default();
    let sites: Vec<HomeSite> =
        if tunnel { Vec::new() } else { home_sites(&caddyfile).into_iter().filter(answering).collect() };
    firewall::apply_rules(FIREWALL_LABEL, &firewall_rules(&sites)).await.map(|_| ())
}

/// The doors this host has, for the app to show
pub fn doors(caddyfile_path: &str) -> Vec<HomeSite> {
    let snippet = std::fs::read_to_string(SNIPPET_PATH).unwrap_or_default();
    home_sites(&std::fs::read_to_string(caddyfile_path).unwrap_or_default())
        .into_iter()
        .filter(|site| snippet.contains(&format!("http://:{} {{", site.port)))
        .collect()
}

/// A Cloudflare tunnel already gives apps a trusted certificate
pub async fn tunnel_running() -> bool {
    let out = tokio::process::Command::new("docker")
        .args(["ps", "-q", "--filter", "name=^cloudflared$"])
        .output()
        .await;
    out.map(|o| !o.stdout.is_empty()).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CADDYFILE: &str = "{\n\torder respond before forward_auth\n}\n\n\
        photos.home.local {\n    # gryonixnexus: immich\n    tls internal\n    import /etc/caddy/gryonixnexus-admin-guard\n    reverse_proxy 127.0.0.1:2283\n}\n\n\
        seafile.home.local {\n    # gryonixnexus: seafile\n    tls internal\n    reverse_proxy 127.0.0.1:8088\n}\n\n\
        tv.example.com {\n    # gryonixnexus: jellyfin\n    reverse_proxy 127.0.0.1:8096\n}\n\n\
        home.home.local {\n    # gryonixnexus: home-assistant\n    tls internal\n    reverse_proxy 127.0.0.1:8123\n}\n";

    #[test]
    fn only_apps_on_caddys_own_certificate_get_a_door() {
        let sites = home_sites(CADDYFILE);
        let owners: Vec<&str> = sites.iter().map(|s| s.owner.as_str()).collect();
        assert_eq!(owners, vec!["immich", "seafile", "home-assistant"], "jellyfin has a real certificate");
        assert_eq!((sites[0].port, sites[0].upstream, sites[0].guarded), (12283, 2283, true));
        assert_eq!((sites[1].port, sites[1].upstream), (18088, 8188), "seafile goes through its link rewriter");
        assert_eq!((sites[2].port, sites[2].upstream, sites[2].guarded), (18123, 8123, false));
    }

    #[test]
    fn the_snippet_proxies_each_door() {
        let text = snippet(&home_sites(CADDYFILE));
        assert!(text.contains("http://:12283 {\n    # gryonixnexus-home: immich\n    import /etc/caddy/gryonixnexus-admin-guard\n    reverse_proxy 127.0.0.1:2283\n}"));
        assert!(text.contains("http://:18123 {\n    # gryonixnexus-home: home-assistant\n    reverse_proxy 127.0.0.1:8123\n}"));
    }

    #[test]
    fn a_site_behind_single_sign_on_keeps_its_guard() {
        let caddy = "photos.home.local {\n    # gryonixnexus: immich\n    tls internal\n    forward_auth 127.0.0.1:9091 {\n        uri /api/verify\n    }\n    reverse_proxy 127.0.0.1:2283\n}\n";
        assert!(home_sites(caddy).is_empty());
    }

    #[test]
    fn the_import_is_added_once() {
        let once = with_import(CADDYFILE);
        assert!(once.ends_with("import /etc/caddy/gryonixnexus-home-network.caddy\n"));
        assert_eq!(with_import(&once), once);
    }

    #[test]
    fn only_private_addresses_reach_the_doors() {
        let rules = firewall_rules(&home_sites(CADDYFILE));
        assert!(rules.contains("ip saddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10 } tcp dport { 12283, 18088, 18123 } accept"));
        assert!(rules.contains("ip6 saddr { fc00::/7, fe80::/10 } tcp dport { 12283, 18088, 18123 } accept"));
        assert!(firewall_rules(&[]).is_empty());
    }

    /// A new web service cannot ship without deciding about apps
    #[test]
    fn every_web_service_decides_about_apps() {
        let input = super::super::context::Input::default();
        for id in super::super::host::CATALOG_ORDER {
            let publishes = super::super::catalog::web_ingress_for(id, &input).is_some();
            if publishes {
                assert!(lan_access(id).is_some(), "{id} publishes a web page but says nothing about apps at home");
            }
        }
    }

    #[test]
    fn doors_never_collide() {
        let input = super::super::context::Input::default();
        let mut taken = std::collections::HashSet::new();
        for id in super::super::host::CATALOG_ORDER {
            if let Some(LanAccess::Apps { port }) = lan_access(id) {
                assert!(taken.insert(port), "{id} reuses door {port}");
                let upstream = super::super::catalog::web_ingress_for(id, &input).map(|w| w.upstream_port);
                assert_eq!(upstream.map(|u| u + 10000), Some(port), "{id}'s door is its port plus 10000");
            }
        }
    }
}
