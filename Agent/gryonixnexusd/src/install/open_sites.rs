//! Sites rendered again with another set of paths open past the guard.

use super::caddy::{
    self, owner_of, serves_only_autoconfig, site_with_public_paths, top_level_blocks, ADMIN_GUARD_PATH,
    AUTOCONFIG_MATCHER, PUBLIC_PATHS_MATCHER, SETUP_GUARD_DIR,
};

/// The parts a site block renders from
#[derive(Debug, Clone, PartialEq, Eq)]
struct SiteParts {
    owner: String,
    names: String,
    port: u16,
    https: bool,
    guard: bool,
    tls_internal: bool,
    sso: bool,
    forwarded_for: bool,
    setup_guard: bool,
    open: Vec<String>,
}

/// One service's sites, as the app sees them
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenSite {
    pub owner: String,
    pub paths: Vec<String>,
    pub editable: bool,
}

fn has_line(block: &str, wanted: &str) -> bool {
    block.lines().any(|line| line.trim() == wanted)
}

fn upstream(block: &str) -> Option<(bool, u16)> {
    let line = block.lines().find_map(|line| line.trim().strip_prefix("reverse_proxy "))?;
    let address = line.trim_end_matches('{').trim();
    let (https, address) = match address.strip_prefix("https://") {
        Some(rest) => (true, rest),
        None => (false, address),
    };
    Some((https, address.strip_prefix("127.0.0.1:")?.parse().ok()?))
}

fn open_paths_of(block: &str) -> Vec<String> {
    let prefix = format!("@{PUBLIC_PATHS_MATCHER} path ");
    block
        .lines()
        .find_map(|line| line.trim().strip_prefix(&prefix).map(str::to_string))
        .map(|rest| rest.split_whitespace().map(str::to_string).collect())
        .unwrap_or_default()
}

fn site_parts(block: &str) -> Option<SiteParts> {
    let block = block.trim();
    let (https, port) = upstream(block)?;
    Some(SiteParts {
        owner: owner_of(block)?,
        names: block.lines().next()?.strip_suffix(" {")?.to_string(),
        port,
        https,
        guard: has_line(block, &format!("import {ADMIN_GUARD_PATH}")),
        tls_internal: has_line(block, "tls internal"),
        sso: block.contains("forward_auth"),
        forwarded_for: block.contains("header_up X-Forwarded-For {remote_host}"),
        setup_guard: block.contains(&format!("import {SETUP_GUARD_DIR}/")),
        open: open_paths_of(block),
    })
}

/// Setup guard goes before the first admin guard import
fn with_setup_import(owner: &str, site: String) -> String {
    let Some(at) = site.find(&format!("import {ADMIN_GUARD_PATH}")) else { return site };
    let line_start = site[..at].rfind('\n').map_or(0, |i| i + 1);
    let indent = &site[line_start..at];
    format!("{}{}\n{indent}{}", &site[..at], caddy::setup_guard_import(owner), &site[at..])
}

fn render(parts: &SiteParts, open: &[String]) -> String {
    let site = site_with_public_paths(
        &parts.owner,
        &parts.names,
        parts.port,
        parts.guard,
        parts.https,
        parts.tls_internal,
        parts.sso,
        open,
        parts.forwarded_for,
    );
    if parts.setup_guard { with_setup_import(&parts.owner, site) } else { site }
}

/// Parts that render back to the very same block
fn faithful_parts(block: &str) -> Option<SiteParts> {
    let parts = site_parts(block)?;
    (parts.guard && render(&parts, &parts.open) == block.trim()).then_some(parts)
}

fn is_autoconfig(block: &str) -> bool {
    block.contains(AUTOCONFIG_MATCHER) || serves_only_autoconfig(block.trim())
}

fn owned_sites<'a>(caddyfile: &'a str, owner: &str) -> Vec<&'a str> {
    top_level_blocks(caddyfile)
        .into_iter()
        .filter(|block| owner_of(block).as_deref() == Some(owner) && !is_autoconfig(block))
        .collect()
}

/// Every service's sites, in Caddyfile order
pub fn open_sites(caddyfile: &str) -> Vec<OpenSite> {
    let mut owners: Vec<String> = Vec::new();
    for block in top_level_blocks(caddyfile) {
        if let Some(owner) = owner_of(block).filter(|owner| !is_autoconfig(block) && !owners.contains(owner)) {
            owners.push(owner);
        }
    }
    owners
        .into_iter()
        .map(|owner| {
            let sites = owned_sites(caddyfile, &owner);
            let first = sites.first().map(|block| open_paths_of(block)).unwrap_or_default();
            let editable = sites.iter().all(|block| faithful_parts(block).is_some());
            OpenSite { owner, paths: first, editable }
        })
        .collect()
}

/// The Caddyfile with one service's sites opened at these paths
pub fn with_open_paths(caddyfile: &str, owner: &str, open: &[String]) -> Option<String> {
    let mut found = false;
    let mut blocks = Vec::new();
    for block in top_level_blocks(caddyfile) {
        if owner_of(block).as_deref() != Some(owner) || is_autoconfig(block) {
            blocks.push(block.to_string());
            continue;
        }
        let parts = faithful_parts(block)?;
        let lead = &block[..block.len() - block.trim_start().len()];
        let tail = &block[block.trim_end().len()..];
        blocks.push(format!("{lead}{}{tail}", render(&parts, open)));
        found = true;
    }
    found.then(|| blocks.join("\n\n"))
}

/// Whether a path is safe to write into a Caddyfile
pub fn is_valid_path(path: &str) -> bool {
    path.starts_with('/')
        && path != "/"
        && path != "/*"
        && path.len() <= 120
        && path.chars().all(|c| c.is_ascii_alphanumeric() || "/._-*".contains(c))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(list: &[&str]) -> Vec<String> {
        list.iter().map(|p| p.to_string()).collect()
    }

    fn guarded(owner: &str, host: &str, port: u16, open: &[String]) -> String {
        site_with_public_paths(owner, host, port, true, false, false, false, open, false)
    }

    #[test]
    fn a_closed_site_opens_and_closes_again() {
        let closed = guarded("nextcloud", "cloud.example.net", 8081, &[]);
        let file = format!("{{\n    email admin@example.net\n}}\n\n{closed}\n");
        let open = paths(&["/remote.php/*", "/ocs/*"]);
        let opened = with_open_paths(&file, "nextcloud", &open).unwrap();
        assert!(opened.contains("@gryonixnexus_open path /remote.php/* /ocs/*"));
        assert_eq!(open_sites(&opened)[0].paths, open);
        let closed_again = with_open_paths(&opened, "nextcloud", &[]).unwrap();
        assert_eq!(closed_again, file);
    }

    #[test]
    fn the_api_of_vaultwarden_can_be_closed() {
        let open = paths(&["/api/*", "/identity/*"]);
        let file = guarded("vaultwarden", "vault.example.net", 8082, &open);
        let sites = open_sites(&file);
        assert_eq!(sites, vec![OpenSite { owner: "vaultwarden".into(), paths: open, editable: true }]);
        let closed = with_open_paths(&file, "vaultwarden", &[]).unwrap();
        assert!(!closed.contains(PUBLIC_PATHS_MATCHER));
        assert!(closed.contains(&format!("import {ADMIN_GUARD_PATH}")));
    }

    #[test]
    fn the_setup_guard_survives_a_rewrite() {
        let site = with_setup_import("immich", guarded("immich", "photos.example.net", 2283, &[]));
        let opened = with_open_paths(&site, "immich", &paths(&["/api/*"])).unwrap();
        assert!(opened.contains(&caddy::setup_guard_import("immich")));
        assert_eq!(with_open_paths(&opened, "immich", &[]).unwrap(), site);
    }

    #[test]
    fn mail_portal_and_sync_paths_round_trip() {
        let sync = paths(&["/SOGo/dav/*", "/Microsoft-Server-ActiveSync"]);
        let site = site_with_public_paths("mailcow", "mail.example.net", 8443, true, true, false, false, &sync, false);
        let closed = with_open_paths(&site, "mailcow", &[]).unwrap();
        assert!(!closed.contains(PUBLIC_PATHS_MATCHER));
        assert_eq!(with_open_paths(&closed, "mailcow", &sync).unwrap(), site);
    }

    #[test]
    fn forwarded_for_and_sso_are_kept() {
        let hooks = paths(&["/webhook/*"]);
        let site = site_with_public_paths("n8n", "n8n.example.net", 5678, true, false, false, true, &hooks, true);
        let closed = with_open_paths(&site, "n8n", &[]).unwrap();
        assert!(closed.contains("forward_auth") && closed.contains("header_up X-Forwarded-For {remote_host}"));
        assert_eq!(with_open_paths(&closed, "n8n", &hooks).unwrap(), site);
    }

    #[test]
    fn a_hand_edited_site_is_left_alone() {
        let site = guarded("nextcloud", "cloud.example.net", 8081, &[]).replace("    import", "    encode gzip\n    import");
        assert!(with_open_paths(&site, "nextcloud", &paths(&["/ocs/*"])).is_none());
        assert!(!open_sites(&site)[0].editable);
    }

    #[test]
    fn an_unguarded_site_is_not_editable() {
        let site = site_with_public_paths("headscale", "mesh.example.net", 8091, false, false, false, false, &[], false);
        assert!(!open_sites(&site)[0].editable);
        assert!(with_open_paths(&site, "headscale", &paths(&["/api/*"])).is_none());
    }

    #[test]
    fn paths_that_would_open_the_page_are_refused() {
        assert!(is_valid_path("/api/*"));
        assert!(is_valid_path("/.well-known/*"));
        assert!(!is_valid_path("/"));
        assert!(!is_valid_path("/*"));
        assert!(!is_valid_path("api/*"));
        assert!(!is_valid_path("/api/* }"));
        assert!(!is_valid_path("/a\"b"));
    }
}
