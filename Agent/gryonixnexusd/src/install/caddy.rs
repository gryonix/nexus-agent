#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebIngress {
    pub hostname: String,
    pub upstream_port: u16,
    pub admin_guard: bool,
    pub upstream_https: bool,
    pub public_paths: Vec<String>,
}

pub const ADMIN_GUARD_PATH: &str = "/etc/caddy/gryonixnexus-admin-guard";

/// One file per site still waiting for its first account
pub const SETUP_GUARD_DIR: &str = "/etc/caddy/gryonixnexus-setup";

/// Sites whose first visitor becomes their administrator
pub const FIRST_VISITOR_ADMIN: [&str; 6] =
    ["immich", "jellyfin", "home-assistant", "n8n", "open-webui", "anythingllm"];

pub const SETUP_GUARD_RULES: &str = "@gryonixnexus_setup_relay {\n    remote_ip 10.8.0.0/24\n    not remote_ip 10.8.0.254/32\n}\nrespond @gryonixnexus_setup_relay \"This site opens to the internet once its first account exists. Connect to your WireGuard VPN to create it.\" 403\n@gryonixnexus_setup_public not remote_ip private_ranges\nrespond @gryonixnexus_setup_public \"This site opens to the internet once its first account exists. Connect to your WireGuard VPN to create it.\" 403\n@gryonixnexus_setup_tunnel header Cf-Connecting-IP *\nrespond @gryonixnexus_setup_tunnel \"This site opens to the internet once its first account exists. Connect to your WireGuard VPN to create it.\" 403\n";

pub fn setup_guard_import(owner: &str) -> String {
    format!("import {SETUP_GUARD_DIR}/{owner}*")
}

/// Without WireGuard nobody could reach a guarded site
pub fn with_setup_guard(owner: &str, installed: &[String], site: String) -> String {
    let has_wireguard = installed.iter().any(|id| id == "wireguard-vpn");
    if !has_wireguard || !FIRST_VISITOR_ADMIN.contains(&owner) {
        return site;
    }
    let Some(at) = site.find(&format!("import {ADMIN_GUARD_PATH}")) else { return site };
    let line_start = site[..at].rfind('\n').map_or(0, |i| i + 1);
    let indent = &site[line_start..at];
    format!("{}{}\n{indent}{}", &site[..at], setup_guard_import(owner), &site[at..])
}

pub fn setup_guarded_owner(site: &str) -> Option<String> {
    let start = site.find(&format!("import {SETUP_GUARD_DIR}/"))? + SETUP_GUARD_DIR.len() + 8;
    let owner = site[start..].split('*').next()?;
    FIRST_VISITOR_ADMIN.contains(&owner).then(|| owner.to_string())
}

pub(super) fn proxy_block(upstream_port: u16, upstream_https: bool, overwrite_forwarded_for: bool) -> String {
    if upstream_https {
        format!(
            "reverse_proxy https://127.0.0.1:{upstream_port} {{\n        header_up Host {{host}}\n        transport http {{\n            tls_insecure_skip_verify\n        }}\n    }}"
        )
    } else if overwrite_forwarded_for {
        format!(
            "reverse_proxy 127.0.0.1:{upstream_port} {{\n        header_up X-Forwarded-For {{remote_host}}\n    }}"
        )
    } else {
        format!("reverse_proxy 127.0.0.1:{upstream_port}")
    }
}

fn owner_line(owner: &str) -> String {
    format!("# {OWNER_TAG} {owner}")
}

const OWNER_TAG: &str = "gryonixnexus:";

const PUBLIC_PATHS_MATCHER: &str = "gryonixnexus_open";

pub fn owner_of(block: &str) -> Option<String> {
    block.lines().skip(1).find_map(|line| {
        let line = line.trim();
        let rest = line.strip_prefix('#')?.trim_start();
        rest.strip_prefix(OWNER_TAG)
            .map(|owner| owner.trim().to_string())
            .filter(|owner| !owner.is_empty())
    })
}

pub fn same_owner(a: &str, b: &str) -> bool {
    let canonical = |owner: &str| if owner == "vpn-panel" { "vpn".to_string() } else { owner.to_string() };
    canonical(a) == canonical(b)
}

/// The Caddyfile without the blocks one service owns
pub fn without_owner(caddyfile: &str, owner: &str) -> String {
    let mut kept = String::new();
    let (mut block, mut depth) = (String::new(), 0i32);
    let mut skip_blank = false;
    for line in caddyfile.split_inclusive('\n') {
        if depth == 0 && block.is_empty() && !line.contains('{') {
            if !(skip_blank && line.trim().is_empty()) {
                kept.push_str(line);
            }
            skip_blank = false;
            continue;
        }
        block.push_str(line);
        depth += line.matches('{').count() as i32 - line.matches('}').count() as i32;
        if depth <= 0 {
            let owned = owner_of(&block).is_some_and(|found| same_owner(&found, owner));
            if !owned {
                kept.push_str(&block);
            }
            skip_blank = owned;
            block.clear();
            depth = 0;
        }
    }
    kept.push_str(&block);
    kept
}

/// A byte-exact port of `ServiceInfraSections.caddySite`.
pub fn site(owner: &str, hostname: &str, upstream_port: u16, admin_guard: bool, upstream_https: bool, tls_internal: bool) -> String {
    site_with_sso(owner, hostname, upstream_port, admin_guard, upstream_https, tls_internal, false)
}

pub fn site_with_sso(
    owner: &str,
    hostname: &str,
    upstream_port: u16,
    admin_guard: bool,
    upstream_https: bool,
    tls_internal: bool,
    sso: bool,
) -> String {
    site_with_public_paths(owner, hostname, upstream_port, admin_guard, upstream_https, tls_internal, sso, &[], false)
}

pub fn site_with_public_paths(
    owner: &str,
    hostname: &str,
    upstream_port: u16,
    admin_guard: bool,
    upstream_https: bool,
    tls_internal: bool,
    sso: bool,
    public_paths: &[String],
    overwrite_forwarded_for: bool,
) -> String {
    let proxy = proxy_block(upstream_port, upstream_https, overwrite_forwarded_for);
    let tls_line = if tls_internal { "tls internal\n    " } else { "" };
    let sso_line = if sso {
        format!("{}\n    ", super::authelia::forward_auth_block())
    } else {
        String::new()
    };
    let portal: &[&str] = if sso { portal_paths(owner) } else { &[] };
    let owner = format!("{}\n    ", owner_line(owner));
    if !portal.is_empty() && public_paths.is_empty() {
        let guard_line =
            if admin_guard { format!("import {ADMIN_GUARD_PATH}\n        ") } else { String::new() };
        let nested = |block: &str| block.replace('\n', "\n    ");
        let proxy = nested(&proxy);
        let sso_line = nested(&sso_line);
        let paths = portal.join(" ");
        return format!(
            "{hostname} {{\n    {owner}{tls_line}@{PORTAL_PATHS_MATCHER} path {paths}\n    handle @{PORTAL_PATHS_MATCHER} {{\n        {guard_line}{sso_line}{proxy}\n    }}\n    handle {{\n        {guard_line}{proxy}\n    }}\n}}"
        );
    }
    if !public_paths.is_empty() && (admin_guard || sso) {
        let guard_line =
            if admin_guard { format!("import {ADMIN_GUARD_PATH}\n        ") } else { String::new() };
        let nested = |block: &str| block.replace('\n', "\n    ");
        let proxy = nested(&proxy);
        let sso_line = nested(&sso_line);
        let paths = public_paths.join(" ");
        if !portal.is_empty() {
            let portal = portal.join(" ");
            return format!(
                "{hostname} {{\n    {owner}{tls_line}@{PUBLIC_PATHS_MATCHER} path {paths}\n    @{PORTAL_PATHS_MATCHER} path {portal}\n    handle @{PUBLIC_PATHS_MATCHER} {{\n        {proxy}\n    }}\n    handle @{PORTAL_PATHS_MATCHER} {{\n        {guard_line}{sso_line}{proxy}\n    }}\n    handle {{\n        {guard_line}{proxy}\n    }}\n}}"
            );
        }
        return format!(
            "{hostname} {{\n    {owner}{tls_line}@{PUBLIC_PATHS_MATCHER} path {paths}\n    handle @{PUBLIC_PATHS_MATCHER} {{\n        {proxy}\n    }}\n    handle {{\n        {guard_line}{sso_line}{proxy}\n    }}\n}}"
        );
    }
    if !admin_guard {
        format!("{hostname} {{\n    {owner}{tls_line}{sso_line}{proxy}\n}}")
    } else {
        format!("{hostname} {{\n    {owner}{tls_line}import {ADMIN_GUARD_PATH}\n    {sso_line}{proxy}\n}}")
    }
}

/// Matcher for the paths the portal still covers
pub const PORTAL_PATHS_MATCHER: &str = "gryonixnexus_portal";

pub fn portal_paths(owner: &str) -> &'static [&'static str] {
    match owner {
        "mailcow" => &["/admin", "/admin/*", "/domainadmin", "/domainadmin/*", "/rspamd", "/rspamd/*"],
        _ => &[],
    }
}

/// Paths mail apps sync over, open whatever the guard says
pub fn sync_paths(owner: &str) -> &'static [&'static str] {
    match owner {
        "mailcow" => super::mail::mailcow::SYNC_PATHS,
        _ => &[],
    }
}

/// The Caddyfile with portal-split sites in today's shape
pub fn with_current_portal_split(caddyfile: &str) -> String {
    let blocks: Vec<String> = top_level_blocks(caddyfile)
        .into_iter()
        .map(|block| portal_split_block(block).unwrap_or_else(|| block.to_string()))
        .collect();
    without_extra_autoconfig_sites(blocks).join("\n\n")
}

/// Only the last autoconfig site stays; two would clash
fn without_extra_autoconfig_sites(blocks: Vec<String>) -> Vec<String> {
    let marker = format!("@{AUTOCONFIG_MATCHER} path");
    let Some(last) = blocks.iter().rposition(|block| block.contains(&marker)) else { return blocks };
    blocks.into_iter().enumerate().filter(|(index, block)| *index == last || !block.contains(&marker)).map(|(_, block)| block).collect()
}

/// A mailcow block whose names are only autodiscover and autoconfig
fn serves_only_autoconfig(block: &str) -> bool {
    let trimmed = block.trim();
    let Some(names) = trimmed.lines().next().and_then(|line| line.strip_suffix(" {")) else { return false };
    owner_of(trimmed).as_deref() == Some("mailcow")
        && names.split(", ").all(|name| name.starts_with("autodiscover.") || name.starts_with("autoconfig."))
}

/// An autoconfig block turned into a full site, put back
fn restored_autoconfig_block(trimmed: &str) -> Option<String> {
    if trimmed.contains(AUTOCONFIG_MATCHER) {
        return None;
    }
    let names: Vec<String> = trimmed.lines().next()?.strip_suffix(" {")?.split(", ").map(str::to_string).collect();
    let upstream = trimmed.lines().find_map(|line| line.trim().strip_prefix("reverse_proxy "))?;
    let port = upstream.trim_end_matches('{').trim().trim_start_matches("https://").strip_prefix("127.0.0.1:")?.parse().ok()?;
    Some(autoconfig_site("mailcow", &names, port))
}

/// One mail block rendered again, when its shape is older
fn portal_split_block(block: &str) -> Option<String> {
    let trimmed = block.trim();
    if serves_only_autoconfig(trimmed) {
        return restored_autoconfig_block(trimmed);
    }
    let owner = owner_of(trimmed)?;
    let sso = trimmed.contains("forward_auth");
    let open: Vec<String> = sync_paths(&owner).iter().map(|path| path.to_string()).collect();
    if portal_paths(&owner).is_empty() || (!sso && open.is_empty()) {
        return None;
    }
    let names = trimmed.lines().next()?.strip_suffix(" {")?;
    let upstream = trimmed.lines().find_map(|line| line.trim().strip_prefix("reverse_proxy "))?;
    let upstream = upstream.trim_end_matches('{').trim();
    let (https, address) = match upstream.strip_prefix("https://") {
        Some(rest) => (true, rest),
        None => (false, upstream),
    };
    let port = address.strip_prefix("127.0.0.1:")?.parse().ok()?;
    let guard = trimmed.lines().any(|line| line.trim() == format!("import {ADMIN_GUARD_PATH}"));
    let tls_internal = trimmed.lines().any(|line| line.trim() == "tls internal");
    let current = site_with_public_paths(&owner, names, port, guard, https, tls_internal, sso, &open, false);
    (current != trimmed).then_some(current)
}

/// Matcher for the files mail apps configure themselves from
pub const AUTOCONFIG_MATCHER: &str = "gryonixnexus_autoconfig";

/// Autodiscover and autoconfig paths, nothing else of the upstream
pub const AUTOCONFIG_PATHS: &[&str] = &["/autodiscover/*", "/mail/config-v1.1.xml", "/.well-known/autoconfig/*"];

/// Public site serving only mail autoconfiguration files
pub fn autoconfig_site(owner: &str, names: &[String], upstream_port: u16) -> String {
    let proxy = proxy_block(upstream_port, true, false).replace('\n', "\n    ");
    let paths = AUTOCONFIG_PATHS.join(" ");
    format!(
        "{} {{\n    {}\n    @{AUTOCONFIG_MATCHER} path {paths}\n    handle @{AUTOCONFIG_MATCHER} {{\n        {proxy}\n    }}\n    handle {{\n        respond 404\n    }}\n}}",
        names.join(", "),
        owner_line(owner)
    )
}

/// The Caddyfile with exactly one autoconfig site, or none
pub fn with_autoconfig_site(caddyfile_text: &str, site: Option<&str>) -> String {
    let marker = format!("@{AUTOCONFIG_MATCHER} path");
    let mut blocks: Vec<String> = top_level_blocks(caddyfile_text)
        .into_iter()
        .map(str::trim)
        .filter(|block| !block.is_empty() && !block.contains(&marker) && !serves_only_autoconfig(block))
        .map(str::to_string)
        .collect();
    blocks.extend(site.map(str::to_string));
    caddyfile(&blocks)
}

pub fn mailcow_domains(caddyfile_text: &str) -> Vec<String> {
    top_level_blocks(caddyfile_text)
        .into_iter()
        .map(str::trim)
        .filter(|block| owner_of(block).as_deref() == Some("mailcow") && !block.contains(AUTOCONFIG_MATCHER))
        .filter_map(|block| block.lines().next()?.strip_suffix(" {").map(str::to_string))
        .flat_map(|names| names.split(", ").filter_map(|n| n.strip_prefix("mail.").map(str::to_string)).collect::<Vec<_>>())
        .collect()
}

pub fn site_overwriting_forwarded_for(
    owner: &str,
    hostname: &str,
    upstream_port: u16,
    admin_guard: bool,
    upstream_https: bool,
    tls_internal: bool,
) -> String {
    site_with_public_paths(owner, hostname, upstream_port, admin_guard, upstream_https, tls_internal, false, &[], true)
}

pub(super) fn top_level_blocks(text: &str) -> Vec<&str> {
    let bytes = text.as_bytes();
    let (mut pieces, mut start, mut depth) = (Vec::new(), 0usize, 0i32);
    let (mut quote, mut comment) = (None::<u8>, false);
    let mut i = 0;
    while i < bytes.len() {
        let byte = bytes[i];
        if comment {
            comment = byte != b'\n';
        } else if let Some(open) = quote {
            if byte == b'\\' {
                i += 1;
            } else if byte == open {
                quote = None;
            }
        } else {
            match byte {
                b'"' | b'`' => quote = Some(byte),
                b'#' if i == 0 || bytes[i - 1].is_ascii_whitespace() => comment = true,
                b'{' => depth += 1,
                b'}' => depth -= 1,
                _ => {}
            }
        }
        if byte == b'\n' && quote.is_none() && depth <= 0 && bytes.get(i + 1) == Some(&b'\n') {
            pieces.push(&text[start..i]);
            start = i + 2;
            i += 2;
            depth = 0;
            continue;
        }
        i += 1;
    }
    pieces.push(&text[start..]);
    pieces
}

pub fn caddyfile(sites: &[String]) -> String {
    sites.join("\n\n")
}

pub fn merge_site(existing: &str, new_site_names: &[String], new_site: &str) -> String {
    let header_prefix = format!("{} {{", new_site_names.join(", "));
    let mut blocks: Vec<String> = top_level_blocks(existing)
        .into_iter()
        .map(str::trim)
        .filter(|block| !block.is_empty())
        .map(str::to_string)
        .collect();
    blocks.retain(|block| !block.starts_with(&header_prefix) && !is_package_welcome_site(block));
    blocks.push(new_site.to_string());
    let owners_global = blocks.iter().find(|block| is_global_block(block)).cloned();
    blocks.retain(|block| !is_global_block(block));
    blocks.insert(0, merged_global(owners_global.as_deref()));
    caddyfile(&blocks)
}

/// The package's `:80` welcome page, which swallows every HTTP redirect
fn is_package_welcome_site(block: &str) -> bool {
    let header = block.lines().map(str::trim).find(|line| !line.is_empty() && !line.starts_with('#'));
    header.is_some_and(|line| line.starts_with(":80") && line.ends_with('{')) && block.contains("/usr/share/caddy")
}

pub fn conflicting_names(existing: &str, new_site_names: &[String], owner: &str) -> Vec<String> {
    let own_header = format!("{} {{", new_site_names.join(", "));
    let others: String = top_level_blocks(existing)
        .into_iter()
        .map(str::trim)
        .filter(|block| !block.is_empty())
        .filter(|block| {
            if !block.starts_with(&own_header) {
                return true;
            }
            matches!(owner_of(block), Some(other) if !same_owner(&other, owner))
        })
        .collect::<Vec<_>>()
        .join("\n\n");
    let taken = served_hostnames(&others);
    new_site_names
        .iter()
        .filter(|name| taken.iter().any(|held| held.eq_ignore_ascii_case(name)))
        .cloned()
        .collect()
}

/// The Caddyfile's global block, byte-identical to `ServiceInfraSections.caddyGlobalOptions`
pub const GLOBAL_OPTIONS: &str = "{\n\torder respond before forward_auth\n\tservers {\n\t\tprotocols h1 h2\n\t}\n}";

/// A global options block, whatever it currently says
fn is_global_block(block: &str) -> bool {
    block.trim_start().lines().next().is_some_and(|line| line.trim() == "{")
}

fn merged_global(existing: Option<&str>) -> String {
    let Some(existing) = existing.map(str::trim) else { return GLOBAL_OPTIONS.to_string() };
    let lines: Vec<&str> = existing.lines().collect();
    if lines.len() < 2 || lines.last().map(|line| line.trim()) != Some("}") {
        return existing.to_string();
    }
    let inner = &lines[1..lines.len() - 1];
    let has = |prefix: &str| inner.iter().any(|line| line.trim_start().starts_with(prefix));
    let mut out = vec!["{".to_string()];
    if !has("order respond before forward_auth") {
        out.push("\torder respond before forward_auth".to_string());
    }
    out.extend(inner.iter().map(|line| line.to_string()));
    if !has("servers") {
        out.extend(["\tservers {", "\t\tprotocols h1 h2", "\t}"].map(String::from));
    }
    out.push("}".to_string());
    out.join("\n")
}

/// The Caddyfile with today's directives in its global block
pub fn with_current_global_options(caddyfile_text: &str) -> String {
    let blocks: Vec<&str> = top_level_blocks(caddyfile_text).into_iter().map(str::trim).filter(|b| !b.is_empty()).collect();
    let Some(global) = blocks.iter().find(|b| is_global_block(b)) else { return caddyfile_text.to_string() };
    let merged = merged_global(Some(global));
    if blocks.first() == Some(global) && merged == *global {
        return caddyfile_text.to_string();
    }
    let mut kept: Vec<String> = vec![merged];
    kept.extend(blocks.iter().filter(|b| !is_global_block(b)).map(|b| b.to_string()));
    caddyfile(&kept)
}

pub fn served_hostnames(caddyfile: &str) -> Vec<String> {
    let mut names = Vec::new();
    for block in top_level_blocks(caddyfile) {
        let Some(header) = block.trim().lines().next() else { continue };
        let Some(names_part) = header.trim().strip_suffix('{') else { continue };
        for name in names_part.split(',') {
            let name = name.trim();
            if name.is_empty() || name.contains(char::is_whitespace) || name.contains("://") {
                continue;
            }
            if !names.iter().any(|existing| existing == name) {
                names.push(name.to_string());
            }
        }
    }
    names
}

/// The deployment's domains, worked out from the names it serves
pub fn domains(served: &[String]) -> Vec<String> {
    let mut counts: Vec<(String, usize)> = Vec::new();
    for name in served {
        let Some((_, rest)) = name.split_once('.') else { continue };
        if !rest.contains('.') {
            continue;
        }
        match counts.iter_mut().find(|(candidate, _)| candidate == rest) {
            Some((_, count)) => *count += 1,
            None => counts.push((rest.to_string(), 1)),
        }
    }
    counts.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    counts.into_iter().map(|(domain, _)| domain).collect()
}

#[cfg(test)]
mod global_options_tests {
    use super::*;

    const OLD_GLOBAL: &str = "{\n\torder respond before forward_auth\n}";

    #[test]
    fn an_older_global_block_is_replaced_once() {
        let site = site("vaultwarden", "vault.example.com", 8082, true, false, false);
        let file = format!("{OLD_GLOBAL}\n\n{site}");
        let upgraded = with_current_global_options(&file);
        assert_eq!(upgraded, format!("{GLOBAL_OPTIONS}\n\n{site}"));
        assert_eq!(with_current_global_options(&upgraded), upgraded);
    }

    #[test]
    fn a_file_without_a_global_block_is_left_alone() {
        let site = site("vaultwarden", "vault.example.com", 8082, true, false, false);
        assert_eq!(with_current_global_options(&site), site);
    }

    #[test]
    fn merging_drops_an_older_global_block() {
        let site = site("vaultwarden", "vault.example.com", 8082, true, false, false);
        let merged = merge_site(&format!("{OLD_GLOBAL}\n\n{site}"), &["dns.example.com".to_string()], "dns.example.com {\n    x\n}");
        assert_eq!(merged.matches("order respond before forward_auth").count(), 1);
        assert!(merged.starts_with(GLOBAL_OPTIONS));
    }

    #[test]
    fn the_owners_own_global_options_survive() {
        let owners = "{\n\temail admin@example.com\n\tacme_dns cloudflare token\n}";
        let site = site("vaultwarden", "vault.example.com", 8082, true, false, false);
        let merged = merge_site(&format!("{owners}\n\n{site}"), &["dns.example.com".to_string()], "dns.example.com {\n    x\n}");
        assert!(merged.contains("email admin@example.com"));
        assert!(merged.contains("acme_dns cloudflare token"));
        assert_eq!(merged.matches("order respond before forward_auth").count(), 1);
        assert_eq!(merged.matches("protocols h1 h2").count(), 1);
        assert_eq!(with_current_global_options(&merged), merged);
    }

    #[test]
    fn an_owners_servers_block_is_not_overwritten() {
        let owners = "{\n\tservers {\n\t\tprotocols h1 h2 h3\n\t}\n}";
        let merged = merge_site(owners, &["a.example.com".to_string()], "a.example.com {\n    x\n}");
        assert!(merged.contains("protocols h1 h2 h3"));
        assert_eq!(merged.matches("servers").count(), 1);
    }

    #[test]
    fn a_hand_written_site_with_a_blank_line_stays_in_one_piece() {
        let hand = "blog.example.com {\n    root * /var/www\n\n    file_server\n}";
        let site = site("vaultwarden", "vault.example.com", 8082, true, false, false);
        let file = format!("{GLOBAL_OPTIONS}\n\n{hand}\n\n{site}");
        let merged = merge_site(&file, &["vault.example.com".to_string()], &site);
        assert!(merged.contains(hand), "the hand-written block must come through whole");
        assert_eq!(merged.matches('{').count(), merged.matches('}').count());
        assert!(served_hostnames(&file).contains(&"blog.example.com".to_string()));
    }

    #[test]
    fn splitting_by_depth_gives_the_text_back() {
        let text = "{\n\ta\n}\n\nx {\n  one\n\n  two\n}\n\n# note {\ny {\n}\n";
        assert_eq!(top_level_blocks(text).join("\n\n"), text);
        assert_eq!(top_level_blocks(text).len(), 3);
    }
}

#[cfg(test)]
mod autoconfig_tests {
    use super::*;

    fn names() -> Vec<String> {
        vec!["autodiscover.example.com".to_string(), "autoconfig.example.com".to_string()]
    }

    #[test]
    fn autoconfig_site_proxies_only_the_autoconfig_paths() {
        let site = autoconfig_site("mailcow", &names(), 18443);
        assert!(site.starts_with("autodiscover.example.com, autoconfig.example.com {\n    # gryonixnexus: mailcow\n"));
        assert!(site.contains("@gryonixnexus_autoconfig path /autodiscover/* /mail/config-v1.1.xml /.well-known/autoconfig/*"));
        assert!(site.contains("reverse_proxy https://127.0.0.1:18443"));
        assert!(site.contains("handle {\n        respond 404\n    }"));
        assert!(!site.contains("forward_auth") && !site.contains(ADMIN_GUARD_PATH));
        assert!(!site.contains("\n\n"));
    }

    #[test]
    fn with_autoconfig_site_replaces_and_removes_the_one_block() {
        let mail = site("mailcow", "mail.example.com", 18443, true, true, false);
        let first = with_autoconfig_site(&mail, Some(&autoconfig_site("mailcow", &names(), 18443)));
        assert_eq!(first.matches(AUTOCONFIG_MATCHER).count(), 2);
        let again = with_autoconfig_site(&first, Some(&autoconfig_site("mailcow", &names()[..1], 18443)));
        assert_eq!(again.matches("@gryonixnexus_autoconfig path").count(), 1);
        assert!(!again.contains("autoconfig.example.com {"));
        assert_eq!(with_autoconfig_site(&first, None), mail);
    }

    #[test]
    fn mailcow_domains_reads_the_mail_names_and_skips_autoconfig() {
        let mail = site("mailcow", "mail.example.com, mail.example.org", 18443, true, true, false);
        let file = with_autoconfig_site(&mail, Some(&autoconfig_site("mailcow", &names(), 18443)));
        assert_eq!(mailcow_domains(&file), vec!["example.com", "example.org"]);
        assert!(mailcow_domains(&site("vaultwarden", "vault.example.com", 8082, true, false, false)).is_empty());
    }

    #[test]
    fn removing_mailcow_removes_its_autoconfig_site() {
        let mail = site("mailcow", "mail.example.com", 18443, true, true, false);
        let file = with_autoconfig_site(&mail, Some(&autoconfig_site("mailcow", &names(), 18443)));
        assert!(!without_owner(&file, "mailcow").contains("autodiscover"));
    }

    #[test]
    fn rebuilding_mail_sites_leaves_the_autoconfig_site_alone() {
        let mail = site("mailcow", "mail.example.com", 18443, true, true, false);
        let file = with_autoconfig_site(&mail, Some(&autoconfig_site("mailcow", &names(), 18443)));
        let rebuilt = with_current_portal_split(&file);
        assert!(rebuilt.contains(&autoconfig_site("mailcow", &names(), 18443)), "{rebuilt}");
        assert_eq!(rebuilt.matches("autodiscover.example.com").count(), 1);
    }

    #[test]
    fn an_autoconfig_site_turned_into_a_mail_site_is_put_back_once() {
        let mail = site("mailcow", "mail.example.com", 18443, true, true, false);
        let names = names();
        let turned = site_with_public_paths("mailcow", &names.join(", "), 18443, true, true, false, false,
                                           &super::super::mail::mailcow::SYNC_PATHS.iter().map(|p| p.to_string()).collect::<Vec<_>>(), false);
        let broken = caddyfile(&[mail.clone(), turned.clone(), autoconfig_site("mailcow", &names, 18443)]);
        let healed = with_current_portal_split(&broken);
        assert_eq!(healed.matches("autodiscover.example.com").count(), 1, "{healed}");
        assert_eq!(healed.matches("autodiscover.example.com, autoconfig.example.com {").count(), 1, "{healed}");
        let replaced = with_autoconfig_site(&caddyfile(&[mail, turned]), Some(&autoconfig_site("mailcow", &names, 18443)));
        assert_eq!(replaced.matches("autodiscover.example.com, autoconfig.example.com {").count(), 1, "{replaced}");
    }
}

#[cfg(test)]
mod tests {
    fn older_mail_site(names: &str, proxy: &str) -> String {
        format!(
            "{names} {{\n    # gryonixnexus: mailcow\n    import {ADMIN_GUARD_PATH}\n    {}\n    {proxy}\n}}",
            super::super::authelia::forward_auth_block()
        )
    }

    /// The shape shipped briefly, with webmail paths skipping the portal
    const OWN_SIGN_IN_SHAPE: &str = "mail.example.com {\n    # gryonixnexus: mailcow\n    @gryonixnexus_own_sign_in path /SOGo /SOGo/*\n    handle @gryonixnexus_own_sign_in {\n        import /etc/caddy/gryonixnexus-admin-guard\n        reverse_proxy https://127.0.0.1:18443 {\n            header_up Host {host}\n            transport http {\n                tls_insecure_skip_verify\n            }\n        }\n    }\n    handle {\n        import /etc/caddy/gryonixnexus-admin-guard\n        forward_auth 127.0.0.1:8094 {\n            uri /api/authz/forward-auth\n        }\n        reverse_proxy https://127.0.0.1:18443 {\n            header_up Host {host}\n            transport http {\n                tls_insecure_skip_verify\n            }\n        }\n    }\n}";

    #[test]
    fn older_mail_sites_keep_the_portal_for_admin_pages_only() {
        let names = "mail.example.com, mail.example.org";
        let proxy = "reverse_proxy https://127.0.0.1:18443 {\n        transport http {\n            tls_insecure_skip_verify\n        }\n    }";
        let other = site_with_sso("nextcloud", "files.example.com", 8081, true, false, false, true);
        let file = format!("{GLOBAL_OPTIONS}\n\n{}\n\n{other}\n", older_mail_site(names, proxy));

        let upgraded = with_current_portal_split(&file);

        let expected = site_with_public_paths("mailcow", names, 18443, true, true, false, true, &sync(), false);
        assert_eq!(upgraded, format!("{GLOBAL_OPTIONS}\n\n{expected}\n\n{other}\n"));
        assert_eq!(with_current_portal_split(&upgraded), upgraded);

        let from_own_sign_in = with_current_portal_split(OWN_SIGN_IN_SHAPE);
        let expected = site_with_public_paths("mailcow", "mail.example.com", 18443, true, true, false, true, &sync(), false);
        assert_eq!(from_own_sign_in, expected);
    }

    fn sync() -> Vec<String> {
        sync_paths("mailcow").iter().map(|path| path.to_string()).collect()
    }

    fn fixture(name: &str) -> String {
        let path = format!("{}/tests/fixtures/install/{name}", env!("CARGO_MANIFEST_DIR"));
        std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("missing fixture {path}: {err}"))
    }

    #[test]
    fn mail_sync_paths_skip_the_guard_and_the_portal() {
        let site = site_with_public_paths("mailcow", "mail.example.com", 18443, true, true, false, true, &sync(), false);
        assert_eq!(site, fixture("caddy-mailcow-sync-paths__caddy-site.txt"));
        let open = site.split("    handle ").nth(1).expect("an open branch");
        assert!(open.starts_with("@gryonixnexus_open {"), "{site}");
        assert!(!open.contains("import") && !open.contains("forward_auth"), "{site}");
    }

    #[test]
    fn older_mail_sites_without_the_portal_open_their_sync_paths() {
        let names = "mail.example.com, mail.example.org";
        let older = site("mailcow", names, 18443, true, true, false);
        let other = site("nextcloud", "files.example.com", 8081, true, false, false);
        let file = format!("{GLOBAL_OPTIONS}\n\n{older}\n\n{other}\n");

        let upgraded = with_current_portal_split(&file);

        let expected = site_with_public_paths("mailcow", names, 18443, true, true, false, false, &sync(), false);
        assert_eq!(upgraded, format!("{GLOBAL_OPTIONS}\n\n{expected}\n\n{other}\n"));
        assert!(expected.contains("@gryonixnexus_open path /SOGo/dav "), "{expected}");
        assert_eq!(with_current_portal_split(&upgraded), upgraded);
    }

    #[test]
    fn sites_in_todays_shape_or_without_mail_stay_as_they_are() {
        let plain_mail = site_with_public_paths("mailcow", "mail.example.com", 18443, true, true, false, false, &sync(), false);
        let portal_mail = site_with_public_paths("mailcow", "mail.example.com", 18443, true, true, false, true, &sync(), false);
        let other = site_with_sso("nextcloud", "files.example.com", 8081, true, false, false, true);
        let unmarked = "mail.example.com {\n    forward_auth 127.0.0.1:8094\n    reverse_proxy 127.0.0.1:1\n}";
        for file in [plain_mail, portal_mail, other, unmarked.to_string()] {
            assert_eq!(with_current_portal_split(&file), file);
        }
    }

    #[test]
    fn a_removed_service_takes_every_block_it_owns() {
        let file = "{\n\temail a@b.c\n}\n\nimport /x\n\nhome.local {\n    # gryonixnexus: home-assistant\n    reverse_proxy 127.0.0.1:8123\n}\n\nfiles.local {\n    # gryonixnexus: nextcloud\n    handle {\n        reverse_proxy 127.0.0.1:8081\n    }\n}\n\nold.local {\n    reverse_proxy 127.0.0.1:1\n}\n";
        let left = without_owner(file, "nextcloud");
        assert!(!left.contains("files.local"), "{left}");
        assert!(left.contains("home.local {") && left.contains("old.local {") && left.contains("import /x"));
        assert!(!left.contains("\n\n\n"), "{left}");
        assert_eq!(without_owner(file, "immich"), file);
    }

    // ------------------------------------------------- one name, one service

    fn two_site_file() -> String {
        merge_site(
            &merge_site("", &["dns.example.com".to_string()],
                        &site("adguard-home", "dns.example.com", 8080, false, false, false)),
            &["cloud.example.com".to_string()],
            &site("nextcloud", "cloud.example.com", 8081, false, false, false),
        )
    }

    fn two_site_file_without_owners() -> String {
        merge_site(
            &merge_site("", &["dns.example.com".to_string()], "dns.example.com {\n\treverse_proxy 127.0.0.1:8080\n}"),
            &["cloud.example.com".to_string()],
            "cloud.example.com {\n\treverse_proxy 127.0.0.1:8081\n}",
        )
    }

    #[test]
    fn a_name_another_block_already_serves_is_a_conflict() {
        let taken = conflicting_names(
            &two_site_file(),
            &["dns.example.com".to_string(), "dns.example.org".to_string()],
            "immich",
        );
        assert_eq!(taken, vec!["dns.example.com".to_string()]);
    }

    #[test]
    fn the_conflict_is_found_regardless_of_case() {
        let taken = conflicting_names(
            &two_site_file(),
            &["DNS.Example.COM".to_string(), "extra.example.org".to_string()],
            "immich",
        );
        assert_eq!(taken, vec!["DNS.Example.COM".to_string()]);
    }

    #[test]
    fn a_service_does_not_conflict_with_its_own_previous_block() {
        assert!(conflicting_names(&two_site_file(), &["cloud.example.com".to_string()], "nextcloud").is_empty());
    }

    #[test]
    fn another_service_asking_for_the_same_names_is_a_conflict() {
        let taken = conflicting_names(&two_site_file(), &["cloud.example.com".to_string()], "immich");
        assert_eq!(taken, vec!["cloud.example.com".to_string()],
                   "a stranger's block with our exact names was taken for our own");
    }

    #[test]
    fn a_block_from_before_owners_existed_is_never_somebody_elses() {
        assert!(
            conflicting_names(&two_site_file_without_owners(),
                              &["cloud.example.com".to_string()], "nextcloud").is_empty(),
            "an install was refused a site it has been serving since before blocks said whose they were"
        );
        assert!(
            conflicting_names(&two_site_file_without_owners(),
                              &["cloud.example.com".to_string()], "immich").is_empty()
        );
    }

    #[test]
    fn a_fresh_name_is_not_a_conflict() {
        assert!(conflicting_names(&two_site_file(), &["mc.example.com".to_string()], "crafty-controller").is_empty());
    }

    #[test]
    fn only_the_names_that_are_taken_are_reported() {
        let taken = conflicting_names(
            &two_site_file(),
            &["mc.example.com".to_string(), "dns.example.com".to_string()],
            "crafty-controller",
        );
        assert_eq!(taken, vec!["dns.example.com".to_string()]);
    }
    use super::*;

    #[test]
    fn the_package_welcome_page_goes_when_a_site_is_added() {
        let stock = "# The Caddyfile is an easy way to configure your Caddy web server.\n\n:80 {\n\t# Set this path to your site's directory.\n\troot * /usr/share/caddy\n\n\t# Enable the static file server.\n\tfile_server\n}\n";
        let site = site("adguard-home", "dns.example.com", 8087, true, false, false);
        let merged = merge_site(stock, &["dns.example.com".to_string()], &site);
        assert!(!merged.contains("/usr/share/caddy"), "{merged}");
        assert!(merged.contains("dns.example.com {"));
    }

    #[test]
    fn an_owner_site_on_port_80_stays() {
        let own = ":80 {\n\trespond \"hello\"\n}\n";
        let site = site("adguard-home", "dns.example.com", 8087, true, false, false);
        assert!(merge_site(own, &["dns.example.com".to_string()], &site).contains("respond \"hello\""));
    }

    #[test]
    fn served_names_come_back_out_of_a_file_this_module_wrote() {
        let file = merge_site(
            &merge_site("", &["vault.example.com".into()],
                        &site("vaultwarden", "vault.example.com", 8080, false, false, false)),
            &["mail.example.com".into(), "mail.alias.com".into()],
            &site("mailcow", "mail.example.com, mail.alias.com", 8443, false, true, false),
        );
        let names = served_hostnames(&file);
        assert!(names.contains(&"vault.example.com".to_string()), "{names:?}");
        assert!(names.contains(&"mail.example.com".to_string()), "{names:?}");
        assert!(names.contains(&"mail.alias.com".to_string()), "{names:?}");
        // The global options block has no names before its brace.
        assert!(!names.iter().any(|n| n.contains('{')), "{names:?}");
    }

    #[test]
    fn the_domain_most_names_agree_on_comes_first() {
        let served = vec![
            "mail.example.com".to_string(),
            "vault.example.com".to_string(),
            "cloud.example.com".to_string(),
            "mail.alias.net".to_string(),
        ];
        assert_eq!(domains(&served), vec!["example.com", "alias.net"]);
    }

    #[test]
    fn a_service_on_its_own_hostname_does_not_outvote_the_deployment() {
        let served = vec![
            "mail.example.com".to_string(),
            "vault.example.com".to_string(),
            "status.someones-other-domain.org".to_string(),
        ];
        assert_eq!(domains(&served).first().map(String::as_str), Some("example.com"));
    }

    #[test]
    fn a_local_only_host_still_yields_its_name() {
        let served = vec!["dns.home.local".to_string(), "cloud.home.local".to_string()];
        assert_eq!(domains(&served), vec!["home.local"]);
    }

    #[test]
    fn nothing_to_derive_from_answers_nothing_rather_than_guessing() {
        assert!(domains(&[]).is_empty());
        assert!(domains(&["localhost".to_string()]).is_empty());
    }

    #[test]
    fn no_guard_no_tls_internal_is_the_plain_two_line_block() {
        assert_eq!(
            site("vaultwarden", "vault.example.com", 8080, false, false, false),
            "vault.example.com {\n    # gryonixnexus: vaultwarden\n    reverse_proxy 127.0.0.1:8080\n}"
        );
    }

    #[test]
    fn guard_and_tls_internal_both_land_before_the_proxy_line() {
        assert_eq!(
            site("adguard-home", "dns.home.local", 8087, true, false, true),
            "dns.home.local {\n    # gryonixnexus: adguard-home\n    tls internal\n    import /etc/caddy/gryonixnexus-admin-guard\n    reverse_proxy 127.0.0.1:8087\n}"
        );
    }

    #[test]
    fn every_shape_of_block_says_whose_it_is() {
        for guard in [false, true] {
            for tls in [false, true] {
                for https in [false, true] {
                    let block = site("nextcloud", "cloud.example.com", 8080, guard, https, tls);
                    assert_eq!(
                        owner_of(&block).as_deref(),
                        Some("nextcloud"),
                        "guard={guard} tls={tls} https={https}"
                    );
                    let second = block.lines().nth(1).unwrap_or_default();
                    assert_eq!(second.trim(), "# gryonixnexus: nextcloud",
                               "the owner is not the first line inside the block");
                }
            }
        }
    }

    #[test]
    fn a_block_from_before_this_existed_names_nobody() {
        assert_eq!(owner_of("cloud.example.com {\n    reverse_proxy 127.0.0.1:8080\n}"), None);
    }

    #[test]
    fn the_header_line_is_not_an_owner() {
        assert_eq!(owner_of("# gryonixnexus: forged {\n    reverse_proxy 127.0.0.1:1\n}"), None);
        assert_eq!(owner_of(GLOBAL_OPTIONS), None);
    }

    #[test]
    fn every_site_owner_is_a_catalog_id() {
        use crate::install::*;
        let known = crate::install::execute::implemented_service_ids();
        let owners = [
            adguard::SERVICE_ID, authelia::SERVICE_ID, crafty::SERVICE_ID,
            forgejo::SERVICE_ID, gitlab::SERVICE_ID, headscale::SERVICE_ID,
            homepage::SERVICE_ID, immich::SERVICE_ID, jellyfin::SERVICE_ID,
            nextcloud::SERVICE_ID, passbolt::SERVICE_ID, photoprism::SERVICE_ID,
            pihole::SERVICE_ID, psono::SERVICE_ID, seafile::SERVICE_ID,
            vaultwarden::SERVICE_ID, mail::mailcow::SERVICE_ID, mail::mailu::SERVICE_ID,
            mail::dockermailserver::SERVICE_ID, vpn::panel::SERVICE_ID,
        ];
        for owner in owners {
            assert!(known.contains(&owner), "{owner} is not a service this agent installs");
        }
        let mut sorted = owners.to_vec();
        sorted.sort_unstable();
        let count = sorted.len();
        sorted.dedup();
        assert_eq!(sorted.len(), count, "two modules claim one catalog id");
    }

    #[test]
    fn an_empty_owner_line_says_nothing() {
        assert_eq!(owner_of("a.example.com {\n    # gryonixnexus:\n    x\n}"), None);
        assert_eq!(owner_of("a.example.com {\n    # gryonixnexus:   \n    x\n}"), None);
    }

    #[test]
    fn https_upstream_matches_the_swift_generators_own_output() {
        let path = format!(
            "{}/tests/fixtures/install/caddy-https-upstream__caddy-site.txt",
            env!("CARGO_MANIFEST_DIR")
        );
        let expected = std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("missing fixture {path}: {err}"));
        assert_eq!(site("mailcow", "mail.example.com, mail.example.org", 18443, true, true, false), expected);
    }

    #[test]
    fn caddyfile_joins_sites_with_a_blank_line() {
        assert_eq!(caddyfile(&["a {\n}".to_string(), "b {\n}".to_string()]), "a {\n}\n\nb {\n}");
    }

    // ─────────────────────────── merge_site ───────────────────────────

    fn sites_only(merged: &str) -> String {
        let prefix = format!("{GLOBAL_OPTIONS}\n\n");
        assert!(
            merged.starts_with(&prefix) || merged == GLOBAL_OPTIONS,
            "every Caddyfile this writes must open with the global block"
        );
        merged.strip_prefix(&prefix).unwrap_or("").to_string()
    }

    #[test]
    fn merging_into_an_empty_or_missing_file_yields_just_the_new_site() {
        assert_eq!(sites_only(&merge_site("", &["dns.example.com".to_string()], "dns.example.com {\n    x\n}")), "dns.example.com {\n    x\n}");
        assert_eq!(
            sites_only(&merge_site("   \n  ", &["dns.example.com".to_string()], "dns.example.com {\n    x\n}")),
            "dns.example.com {\n    x\n}"
        );
    }

    #[test]
    fn merging_appends_without_disturbing_an_unrelated_existing_site() {
        let existing = "vault.example.com {\n    reverse_proxy 127.0.0.1:8080\n}";
        let merged = sites_only(&merge_site(existing, &["dns.example.com".to_string()], "dns.example.com {\n    x\n}"));
        assert_eq!(merged, "vault.example.com {\n    reverse_proxy 127.0.0.1:8080\n}\n\ndns.example.com {\n    x\n}");
    }

    #[test]
    fn a_rerun_replaces_only_its_own_stale_block_and_leaves_the_rest() {
        let existing = "vault.example.com {\n    a\n}\n\ndns.example.com {\n    OLD\n}\n\nother.example.com {\n    b\n}";
        let merged = sites_only(&merge_site(existing, &["dns.example.com".to_string()], "dns.example.com {\n    NEW\n}"));
        assert_eq!(
            merged,
            "vault.example.com {\n    a\n}\n\nother.example.com {\n    b\n}\n\ndns.example.com {\n    NEW\n}"
        );
        assert!(!merged.contains("OLD"));
    }

    #[test]
    fn a_multi_name_header_is_matched_and_replaced_as_one_block() {
        let existing = "dns.example.com, dns.example.org {\n    OLD\n}";
        let merged = sites_only(&merge_site(
            existing,
            &["dns.example.com".to_string(), "dns.example.org".to_string()],
            "dns.example.com, dns.example.org {\n    NEW\n}",
        ));
        assert_eq!(merged, "dns.example.com, dns.example.org {\n    NEW\n}");
    }

    /// The global block is present, first, and never duplicated
    #[test]
    fn the_global_block_is_present_once_and_first() {
        let first = merge_site("", &["a.example.com".to_string()], "a.example.com {\n    x\n}");
        assert!(first.starts_with(GLOBAL_OPTIONS), "a fresh file must open with it");
        assert_eq!(first.matches("order respond before forward_auth").count(), 1);

        let again = merge_site(&first, &["b.example.com".to_string()], "b.example.com {\n    y\n}");
        assert!(again.starts_with(GLOBAL_OPTIONS));
        assert_eq!(again.matches("order respond before forward_auth").count(), 1);
        assert!(again.contains("a.example.com {\n    x\n}"), "the earlier site survives");

        let legacy = merge_site("old.example.com {\n    z\n}",
                                &["c.example.com".to_string()],
                                "c.example.com {\n    w\n}");
        assert!(legacy.starts_with(GLOBAL_OPTIONS));
        assert!(legacy.contains("old.example.com {\n    z\n}"));
    }

    #[test]
    fn a_hostname_that_is_a_prefix_of_another_sites_header_is_not_confused_with_it() {
        let existing = "dns.example.com.evil.net {\n    untouched\n}";
        let merged = merge_site(existing, &["dns.example.com".to_string()], "dns.example.com {\n    NEW\n}");
        assert!(merged.contains("dns.example.com.evil.net {\n    untouched\n}"), "unrelated lookalike header must survive");
        assert!(merged.contains("dns.example.com {\n    NEW\n}"));
    }
    #[test]
    fn only_mailcow_admin_pages_ask_for_the_portal() {
        let site = site_with_sso("mailcow", "mail.example.com", 18443, true, true, false, true);
        let (admin, rest) = site.split_once("    handle {").expect("two branches");
        assert!(admin.contains("path /admin /admin/* /domainadmin /domainadmin/* /rspamd /rspamd/*"), "{site}");
        assert!(admin.contains("forward_auth"));
        assert!(rest.contains("import /etc/caddy/gryonixnexus-admin-guard"), "webmail stays VPN-only");
        assert!(!rest.contains("forward_auth"), "mailbox users sign in to mailcow, not the portal");
        assert!(!site_with_sso("nextcloud", "files.example.com", 8081, true, false, false, true).contains("handle"));
        let fixture = std::fs::read_to_string(format!(
            "{}/tests/fixtures/install/caddy-mailcow-portal-paths__caddy-site.txt",
            env!("CARGO_MANIFEST_DIR")
        ))
        .expect("the Swift rendering");
        assert_eq!(site, fixture, "the agent renders what the app's generator renders");
    }

    #[test]
    fn the_panel_site_the_script_signed_is_the_vpns_own() {
        let file = "vpn.example.com {\n    # gryonixnexus: vpn-panel\n    reverse_proxy 127.0.0.1:51900\n}\n";
        assert!(conflicting_names(file, &["vpn.example.com".to_string()], "vpn").is_empty());
        assert_eq!(without_owner(file, "vpn").trim(), "");
        assert!(!conflicting_names(file, &["vpn.example.com".to_string()], "nextcloud").is_empty());
    }

    #[test]
    fn a_first_visitor_site_waits_behind_the_vpn_only_with_wireguard() {
        let site = site("immich", "photos.example.com", 2283, true, false, false);
        let installed = vec!["immich".to_string(), "wireguard-vpn".to_string()];
        let guarded = with_setup_guard("immich", &installed, site.clone());
        assert!(guarded.contains("    import /etc/caddy/gryonixnexus-setup/immich*\n    import /etc/caddy/gryonixnexus-admin-guard"));
        assert_eq!(setup_guarded_owner(&guarded).as_deref(), Some("immich"));
        assert_eq!(with_setup_guard("immich", &installed[..1], site.clone()), site);
        assert_eq!(with_setup_guard("vaultwarden", &installed, site.clone()), site);
        assert_eq!(setup_guarded_owner(&site), None);
    }

    #[test]
    fn the_setup_guard_sits_inside_the_guarded_handle_beside_public_paths() {
        let paths = vec!["/webhook/*".to_string()];
        let site = site_with_public_paths("n8n", "n8n.example.com", 8099, true, false, false, false, &paths, false);
        let guarded = with_setup_guard("n8n", &["wireguard-vpn".to_string()], site);
        assert!(guarded.contains("    handle {\n        import /etc/caddy/gryonixnexus-setup/n8n*\n        import /etc/caddy/gryonixnexus-admin-guard"));
        assert_eq!(guarded.matches("gryonixnexus-setup").count(), 1);
    }

    #[test]
    fn the_setup_rules_use_names_of_their_own() {
        for name in ["@gryonixnexus_setup_relay", "@gryonixnexus_setup_public", "@gryonixnexus_setup_tunnel"] {
            assert!(SETUP_GUARD_RULES.contains(name));
        }
        assert!(!SETUP_GUARD_RULES.contains("@gryonixnexus_public "));
        let denial = "This site opens to the internet once its first account exists. Connect to your WireGuard VPN to create it.";
        assert_eq!(SETUP_GUARD_RULES.matches(denial).count(), 3);
        assert!(SETUP_GUARD_RULES.starts_with("@gryonixnexus_setup_relay {\n    remote_ip 10.8.0.0/24\n    not remote_ip 10.8.0.254/32\n}\n"));
        assert!(SETUP_GUARD_RULES.ends_with(" 403\n"));
    }
}
