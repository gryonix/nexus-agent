//! Points one service's Caddy site at this machine or at another one.
//!
//! Only the `reverse_proxy` statements that aim at the service's own local
//! port, or at a remote this module wrote, are rewritten; the rest of the
//! site stays byte for byte.

use super::caddy::{owner_of, proxy_block, same_owner, top_level_blocks, AUTOCONFIG_MATCHER};

const DEFAULT_REMOTE_PORT: u16 = 443;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalProxy {
    pub port: u16,
    pub https: bool,
    pub overwrite_forwarded_for: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Upstream {
    Local,
    Remote { address: String, port: u16 },
}

#[derive(Debug, PartialEq, Eq)]
pub enum UpstreamError {
    NoSite,
    UnknownShape,
    BadAddress(String),
}

impl UpstreamError {
    pub fn message(&self) -> String {
        match self {
            Self::NoSite => "this machine has no site for the service".to_string(),
            Self::UnknownShape => "the service's site has a shape the agent does not rewrite".to_string(),
            Self::BadAddress(address) => format!("{address:?} is not an address the agent will write into Caddy"),
        }
    }
}

struct Statement {
    first: usize,
    end: usize,
    indent: usize,
    kind: Upstream,
}

fn safe_token(text: &str) -> bool {
    !text.is_empty() && text.chars().all(|c| c.is_ascii_alphanumeric() || ".-_:*".contains(c))
}

/// The remote proxy statement, written at the site's own indentation.
fn remote_proxy_block(address: &str, port: u16, server_name: &str) -> String {
    let host = if address.contains(':') { format!("[{address}]") } else { address.to_string() };
    format!(
        "reverse_proxy https://{host}:{port} {{\n        header_up Host {{host}}\n        transport http {{\n            tls_server_name {server_name}\n            tls_insecure_skip_verify\n        }}\n    }}"
    )
}

fn parse_remote(target: &str) -> Option<Upstream> {
    let rest = target.strip_prefix("https://")?;
    let (host, port) = rest.rsplit_once(':')?;
    let address = host.trim_start_matches('[').trim_end_matches(']').to_string();
    Some(Upstream::Remote { address, port: port.parse().ok()? })
}

fn statement_end(lines: &[&str], first: usize, indent: usize) -> usize {
    if !lines[first].trim_end().ends_with('{') {
        return first + 1;
    }
    let closes = |line: &&str| line.trim() == "}" && line.len() - line.trim_start().len() == indent;
    lines[first + 1..].iter().position(closes).map_or(lines.len(), |at| first + 1 + at + 1)
}

fn statements(lines: &[&str], local: &LocalProxy) -> Vec<Statement> {
    let mut found = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        let trimmed = lines[index].trim_start();
        let Some(rest) = trimmed.strip_prefix("reverse_proxy ") else {
            index += 1;
            continue;
        };
        let indent = lines[index].len() - trimmed.len();
        let end = statement_end(lines, index, indent);
        let target = rest.trim_end_matches('{').trim();
        let local_targets = [format!("127.0.0.1:{}", local.port), format!("https://127.0.0.1:{}", local.port)];
        let remote = lines[index..end].iter().any(|line| line.trim().starts_with("tls_server_name"));
        let kind = if local_targets.iter().any(|t| t == target) {
            Some(Upstream::Local)
        } else if remote {
            parse_remote(target)
        } else {
            None
        };
        if let Some(kind) = kind {
            found.push(Statement { first: index, end, indent, kind });
        }
        index = end;
    }
    found
}

fn indented(text: &str, indent: usize) -> Vec<String> {
    let extra = " ".repeat(indent.saturating_sub(4));
    text.split('\n')
        .enumerate()
        .map(|(row, line)| if row == 0 { format!("{}{line}", " ".repeat(indent)) } else { format!("{extra}{line}") })
        .collect()
}

fn header_name(block: &str) -> Option<String> {
    let header = block.lines().next()?.trim().strip_suffix('{')?.trim();
    Some(header.split(',').next()?.trim().to_string())
}

fn wanted_text(target: &Upstream, local: &LocalProxy, name: &str) -> String {
    match target {
        Upstream::Local => proxy_block(local.port, local.https, local.overwrite_forwarded_for),
        Upstream::Remote { address, port } => remote_proxy_block(address, *port, name),
    }
}

fn rewrite_block(block: &str, local: &LocalProxy, target: &Upstream) -> Option<String> {
    let mut lines: Vec<String> = block.split('\n').map(str::to_string).collect();
    let borrowed: Vec<&str> = block.split('\n').collect();
    let found = statements(&borrowed, local);
    if found.is_empty() {
        return None;
    }
    let name = header_name(block).unwrap_or_default();
    for statement in found.iter().rev().filter(|s| s.kind != *target) {
        let replacement = indented(&wanted_text(target, local, &name), statement.indent);
        lines.splice(statement.first..statement.end, replacement);
    }
    Some(lines.join("\n"))
}

fn owned_blocks<'a>(caddyfile: &'a str, owner: &str) -> Vec<&'a str> {
    top_level_blocks(caddyfile)
        .into_iter()
        .filter(|block| !block.contains(AUTOCONFIG_MATCHER))
        .filter(|block| owner_of(block).is_some_and(|found| same_owner(&found, owner)))
        .collect()
}

fn checked(target: &Upstream, name: &str) -> Result<(), UpstreamError> {
    if let Upstream::Remote { address, .. } = target {
        if !safe_token(address) {
            return Err(UpstreamError::BadAddress(address.clone()));
        }
        if !safe_token(name) {
            return Err(UpstreamError::BadAddress(name.to_string()));
        }
    }
    Ok(())
}

/// What the service's site proxies to now.
pub fn current(caddyfile: &str, owner: &str, local: &LocalProxy) -> Result<Upstream, UpstreamError> {
    let blocks = owned_blocks(caddyfile, owner);
    if blocks.is_empty() {
        return Err(UpstreamError::NoSite);
    }
    blocks
        .iter()
        .find_map(|block| {
            let lines: Vec<&str> = block.split('\n').collect();
            statements(&lines, local).into_iter().next().map(|s| s.kind)
        })
        .ok_or(UpstreamError::UnknownShape)
}

pub fn with_upstream(
    caddyfile: &str,
    owner: &str,
    local: &LocalProxy,
    target: &Upstream,
) -> Result<Option<String>, UpstreamError> {
    let blocks = owned_blocks(caddyfile, owner);
    if blocks.is_empty() {
        return Err(UpstreamError::NoSite);
    }
    let name = header_name(blocks[0]).unwrap_or_default();
    checked(target, &name)?;
    let mut text = caddyfile.to_string();
    let mut recognised = false;
    for block in blocks.iter().rev() {
        let Some(rewritten) = rewrite_block(block, local, target) else { continue };
        recognised = true;
        if rewritten != *block {
            let start = block.as_ptr() as usize - caddyfile.as_ptr() as usize;
            text.replace_range(start..start + block.len(), &rewritten);
        }
    }
    if !recognised {
        return Err(UpstreamError::UnknownShape);
    }
    Ok((text != caddyfile).then_some(text))
}

/// The first name the service's site answers to.
pub fn site_name(caddyfile: &str, owner: &str) -> Option<String> {
    owned_blocks(caddyfile, owner).first().and_then(|block| header_name(block))
}

pub fn remote_port(requested: u32) -> u16 {
    u16::try_from(requested).ok().filter(|port| *port != 0).unwrap_or(DEFAULT_REMOTE_PORT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::install::caddy::{
        caddyfile, site, site_overwriting_forwarded_for, site_with_public_paths, site_with_sso,
    };

    const OWNER: &str = "vaultwarden";

    fn local() -> LocalProxy {
        LocalProxy { port: 8222, https: false, overwrite_forwarded_for: false }
    }

    fn remote() -> Upstream {
        Upstream::Remote { address: "10.8.0.5".to_string(), port: 443 }
    }

    fn file(sites: &[String]) -> String {
        caddyfile(sites)
    }

    fn round_trip(site_text: String, local: LocalProxy) {
        let other = site("adguard-home", "dns.example.com", 3000, true, false, false);
        let original = file(&[other.clone(), site_text]);
        let moved = with_upstream(&original, OWNER, &local, &remote()).unwrap().unwrap();
        assert!(moved.contains("reverse_proxy https://10.8.0.5:443 {"));
        assert!(moved.contains("tls_server_name vault.example.com"));
        assert!(moved.contains(&other), "other sites stay untouched");
        assert_eq!(current(&moved, OWNER, &local).unwrap(), remote());
        let back = with_upstream(&moved, OWNER, &local, &Upstream::Local).unwrap().unwrap();
        assert_eq!(back, original);
    }

    #[test]
    fn a_plain_site_goes_out_and_comes_back_byte_for_byte() {
        round_trip(site(OWNER, "vault.example.com", 8222, false, false, false), local());
    }

    #[test]
    fn a_guarded_site_with_internal_tls_round_trips() {
        round_trip(site(OWNER, "vault.example.com", 8222, true, false, true), local());
    }

    #[test]
    fn an_https_upstream_round_trips() {
        let https = LocalProxy { https: true, ..local() };
        round_trip(site(OWNER, "vault.example.com", 8222, true, true, false), https);
    }

    #[test]
    fn a_site_that_overwrites_the_forwarded_for_header_round_trips() {
        let xff = LocalProxy { overwrite_forwarded_for: true, ..local() };
        round_trip(site_overwriting_forwarded_for(OWNER, "vault.example.com", 8222, true, false, false), xff);
    }

    #[test]
    fn a_site_behind_single_sign_on_round_trips() {
        round_trip(site_with_sso(OWNER, "vault.example.com", 8222, true, false, false, true), local());
    }

    #[test]
    fn both_branches_of_a_public_path_site_are_rewritten() {
        let paths = vec!["/hook/*".to_string()];
        let text = site_with_public_paths(OWNER, "vault.example.com", 8222, true, false, false, false, &paths, false);
        let moved = with_upstream(&text, OWNER, &local(), &remote()).unwrap().unwrap();
        assert_eq!(moved.matches("reverse_proxy https://10.8.0.5:443 {").count(), 2);
        assert_eq!(with_upstream(&moved, OWNER, &local(), &Upstream::Local).unwrap().unwrap(), text);
    }

    #[test]
    fn pointing_at_where_it_already_points_changes_nothing() {
        let text = site(OWNER, "vault.example.com", 8222, false, false, false);
        assert_eq!(with_upstream(&text, OWNER, &local(), &Upstream::Local).unwrap(), None);
        let moved = with_upstream(&text, OWNER, &local(), &remote()).unwrap().unwrap();
        assert_eq!(with_upstream(&moved, OWNER, &local(), &remote()).unwrap(), None);
    }

    #[test]
    fn a_remote_site_can_move_to_another_remote() {
        let text = site(OWNER, "vault.example.com", 8222, false, false, false);
        let first = with_upstream(&text, OWNER, &local(), &remote()).unwrap().unwrap();
        let other = Upstream::Remote { address: "nas.lan".to_string(), port: 8443 };
        let second = with_upstream(&first, OWNER, &local(), &other).unwrap().unwrap();
        assert!(second.contains("reverse_proxy https://nas.lan:8443 {"));
        assert!(!second.contains("10.8.0.5"));
    }

    #[test]
    fn an_ipv6_address_is_bracketed_and_read_back() {
        let text = site(OWNER, "vault.example.com", 8222, false, false, false);
        let v6 = Upstream::Remote { address: "fd00::5".to_string(), port: 443 };
        let moved = with_upstream(&text, OWNER, &local(), &v6).unwrap().unwrap();
        assert!(moved.contains("reverse_proxy https://[fd00::5]:443 {"));
        assert_eq!(current(&moved, OWNER, &local()).unwrap(), v6);
    }

    #[test]
    fn a_missing_site_and_an_unknown_shape_are_told_apart() {
        let text = site("nextcloud", "cloud.example.com", 8080, false, false, false);
        assert_eq!(with_upstream(&text, OWNER, &local(), &remote()), Err(UpstreamError::NoSite));
        let odd = site(OWNER, "vault.example.com", 9999, false, false, false);
        assert_eq!(with_upstream(&odd, OWNER, &local(), &remote()), Err(UpstreamError::UnknownShape));
        assert_eq!(current(&odd, OWNER, &local()), Err(UpstreamError::UnknownShape));
    }

    #[test]
    fn an_address_that_could_break_the_file_is_refused() {
        let text = site(OWNER, "vault.example.com", 8222, false, false, false);
        for bad in ["a b", "x}\nrespond 200", "", "h\"ost"] {
            let target = Upstream::Remote { address: bad.to_string(), port: 443 };
            assert!(matches!(with_upstream(&text, OWNER, &local(), &target), Err(UpstreamError::BadAddress(_))));
        }
    }

    #[test]
    fn the_site_name_is_the_first_name_of_the_block() {
        let text = site(OWNER, "vault.example.com, vault.example.org", 8222, false, false, false);
        assert_eq!(site_name(&text, OWNER).as_deref(), Some("vault.example.com"));
    }

    #[test]
    fn the_remote_port_defaults_to_https() {
        assert_eq!(remote_port(0), 443);
        assert_eq!(remote_port(8443), 8443);
        assert_eq!(remote_port(70000), 443);
    }
}
