//! DNS-over-HTTPS for Pi-hole and AdGuard Home: a bridge container
//! answers on loopback, Caddy opens it under a secret path.

use std::io;
use std::path::{Path, PathBuf};

use super::context::Input;
use super::{adguard, app_settings, pihole};

pub const IMAGE: &str = "satishweb/doh-server:v2.3.10-5-alpine";
pub const PORT: u16 = 8104;
const TOKEN_FILE: &str = "doh.env";
const TOKEN_KEY: &str = "DOH_TOKEN";
const MATCHER: &str = "gryonixnexus_doh";
/// The image's own check asks localhost, which is IPv6 here
const HEALTH_PROBE: &str = "wget --tries=1 --timeout=10 -S -O /dev/null 'http://127.0.0.1:8104/dns-query?name=healthcheck.example&type=A' 2>&1 | grep -qE 'HTTP/1.[01] (200|503)'";

pub fn setting_key(service: &str) -> Option<&'static str> {
    match service {
        pihole::SERVICE_ID => Some("pihole_doh"),
        adguard::SERVICE_ID => Some("adguard_doh"),
        _ => None,
    }
}

fn service_dir(service: &str, input: &Input) -> Option<PathBuf> {
    match service {
        pihole::SERVICE_ID => Some(PathBuf::from(&input.pihole_path)),
        adguard::SERVICE_ID => Some(PathBuf::from(&input.adguard_path)),
        _ => None,
    }
}

pub fn wanted(service: &str, input: &Input) -> bool {
    setting_key(service).is_some_and(|key| app_settings::is_on(input, key)) && !input.local_only
}

pub fn project(service: &str) -> String {
    format!("{service}-doh")
}

pub fn bridge_dir(dir: &Path) -> PathBuf {
    dir.join("doh")
}

pub fn token_path(dir: &Path) -> PathBuf {
    dir.join(TOKEN_FILE)
}

pub fn compose_contents(service: &str) -> String {
    format!(
        "services:\n  doh:\n    image: {IMAGE}\n    container_name: {}\n    restart: unless-stopped\n    network_mode: host\n    environment:\n      UPSTREAM_DNS_SERVER: udp:127.0.0.1:53\n      DOH_HTTP_PREFIX: /dns-query\n      DOH_HTTP_PREFIXES: \"\"\n      DOH_SERVER_LISTEN: 127.0.0.1:{PORT}\n    healthcheck:\n      test: [\"CMD-SHELL\", \"{HEALTH_PROBE}\"]\n      interval: 60s\n      timeout: 30s\n      retries: 3\n",
        project(service)
    )
}

pub fn read_token(dir: &Path) -> Option<String> {
    let text = std::fs::read_to_string(token_path(dir)).ok()?;
    let prefix = format!("{TOKEN_KEY}=");
    let token = text.lines().find_map(|line| line.strip_prefix(prefix.as_str()))?.trim();
    (!token.is_empty()).then(|| token.to_string())
}

pub fn token_or_create(dir: &Path) -> io::Result<String> {
    if let Some(token) = read_token(dir) {
        return Ok(token);
    }
    use std::io::Read;
    let mut bytes = [0u8; 24];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    let token: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    crate::util::write_file_atomic(&token_path(dir), format!("{TOKEN_KEY}={token}\n").as_bytes(), 0o600)?;
    Ok(token)
}

fn is_site_level(line: &str) -> bool {
    let line = line.trim();
    line.starts_with('#') || line == "tls internal"
}

fn doh_handle(token: &str) -> String {
    format!(
        "    @{MATCHER} path /dns-query/{token}\n    handle @{MATCHER} {{\n        rewrite * /dns-query\n        reverse_proxy 127.0.0.1:{PORT}\n    }}\n"
    )
}

pub fn wrap_site(site: &str, token: &str) -> String {
    let lines: Vec<&str> = site.lines().collect();
    let Some((head, rest)) = lines.split_first() else { return site.to_string() };
    let Some((_, body)) = rest.split_last() else { return site.to_string() };
    let mut out = format!("{head}\n");
    for line in body.iter().filter(|line| is_site_level(line)) {
        out.push_str(&format!("{line}\n"));
    }
    out.push_str(&doh_handle(token));
    out.push_str("    handle {\n");
    for line in body.iter().filter(|line| !is_site_level(line)) {
        out.push_str(&format!("    {line}\n"));
    }
    out.push_str("    }\n}");
    out
}

pub fn decorate(service: &str, input: &Input, site: String) -> String {
    let token = wanted(service, input)
        .then(|| service_dir(service, input).and_then(|dir| read_token(&dir)))
        .flatten();
    match token {
        Some(token) => wrap_site(&site, &token),
        None => site,
    }
}

pub fn url(host: &str, token: &str) -> String {
    format!("https://{host}/dns-query/{token}")
}

/// The live address of a service's bridge, from the Caddyfile
pub fn address_in(caddyfile: &str, service: &str) -> Option<String> {
    let marker = format!("# gryonixnexus: {service}");
    let secret = format!("@{MATCHER} path /dns-query/");
    let mut host: Option<&str> = None;
    let mut ours = false;
    for line in caddyfile.lines() {
        if !line.starts_with(char::is_whitespace) && line.trim_end().ends_with('{') {
            host = line.split([',', ' ']).find(|part| !part.is_empty());
            ours = false;
        } else if line.trim() == marker {
            ours = true;
        } else if let (true, Some(host), Some(token)) = (ours, host, line.trim().strip_prefix(secret.as_str())) {
            return Some(url(host, token.trim()));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const SITE: &str = "dns.example.com {\n    # gryonixnexus: pihole\n    import /etc/caddy/gryonixnexus-admin-guard\n    reverse_proxy 127.0.0.1:8092\n}";

    #[test]
    fn the_secret_path_is_served_before_the_guarded_site() {
        let wrapped = wrap_site(SITE, "abc");
        assert_eq!(
            wrapped,
            "dns.example.com {\n    # gryonixnexus: pihole\n    @gryonixnexus_doh path /dns-query/abc\n    handle @gryonixnexus_doh {\n        rewrite * /dns-query\n        reverse_proxy 127.0.0.1:8104\n    }\n    handle {\n        import /etc/caddy/gryonixnexus-admin-guard\n        reverse_proxy 127.0.0.1:8092\n    }\n}"
        );
    }

    #[test]
    fn tls_internal_stays_at_site_level() {
        let site = "a.home.local {\n    # gryonixnexus: pihole\n    tls internal\n    reverse_proxy 127.0.0.1:8092\n}";
        let wrapped = wrap_site(site, "t");
        assert!(wrapped.find("tls internal").unwrap() < wrapped.find("handle {").unwrap());
    }

    #[test]
    fn nothing_changes_while_the_setting_is_off() {
        let input = Input::default();
        assert_eq!(decorate("pihole", &input, SITE.to_string()), SITE);
    }

    #[test]
    fn a_token_is_made_once_and_kept() {
        let dir = std::env::temp_dir().join(format!("doh-token-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let first = token_or_create(&dir).unwrap();
        assert_eq!(first.len(), 48);
        assert_eq!(token_or_create(&dir).unwrap(), first);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_bridge_listens_on_loopback_only() {
        let compose = compose_contents("pihole");
        assert!(compose.contains("DOH_SERVER_LISTEN: 127.0.0.1:8104"));
        assert!(compose.contains("http://127.0.0.1:8104/dns-query"));
        assert!(HEALTH_PROBE.contains(&format!("127.0.0.1:{PORT}")));
        assert!(compose.contains("container_name: pihole-doh"));
    }

    #[test]
    fn the_live_address_is_read_back_from_the_caddyfile() {
        let other = "vault.example.com {\n    # gryonixnexus: vaultwarden\n    reverse_proxy 127.0.0.1:8080\n}";
        let ours = wrap_site(&SITE.replace("dns.example.com", "dns.example.com, dns.example.org"), "abc");
        let caddyfile = format!("{other}\n\n{ours}\n");
        assert_eq!(address_in(&caddyfile, "pihole").as_deref(), Some("https://dns.example.com/dns-query/abc"));
        assert_eq!(address_in(&caddyfile, "adguard-home"), None);
        assert_eq!(address_in(SITE, "pihole"), None);
    }

    #[test]
    fn the_url_carries_the_token() {
        assert_eq!(url("dns.example.com", "abc"), "https://dns.example.com/dns-query/abc");
    }
}
