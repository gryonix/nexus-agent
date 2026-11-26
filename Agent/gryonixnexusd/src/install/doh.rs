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
const DEVICE_MATCHER: &str = "gryonixnexus_doh_device";
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

/// AdGuard answers DoH itself, seeing each client
pub fn bridge_wanted(service: &str, input: &Input) -> bool {
    service != adguard::SERVICE_ID && wanted(service, input)
}

/// Where Caddy sends DoH for a service
pub fn upstream_port(service: &str) -> u16 {
    if service == adguard::SERVICE_ID { adguard::WEB_UI_PORT } else { PORT }
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

fn doh_handle(token: &str, port: u16) -> String {
    let mut out = format!(
        "    @{MATCHER} path /dns-query/{token}\n    handle @{MATCHER} {{\n        rewrite * /dns-query\n        reverse_proxy 127.0.0.1:{port}\n    }}\n"
    );
    if port == adguard::WEB_UI_PORT {
        out.push_str(&device_handle(token));
    }
    out
}

/// Passes a device name on as AdGuard's ClientID
fn device_handle(token: &str) -> String {
    format!(
        "    @{DEVICE_MATCHER} path /dns-query/{token}/*\n    handle @{DEVICE_MATCHER} {{\n        rewrite * /dns-query/{{http.request.uri.path.2}}\n        reverse_proxy 127.0.0.1:{}\n    }}\n",
        adguard::WEB_UI_PORT
    )
}

pub fn wrap_site(site: &str, token: &str, port: u16) -> String {
    let lines: Vec<&str> = site.lines().collect();
    let Some((head, rest)) = lines.split_first() else { return site.to_string() };
    let Some((_, body)) = rest.split_last() else { return site.to_string() };
    let mut out = format!("{head}\n");
    for line in body.iter().filter(|line| is_site_level(line)) {
        out.push_str(&format!("{line}\n"));
    }
    out.push_str(&doh_handle(token, port));
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
        Some(token) => wrap_site(&site, &token, upstream_port(service)),
        None => site,
    }
}

pub fn url(host: &str, token: &str) -> String {
    format!("https://{host}/dns-query/{token}")
}

/// Points AdGuard's DoH from the bridge to AdGuard itself
pub fn retarget_adguard(caddyfile: &str) -> Option<String> {
    let marker = format!("# gryonixnexus: {}", adguard::SERVICE_ID);
    let bridge = format!("reverse_proxy 127.0.0.1:{PORT}");
    let direct = format!("reverse_proxy 127.0.0.1:{}", adguard::WEB_UI_PORT);
    let (mut ours, mut in_doh, mut changed) = (false, false, false);
    let mut token: Option<String> = None;
    let secret = format!("@{MATCHER} path /dns-query/");
    let mut out: Vec<String> = Vec::new();
    for line in caddyfile.lines() {
        let trimmed = line.trim();
        if !line.starts_with(char::is_whitespace) && trimmed.ends_with('{') {
            ours = false;
        } else if trimmed == marker {
            ours = true;
        }
        if ours {
            if let Some(found) = trimmed.strip_prefix(secret.as_str()) {
                token = Some(found.trim().to_string());
            }
        }
        if ours && trimmed == format!("handle @{MATCHER} {{") {
            in_doh = true;
        } else if in_doh && trimmed == "}" {
            in_doh = false;
            out.push(line.to_string());
            if changed && !caddyfile.contains(DEVICE_MATCHER) {
                if let Some(token) = &token {
                    out.extend(device_handle(token).lines().map(str::to_string));
                }
            }
            continue;
        }
        if ours && in_doh && trimmed == bridge {
            out.push(line.replacen(&bridge, &direct, 1));
            changed = true;
        } else {
            out.push(line.to_string());
        }
    }
    let mut text = out.join("\n");
    if caddyfile.ends_with('\n') {
        text.push('\n');
    }
    changed.then_some(text)
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
        let wrapped = wrap_site(SITE, "abc", PORT);
        assert_eq!(
            wrapped,
            "dns.example.com {\n    # gryonixnexus: pihole\n    @gryonixnexus_doh path /dns-query/abc\n    handle @gryonixnexus_doh {\n        rewrite * /dns-query\n        reverse_proxy 127.0.0.1:8104\n    }\n    handle {\n        import /etc/caddy/gryonixnexus-admin-guard\n        reverse_proxy 127.0.0.1:8092\n    }\n}"
        );
    }

    #[test]
    fn tls_internal_stays_at_site_level() {
        let site = "a.home.local {\n    # gryonixnexus: pihole\n    tls internal\n    reverse_proxy 127.0.0.1:8092\n}";
        let wrapped = wrap_site(site, "t", PORT);
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
        let ours = wrap_site(&SITE.replace("dns.example.com", "dns.example.com, dns.example.org"), "abc", PORT);
        let caddyfile = format!("{other}\n\n{ours}\n");
        assert_eq!(address_in(&caddyfile, "pihole").as_deref(), Some("https://dns.example.com/dns-query/abc"));
        assert_eq!(address_in(&caddyfile, "adguard-home"), None);
        assert_eq!(address_in(SITE, "pihole"), None);
    }

    #[test]
    fn adguard_answers_doh_itself_and_needs_no_bridge() {
        assert_eq!(upstream_port(adguard::SERVICE_ID), adguard::WEB_UI_PORT);
        assert_eq!(upstream_port(pihole::SERVICE_ID), PORT);
        let input = Input::default();
        assert!(!bridge_wanted(adguard::SERVICE_ID, &input));
        let wrapped = wrap_site(SITE, "t", adguard::WEB_UI_PORT);
        assert!(wrapped.contains("rewrite * /dns-query/{http.request.uri.path.2}"));
        assert!(!wrap_site(SITE, "t", PORT).contains(DEVICE_MATCHER));
    }

    #[test]
    fn an_adguard_site_moves_from_the_bridge_to_adguard() {
        let adguard_site = SITE.replace("# gryonixnexus: pihole", "# gryonixnexus: adguard-home");
        let caddyfile = format!("{}\n\n{}\n", wrap_site(SITE, "p", PORT), wrap_site(&adguard_site, "a", PORT));
        let moved = retarget_adguard(&caddyfile).unwrap();
        assert_eq!(moved.matches("reverse_proxy 127.0.0.1:8104").count(), 1);
        assert!(moved.contains(&format!("reverse_proxy 127.0.0.1:{}", adguard::WEB_UI_PORT)));
        assert!(moved.contains("reverse_proxy 127.0.0.1:8092"));
        assert!(moved.contains("@gryonixnexus_doh_device path /dns-query/a/*"));
        assert!(!moved.contains("/dns-query/p/*"));
        assert_eq!(retarget_adguard(&moved), None);
        assert_eq!(address_in(&moved, "adguard-home").as_deref(), Some("https://dns.example.com/dns-query/a"));
    }

    #[test]
    fn the_url_carries_the_token() {
        assert_eq!(url("dns.example.com", "abc"), "https://dns.example.com/dns-query/abc");
    }
}
