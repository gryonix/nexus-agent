//! Sites waiting for a certificate get Caddy to ask again

use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const CADDYFILE: &str = "/etc/caddy/Caddyfile";
const CERTIFICATES: &str = "/var/lib/caddy/.local/share/caddy/certificates";
const RETRY_GAP: Duration = Duration::from_secs(30 * 60);

/// Hostnames of the sites this agent wrote
pub fn managed_hostnames(caddyfile: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut header: Option<&str> = None;
    for line in caddyfile.lines() {
        let trimmed = line.trim();
        if !line.starts_with(char::is_whitespace) && trimmed.ends_with('{') {
            header = Some(trimmed.trim_end_matches('{').trim());
        } else if trimmed.starts_with("# gryonixnexus:") {
            if let Some(found) = header.take() {
                names.extend(found.split(',').map(str::trim).filter(|name| is_hostname(name)).map(str::to_string));
            }
        }
    }
    names
}

fn is_hostname(name: &str) -> bool {
    !name.is_empty() && !name.starts_with(':') && !name.contains("://") && name.contains('.') && !name.contains('*')
}

/// Names with no certificate in Caddy's storage
pub fn missing(names: &[String], storage: &Path) -> Vec<String> {
    let issuers: Vec<_> = std::fs::read_dir(storage)
        .map(|entries| entries.flatten().map(|entry| entry.path()).collect())
        .unwrap_or_default();
    names
        .iter()
        .filter(|name| !issuers.iter().any(|issuer| issuer.join(name).join(format!("{name}.crt")).exists()))
        .cloned()
        .collect()
}

fn last_retry() -> &'static Mutex<Option<Instant>> {
    static LAST: Mutex<Option<Instant>> = Mutex::new(None);
    &LAST
}

/// One pass of the periodic check
pub async fn retry_missing() {
    let Ok(caddyfile) = std::fs::read_to_string(CADDYFILE) else { return };
    let waiting = missing(&managed_hostnames(&caddyfile), Path::new(CERTIFICATES));
    if waiting.is_empty() {
        return;
    }
    {
        let mut last = last_retry().lock().unwrap();
        if last.is_some_and(|at| at.elapsed() < RETRY_GAP) {
            return;
        }
        *last = Some(Instant::now());
    }
    tracing::info!(names = %waiting.join(", "), "certificates missing, asking Caddy again");
    let _ = tokio::process::Command::new("caddy")
        .envs(crate::install::caddy_check::cli_env())
        .args(["reload", "--config", CADDYFILE, "--adapter", "caddyfile", "--force"])
        .output()
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &str = "{\n\torder respond before forward_auth\n}\n\ndns.example.com, dns.example.org {\n    # gryonixnexus: adguard-home\n    reverse_proxy 127.0.0.1:8087\n}\n\n:80 {\n\trespond \"own\"\n}\n\nblog.example.com {\n\tfile_server\n}\n";

    #[test]
    fn only_the_sites_this_agent_wrote_are_watched() {
        assert_eq!(managed_hostnames(FILE), vec!["dns.example.com", "dns.example.org"]);
    }

    #[test]
    fn a_name_without_a_certificate_is_missing() {
        let storage = std::env::temp_dir().join(format!("gnx-certs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&storage);
        let issued = storage.join("acme-v02.api.letsencrypt.org-directory/dns.example.com");
        std::fs::create_dir_all(&issued).unwrap();
        std::fs::write(issued.join("dns.example.com.crt"), "x").unwrap();
        let names = vec!["dns.example.com".to_string(), "dns.example.org".to_string()];
        assert_eq!(missing(&names, &storage), vec!["dns.example.org"]);
        let _ = std::fs::remove_dir_all(&storage);
    }
}
