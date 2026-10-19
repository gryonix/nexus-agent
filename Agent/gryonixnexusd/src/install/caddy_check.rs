//! Asks Caddy about a Caddyfile and finds the sites it refuses.

use super::caddy;
use super::home_network::SNIPPET_PATH;
use std::path::{Path, PathBuf};
use std::process::Stdio;

/// Where a single site is checked on its own
const SCRATCH_NAME: &str = "Caddyfile.gryonixnexus-check";

/// Longest Caddy complaint kept in a message
const REASON_LIMIT: usize = 400;

/// Caddy's complaint, cut to its error line
pub fn reason(stderr: &str) -> String {
    let lines: Vec<&str> = stderr.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    let logged = lines.iter().rev().find_map(|l| logged_error(l));
    let line = lines
        .iter()
        .rev()
        .find_map(|l| l.strip_prefix("Error:").map(str::to_string))
        .or(logged)
        .or_else(|| lines.last().map(|l| l.to_string()))
        .unwrap_or_else(|| "Caddy gave no reason".to_string());
    line.trim().chars().take(REASON_LIMIT).collect()
}

/// The message of a JSON log line at error level
fn logged_error(line: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(line).ok()?;
    (value.get("level")?.as_str()? == "error").then(|| value.get("msg")?.as_str().map(str::to_string))?
}

/// A writable home for Caddy's command line
pub fn cli_env() -> [(&'static str, PathBuf); 3] {
    let home = crate::backup::wrapper_home().join("caddy");
    let _ = std::fs::create_dir_all(&home);
    [("HOME", home.clone()), ("XDG_DATA_HOME", home.join("data")), ("XDG_CONFIG_HOME", home.join("config"))]
}

/// Caddy's verdict on a file: None when it would load
pub async fn refusal(path: &Path) -> Option<String> {
    let out = tokio::process::Command::new("caddy")
        .args(["validate", "--config", &path.to_string_lossy(), "--adapter", "caddyfile"])
        .envs(cli_env())
        .stdin(Stdio::null())
        .output()
        .await
        .ok()?;
    (!out.status.success()).then(|| reason(&String::from_utf8_lossy(&out.stderr)))
}

/// A global options or snippet block, needed by every site
fn is_definition(block: &str) -> bool {
    let first = block.lines().map(str::trim).find(|l| !l.is_empty() && !l.starts_with('#')).unwrap_or("");
    first == "{" || first.starts_with('(')
}

/// The block without the home network import glued to it
pub fn without_home_import(block: &str) -> String {
    let line = format!("import {SNIPPET_PATH}");
    block.lines().filter(|l| l.trim() != line).collect::<Vec<_>>().join("\n").trim().to_string()
}

/// Each site, with the blocks it needs to load
pub fn sites_alone(text: &str) -> Vec<(String, String)> {
    let blocks: Vec<String> =
        caddy::top_level_blocks(text).into_iter().map(without_home_import).filter(|b| !b.is_empty()).collect();
    let shared: Vec<&String> = blocks.iter().filter(|b| is_definition(b)).collect();
    let prefix = shared.iter().map(|b| b.as_str()).collect::<Vec<_>>().join("\n\n");
    blocks
        .iter()
        .filter(|b| !is_definition(b) && b.lines().any(|l| l.trim_end().ends_with('{')))
        .map(|b| (b.clone(), format!("{prefix}\n\n{b}\n")))
        .collect()
}

/// Sites Caddy refuses on their own, with its reasons
pub async fn refused_sites(text: &str, dir: &Path) -> Option<Vec<(String, String)>> {
    let scratch = dir.join(SCRATCH_NAME);
    let sites = sites_alone(text);
    let base = caddy::top_level_blocks(text).into_iter().filter(|b| is_definition(b)).collect::<Vec<_>>().join("\n\n");
    let checked = check(&scratch, &format!("{base}\n")).await;
    if checked.is_some() {
        let _ = std::fs::remove_file(&scratch);
        return None;
    }
    let mut refused = Vec::new();
    for (site, alone) in sites {
        if let Some(why) = check(&scratch, &alone).await {
            refused.push((site, why));
        }
    }
    let _ = std::fs::remove_file(&scratch);
    Some(refused)
}

async fn check(scratch: &Path, text: &str) -> Option<String> {
    if let Err(err) = std::fs::write(scratch, text) {
        return Some(format!("could not write {}: {err}", scratch.display()));
    }
    refusal(scratch).await
}

/// A site's service, else its first line
pub fn site_label(site: &str) -> String {
    caddy::owner_of(site).unwrap_or_else(|| site.lines().next().unwrap_or("").trim_end_matches('{').trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &str = "{\n\torder respond before forward_auth\n}\n\n(shared) {\n    encode gzip\n}\n\na.example.net {\n    # gryonixnexus: vaultwarden\n    reverse_proxy 127.0.0.1:1\n}\n\nb.example.net {\n    # gryonixnexus: adguard-home\n    reverse_proxy 127.0.0.1:2\n}\nimport /etc/caddy/gryonixnexus-home-network.caddy\n";

    #[test]
    fn the_error_line_is_what_the_owner_sees() {
        let stderr = "{\"level\":\"info\",\"msg\":\"using config\"}\nError: adapting config using caddyfile: ambiguous site definition: a.example.net\n";
        assert_eq!(reason(stderr), "adapting config using caddyfile: ambiguous site definition: a.example.net");
        assert_eq!(reason("something odd\n"), "something odd");
        assert_eq!(reason(""), "Caddy gave no reason");
        let logged = "{\"level\":\"error\",\"ts\":1,\"msg\":\"adapting config using caddyfile: ambiguous site definition: a.example.net\"}";
        assert_eq!(reason(logged), "adapting config using caddyfile: ambiguous site definition: a.example.net");
    }

    #[test]
    fn each_site_is_checked_with_the_global_and_snippet_blocks() {
        let sites = sites_alone(FILE);
        assert_eq!(sites.len(), 2);
        assert!(sites[1].0.starts_with("b.example.net {") && !sites[1].0.contains("import /etc/caddy"));
        assert!(sites[1].1.starts_with("{\n\torder respond") && sites[1].1.contains("(shared) {"));
        assert!(!sites[1].1.contains("a.example.net"));
    }

    #[test]
    fn a_site_is_named_by_its_service_or_its_address() {
        let sites = sites_alone(FILE);
        assert_eq!(site_label(&sites[1].0), "adguard-home");
        assert_eq!(site_label("c.example.net {\n    respond 1\n}"), "c.example.net");
    }
}
