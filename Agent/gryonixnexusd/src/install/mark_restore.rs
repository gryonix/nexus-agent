//! Keeps a home's mark restore off packets that carry their own mark.

use super::firewall;

const BARE: &str = "meta mark set ct mark";
const GUARDED: &str = "ct mark != 0 meta mark set ct mark";
const CHAINS: [&str; 2] = ["prerouting", "output"];

/// Fixes the saved ruleset and the live chains, once
pub async fn refresh() -> Result<bool, String> {
    let path = super::firewall_base::conf_path();
    let Ok(text) = std::fs::read_to_string(&path) else { return Ok(false) };
    let Some(fixed) = guarded(&text) else { return Ok(false) };
    std::fs::write(&path, fixed).map_err(|err| format!("could not write {path}: {err}"))?;
    for chain in CHAINS {
        let listing = nft(&["-a", "list", "chain", "inet", "filter", chain]).await.unwrap_or_default();
        for handle in bare_handles(&listing) {
            let handle = handle.to_string();
            let mut args = vec!["replace", "rule", "inet", "filter", chain, "handle", &handle];
            args.extend(GUARDED.split(' '));
            nft(&args).await?;
        }
    }
    Ok(true)
}

/// The ruleset with bare restores guarded; None when none
fn guarded(text: &str) -> Option<String> {
    let mut changed = false;
    let lines: Vec<String> = text
        .lines()
        .map(|line| {
            if line.trim() != BARE {
                return line.to_string();
            }
            changed = true;
            line.replace(BARE, GUARDED)
        })
        .collect();
    changed.then(|| lines.join("\n") + if text.ends_with('\n') { "\n" } else { "" })
}

/// Handles of bare restores in `nft -a list chain` output
fn bare_handles(listing: &str) -> Vec<u64> {
    listing
        .lines()
        .filter_map(|line| {
            let (rule, handle) = line.trim().split_once(" # handle ")?;
            (rule == BARE).then(|| handle.trim().parse().ok()).flatten()
        })
        .collect()
}

async fn nft(args: &[&str]) -> Result<String, String> {
    let output = tokio::process::Command::new(firewall::nft_bin())
        .args(args)
        .output()
        .await
        .map_err(|err| format!("could not run nft: {err}"))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_bare_restores_are_guarded() {
        let text = "chain output {\n        meta mark set ct mark\n    }\n";
        let fixed = guarded(text).unwrap();
        assert!(fixed.contains("        ct mark != 0 meta mark set ct mark\n"));
        assert!(guarded(&fixed).is_none(), "a guarded ruleset is left alone");
    }

    #[test]
    fn live_handles_are_read_for_bare_rules_only() {
        let listing = "\tchain output { # handle 3\n\t\tmeta mark set ct mark # handle 9\n\t\tct mark != 0x0 meta mark set ct mark # handle 10\n\t}\n";
        assert_eq!(bare_handles(listing), vec![9]);
    }
}
