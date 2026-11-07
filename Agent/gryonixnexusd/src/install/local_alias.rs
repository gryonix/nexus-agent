//! A site's second name, `<first label>.local`, for the home network.

use super::caddy;

/// The .local name a public site gets
pub fn alias_for(host: &str) -> Option<String> {
    let label = host.split('.').next()?.to_ascii_lowercase();
    let valid = !label.is_empty()
        && label.len() <= 63
        && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        && !label.starts_with('-')
        && !label.ends_with('-');
    (valid && !host.ends_with(".local")).then(|| format!("{label}.local"))
}

fn header_names(block: &str) -> Option<Vec<String>> {
    let header = block.trim().lines().next()?;
    let names = header.trim().strip_suffix('{')?;
    Some(names.split(',').map(|name| name.trim().to_string()).filter(|name| !name.is_empty()).collect())
}

/// Public sites paired with their .local names
pub fn local_aliases(caddyfile: &str) -> Vec<(String, String)> {
    caddy::top_level_blocks(caddyfile)
        .into_iter()
        .filter_map(header_names)
        .flat_map(|names| {
            names
                .iter()
                .filter_map(|host| alias_for(host).filter(|alias| names.contains(alias)).map(|alias| (host.clone(), alias)))
                .collect::<Vec<_>>()
        })
        .collect()
}

/// The Caddyfile with the site's .local name added or removed
pub fn with_local_alias(caddyfile: &str, host: &str, on: bool) -> Result<String, String> {
    let alias = alias_for(host).ok_or_else(|| format!("{host} has no usable first label"))?;
    let blocks = caddy::top_level_blocks(caddyfile);
    let Some(block) = blocks.iter().find(|block| header_names(block).is_some_and(|names| names.iter().any(|n| n == host)))
    else {
        return Err(format!("no site answers at {host}"));
    };
    let taken = blocks.iter().any(|other| {
        !std::ptr::eq(*other, *block) && header_names(other).is_some_and(|names| names.contains(&alias))
    });
    if on && taken {
        return Err(format!("{alias} is already used by another site"));
    }
    let mut names = header_names(block).unwrap_or_default();
    names.retain(|name| name != &alias);
    if on {
        names.push(alias);
    }
    let old_header = block.trim_start().lines().next().unwrap_or_default();
    let new_header = format!("{} {{", names.join(", "));
    let start = block.as_ptr() as usize - caddyfile.as_ptr() as usize;
    let rewritten = block.replacen(old_header, &new_header, 1);
    Ok(format!("{}{}{}", &caddyfile[..start], rewritten, &caddyfile[start + block.len()..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &str = "{\n    email a@b.c\n}\n\nvault.example.com {\n    # gryonixnexus: vaultwarden\n    reverse_proxy 127.0.0.1:8082\n}\n\nphotos.example.com {\n    reverse_proxy 127.0.0.1:2283\n}\n";

    #[test]
    fn the_alias_is_added_once_and_removed_again() {
        let on = with_local_alias(FILE, "vault.example.com", true).unwrap();
        assert!(on.contains("vault.example.com, vault.local {\n    # gryonixnexus: vaultwarden"), "{on}");
        assert_eq!(with_local_alias(&on, "vault.example.com", true).unwrap(), on);
        assert_eq!(local_aliases(&on), vec![("vault.example.com".to_string(), "vault.local".to_string())]);
        assert_eq!(with_local_alias(&on, "vault.example.com", false).unwrap(), FILE);
    }

    #[test]
    fn reinstalling_a_site_keeps_its_local_name_and_no_duplicate() {
        let on = with_local_alias(FILE, "vault.example.com", true).unwrap();
        let fresh = "vault.example.com {\n    # gryonixnexus: vaultwarden\n    reverse_proxy 127.0.0.1:9999\n}";
        let merged = caddy::merge_site(&on, &["vault.example.com".to_string()], fresh);
        assert_eq!(merged.matches("vault.example.com").count(), 1, "{merged}");
        assert!(merged.contains("vault.example.com, vault.local {\n    # gryonixnexus: vaultwarden\n    reverse_proxy 127.0.0.1:9999"), "{merged}");
    }

    #[test]
    fn unknown_sites_and_taken_names_are_refused() {
        assert!(with_local_alias(FILE, "mail.example.com", true).is_err());
        let clash = format!("{FILE}\nvault.local {{\n    respond 200\n}}\n");
        assert!(with_local_alias(&clash, "vault.example.com", true).is_err());
        assert_eq!(alias_for("Photos.example.com").as_deref(), Some("photos.local"));
        assert_eq!(alias_for("photos.home.local"), None);
    }
}
