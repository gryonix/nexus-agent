//! Every site the agent writes, merged and checked by a real Caddy.

use super::caddy;
use super::context::Input;
use super::mail::{dockermailserver, mailcow, mailu};
use super::vpn::panel;
use super::*;
use std::path::Path;

const STOCK_CADDYFILE: &str = "# The Caddyfile is an easy way to configure your Caddy web server.\n#\n# To use your own domain name (with automatic HTTPS), first make\n# sure your domain's A/AAAA DNS records are properly pointed to\n# this machine's public IP, then replace \":80\" below with your\n# domain name.\n\n:80 {\n\t# Set this path to your site's directory.\n\troot * /usr/share/caddy\n\n\t# Enable the static file server.\n\tfile_server\n\n\t# Another common task is to set up a reverse proxy:\n\t# reverse_proxy localhost:8080\n\n\t# Or serve a PHP site through php-fpm:\n\t# php_fastcgi localhost:9000\n}\n\n# Refer to the Caddy docs for more information:\n# https://caddyserver.com/docs/caddyfile\n";

const GUARD_ON: &str = "@gryonixnexus_relay {\n    remote_ip 10.8.0.0/24\n    not remote_ip 10.8.0.254/32\n}\nrespond @gryonixnexus_relay \"Denied\" 403\n@gryonixnexus_public not remote_ip private_ranges 203.0.113.7/32\nrespond @gryonixnexus_public \"Denied\" 403\n@gryonixnexus_tunnel header Cf-Connecting-IP *\nrespond @gryonixnexus_tunnel \"Denied\" 403\n";

fn input(local_only: bool) -> Input {
    Input {
        domain: if local_only { "home.lan".into() } else { "example.net".into() },
        local_only,
        installed_services: ["wireguard-vpn", "immich", "jellyfin", "n8n", "open-webui", "home-assistant"]
            .map(String::from)
            .to_vec(),
        ..Input::default()
    }
}

/// Each service's site as its installer writes it
fn sites(input: &Input) -> Vec<(Vec<String>, String)> {
    vec![
        (vaultwarden::caddy_site_names(input), vaultwarden::caddy_site(input)),
        (nextcloud::caddy_site_names(input), nextcloud::caddy_site(input)),
        (adguard::caddy_site_names(input), adguard::caddy_site(input)),
        (mailcow::caddy_site_names(input), mailcow::caddy_site(input)),
        (panel::caddy_site_names(input), panel::caddy_site(input)),
        (immich::caddy_site_names(input), immich::caddy_site(input)),
        (jellyfin::caddy_site_names(input), jellyfin::caddy_site(input)),
        (home_assistant::caddy_site_names(input), home_assistant::caddy_site(input)),
        (zigbee2mqtt::caddy_site_names(input), zigbee2mqtt::caddy_site(input)),
        (open_webui::caddy_site_names(input), open_webui::caddy_site(input)),
        (openclaw::caddy_site_names(input), openclaw::caddy_site(input)),
        (anythingllm::caddy_site_names(input), anythingllm::caddy_site(input)),
        (n8n::caddy_site_names(input), n8n::caddy_site(input)),
        (litellm::caddy_site_names(input), litellm::caddy_site(input)),
        (crafty::caddy_site_names(input), crafty::caddy_site(input)),
        (gitlab::caddy_site_names(input), gitlab::caddy_site(input)),
        (forgejo::caddy_site_names(input), forgejo::caddy_site(input)),
        (photoprism::caddy_site_names(input), photoprism::caddy_site(input)),
        (passbolt::caddy_site_names(input), passbolt::caddy_site(input)),
        (seafile::caddy_site_names(input), seafile::caddy_site(input)),
        (psono::caddy_site_names(input), psono::caddy_site(input)),
        (headscale::caddy_site_names(input), headscale::caddy_site(input)),
        (homepage::caddy_site_names(input), homepage::caddy_site(input)),
        (authelia::caddy_site_names(input), authelia::caddy_site(input)),
        (pihole::caddy_site_names(input), pihole::caddy_site(input)),
        (mailu::caddy_site_names(input), mailu::caddy_site(input)),
        (dockermailserver::caddy_site_names(input), dockermailserver::caddy_site(input)),
    ]
}

/// Merges sites the way installs do, skipping taken names
fn merged(input: &Input, sso: bool) -> String {
    let mut file = STOCK_CADDYFILE.to_string();
    for (names, site) in sites(input) {
        let owner = caddy::owner_of(&site).unwrap_or_default();
        if caddy::conflicting_names(&file, &names, &owner).is_empty() {
            file = caddy::merge_site(&file, &names, &site);
        }
    }
    if sso {
        for id in ["vaultwarden", "nextcloud", "immich", "jellyfin", "n8n"] {
            if let Some((names, site)) = catalog::site_for(id, input, true) {
                file = caddy::merge_site(&file, &names, &site);
            }
        }
    }
    let autoconfig = mailcow::autoconfig_site(&mailcow::autoconfig_site_names(&mailcow::mail_domains(input)));
    caddy::with_autoconfig_site(&file, autoconfig.as_deref())
}

/// Caddy's verdict on the file, with its error text
fn validate(dir: &Path, caddyfile: &str) -> Result<(), String> {
    let etc = dir.join("etc-caddy");
    std::fs::create_dir_all(etc.join("gryonixnexus-setup")).unwrap();
    std::fs::write(etc.join("gryonixnexus-admin-guard"), GUARD_ON).unwrap();
    for owner in caddy::FIRST_VISITOR_ADMIN {
        std::fs::write(etc.join("gryonixnexus-setup").join(owner), caddy::SETUP_GUARD_RULES).unwrap();
    }
    let here = |text: &str| text.replace("/etc/caddy/", &format!("{}/", etc.display()));
    let text = here(&home_network::with_import(caddyfile));
    let doors = home_network::snippet(&home_network::home_sites(caddyfile));
    std::fs::write(etc.join("gryonixnexus-home-network.caddy"), here(&doors)).unwrap();
    let path = etc.join("Caddyfile");
    std::fs::write(&path, &text).unwrap();
    let out = std::process::Command::new("caddy")
        .args(["validate", "--config", path.to_str().unwrap(), "--adapter", "caddyfile"])
        .env("XDG_DATA_HOME", dir.join("data"))
        .env("XDG_CONFIG_HOME", dir.join("config"))
        .output()
        .map_err(|err| err.to_string())?;
    if out.status.success() {
        return Ok(());
    }
    Err(format!("{}\n--- Caddyfile ---\n{text}", String::from_utf8_lossy(&out.stderr)))
}

fn caddy_installed() -> bool {
    std::process::Command::new("caddy").arg("version").output().is_ok_and(|o| o.status.success())
}

#[test]
fn a_site_with_its_own_certificate_validates_under_a_read_only_home() {
    if !caddy_installed() {
        return;
    }
    let dir = std::env::temp_dir().join(format!("gnx-caddy-home-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("Caddyfile");
    std::fs::write(&path, "b.home.lan {\n    tls internal\n    reverse_proxy 127.0.0.1:1\n}\n").unwrap();
    std::env::set_var("GRYONIXNEXUSD_STATE_DIR", dir.join("state"));
    let verdict = tokio::runtime::Runtime::new().unwrap().block_on(super::caddy_check::refusal(&path));
    std::env::remove_var("GRYONIXNEXUSD_STATE_DIR");
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(verdict, None);
}

#[test]
fn every_site_together_is_a_file_caddy_loads() {
    if !caddy_installed() {
        return;
    }
    for (local_only, sso) in [(false, false), (false, true), (true, false)] {
        let dir = std::env::temp_dir().join(format!("gnx-caddy-{}-{local_only}-{sso}", std::process::id()));
        let file = merged(&input(local_only), sso);
        let verdict = validate(&dir, &file);
        let _ = std::fs::remove_dir_all(&dir);
        if let Err(why) = verdict {
            panic!("local_only={local_only} sso={sso}: Caddy refused the file:\n{why}");
        }
    }
}

#[tokio::test]
async fn only_the_site_caddy_refuses_is_found() {
    if !caddy_installed() {
        return;
    }
    let dir = std::env::temp_dir().join(format!("gnx-caddy-refused-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = format!(
        "{}\n\ngood.example.net {{\n    # gryonixnexus: vaultwarden\n    reverse_proxy 127.0.0.1:1\n}}\n\nbad.example.net {{\n    # gryonixnexus: adguard-home\n    no_such_directive on\n}}\n",
        caddy::GLOBAL_OPTIONS
    );
    let refused = super::caddy_check::refused_sites(&file, &dir).await.expect("the global block loads");
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(refused.len(), 1, "{refused:?}");
    assert!(refused[0].0.starts_with("bad.example.net"));
    assert!(refused[0].1.contains("no_such_directive"), "{}", refused[0].1);
}

#[test]
fn a_mail_server_after_an_agent_restart_is_a_file_caddy_loads() {
    if !caddy_installed() {
        return;
    }
    let mut input = input(false);
    input.installed_services.push("mailcow".into());
    let names = mailcow::autoconfig_site_names(&mailcow::mail_domains(&input));
    let mut file = caddy::merge_site(STOCK_CADDYFILE, &mailcow::caddy_site_names(&input), &mailcow::caddy_site(&input));
    for _ in 0..3 {
        file = caddy::with_current_portal_split(&file);
        file = caddy::with_autoconfig_site(&file, mailcow::autoconfig_site(&names).as_deref());
    }
    let dir = std::env::temp_dir().join(format!("gnx-caddy-restart-{}", std::process::id()));
    let verdict = validate(&dir, &file);
    let _ = std::fs::remove_dir_all(&dir);
    if let Err(why) = verdict {
        panic!("Caddy refused the mail sites after restarts:\n{why}");
    }
}
