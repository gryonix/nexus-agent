//! The catalog's SHELVES, as the start page needs them

use super::caddy::WebIngress;
use super::context::Input;

type Shelf = (&'static str, &'static str, &'static [(&'static str, &'static str)]);

const MAIL: &[(&str, &str)] =
    &[("mailcow", "Mailcow"), ("mailu", "Mailu"), ("docker-mailserver", "Docker Mailserver")];
const PASSWORDS: &[(&str, &str)] =
    &[("vaultwarden", "Vaultwarden"), ("psono", "Psono"), ("passbolt", "Passbolt")];
const FILES: &[(&str, &str)] = &[("nextcloud", "Nextcloud"), ("seafile", "Seafile")];
const PHOTOS: &[(&str, &str)] = &[("immich", "Immich"), ("photoprism", "PhotoPrism")];
const MEDIA: &[(&str, &str)] = &[("jellyfin", "Jellyfin")];
const CODE: &[(&str, &str)] = &[("gitlab", "GitLab"), ("forgejo", "Forgejo")];
const NETWORK: &[(&str, &str)] = &[("adguard-home", "AdGuard Home"), ("pihole", "Pi-hole")];
const VPN: &[(&str, &str)] = &[
    ("wireguard-vpn", "WireGuard"),
    ("amnezia-wg", "AmneziaWG"),
    ("shadowsocks", "Shadowsocks"),
    ("xray-reality", "VLESS / Reality"),
    ("openvpn", "OpenVPN"),
    ("vpn-panel", "VPN Panel"),
];
const MESH: &[(&str, &str)] = &[("headscale", "Headscale"), ("tailscale-node", "Tailscale")];
const REMOTE_ACCESS: &[(&str, &str)] = &[("cloudflared", "Cloudflare Tunnel")];
const DASHBOARD: &[(&str, &str)] = &[("homepage", "Homepage")];
const SSO: &[(&str, &str)] = &[("authelia", "Authelia")];
const AI: &[(&str, &str)] = &[
    ("open-webui", "Open WebUI"),
    ("ollama", "Ollama"),
    ("anythingllm", "AnythingLLM"),
    ("litellm", "LiteLLM"),
    ("qdrant", "Qdrant"),
    ("searxng", "SearXNG"),
    ("openclaw", "OpenClaw"),
];
const AUTOMATION: &[(&str, &str)] = &[("n8n", "n8n")];
const SMART_HOME: &[(&str, &str)] = &[
    ("home-assistant", "Home Assistant"),
    ("mosquitto", "Mosquitto"),
    ("zigbee2mqtt", "Zigbee2MQTT"),
];
const GAMES: &[(&str, &str)] = &[
    ("minecraft-java", "Minecraft (Java)"),
    ("minecraft-bedrock", "Minecraft (Bedrock)"),
    ("crafty-controller", "Crafty Controller"),
];

pub fn categories() -> Vec<Shelf> {
    vec![
        ("Mail", "A mail server on your own domain: mailboxes, webmail, spam filtering.", MAIL),
        ("Passwords", "A password vault for people, with apps and browser extensions.", PASSWORDS),
        ("Files", "File sync and sharing across your devices — your own drive, on your own server.", FILES),
        ("Photos", "A photo and video library: automatic phone backup, albums, search.", PHOTOS),
        ("Media", "Streams films, series and music you already own to any device.", MEDIA),
        ("Git hosting", "Your own Git server: repositories, issues, pull requests.", CODE),
        (
            "Ad & tracker blocking",
            "A DNS server for your devices that drops ads, trackers and malware domains before they load.",
            NETWORK,
        ),
        (
            "VPN",
            "An encrypted tunnel into this server from anywhere, with a panel that hands out client profiles.",
            VPN,
        ),
        (
            "Private network for your devices",
            "Links your own phones, laptops and servers straight to each other, wherever they are. Nothing is published to the internet.",
            MESH,
        ),
        (
            "Game servers",
            "A Minecraft server on your own machine, with a web panel for the console, players and backups.",
            GAMES,
        ),
        (
            "Access without opening ports",
            "The server dials out and keeps the connection open, so its sites work from the internet even behind a router with no public IP.",
            REMOTE_ACCESS,
        ),
        (
            "Start page",
            "One page linking to everything installed on this server, built from the services you picked.",
            DASHBOARD,
        ),
        (
            "Single sign-on",
            "One login in front of the admin panels, on top of the password each of them already has.",
            SSO,
        ),
        (
            "AI",
            "A model that runs on your own machine, and a chat in front of it: nothing you type, and none of the documents you feed it, leaves the server.",
            AI,
        ),
        (
            "Automation",
            "Connects your services to each other: an event, then a step, then a step. Zapier, running on your own server.",
            AUTOMATION,
        ),
        (
            "Smart home",
            "Runs the house from your own machine: lights, sensors, heating and cameras in one app, working even when the internet is down. Only on a machine at home.",
            SMART_HOME,
        ),
    ]
}

pub fn web_ingress_for(id: &str, input: &Input) -> Option<WebIngress> {
    use super::mail::{dockermailserver as dms, mailcow, mailu};
    match id {
        "mailcow" => Some(mailcow::web_ingress(input)),
        "mailu" => Some(mailu::web_ingress(input)),
        "docker-mailserver" => Some(dms::web_ingress(input)),
        "vaultwarden" => Some(super::vaultwarden::web_ingress(input)),
        "psono" => Some(super::psono::web_ingress(input)),
        "passbolt" => Some(super::passbolt::web_ingress(input)),
        "nextcloud" => Some(super::nextcloud::web_ingress(input)),
        "seafile" => Some(super::seafile::web_ingress(input)),
        "immich" => Some(super::immich::web_ingress(input)),
        "photoprism" => Some(super::photoprism::web_ingress(input)),
        "gitlab" => Some(super::gitlab::web_ingress(input)),
        "forgejo" => Some(super::forgejo::web_ingress(input)),
        "jellyfin" => Some(super::jellyfin::web_ingress(input)),
        "home-assistant" => Some(super::home_assistant::web_ingress(input)),
        "zigbee2mqtt" => Some(super::zigbee2mqtt::web_ingress(input)),
        "crafty-controller" => Some(super::crafty::web_ingress(input)),
        "adguard-home" => Some(super::adguard::web_ingress(input)),
        "pihole" => Some(super::pihole::web_ingress(input)),
        "homepage" => Some(super::homepage::web_ingress(input)),
        "headscale" => Some(super::headscale::web_ingress(input)),
        "authelia" => Some(super::authelia::web_ingress(input)),
        "vpn-panel" => Some(super::vpn::panel::web_ingress(input)),
        "open-webui" => Some(super::open_webui::web_ingress(input)),
        "litellm" => Some(super::litellm::web_ingress(input)),
        "n8n" => Some(super::n8n::web_ingress(input)),
        "anythingllm" => Some(super::anythingllm::web_ingress(input)),
        "openclaw" => Some(super::openclaw::web_ingress(input)),
        _ => None,
    }
}

pub fn site_names_for(id: &str, input: &Input) -> Vec<String> {
    let Some(ingress) = web_ingress_for(id, input) else { return Vec::new() };
    let mut names = vec![ingress.hostname.clone()];
    names.extend(input.mirrored_hostnames(&ingress.hostname));
    names
}

pub fn site_for(id: &str, input: &Input, sso: bool) -> Option<(Vec<String>, String)> {
    let ingress = web_ingress_for(id, input)?;
    let names = site_names_for(id, input);
    let text = super::caddy::site_with_public_paths(
        id,
        &names.join(", "),
        ingress.upstream_port,
        ingress.admin_guard,
        ingress.upstream_https,
        input.local_only,
        sso,
        &ingress.public_paths,
        false,
    );
    Some((names, super::caddy::with_setup_guard(id, &input.installed_services, text)))
}

pub fn web_hostname(id: &str, input: &Input) -> Option<String> {
    super::host::uninstall::hostname_for(id, input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_member_is_an_id_the_wrapper_catalog_also_carries() {
        for (_, _, members) in categories() {
            for (id, _) in members {
                assert!(
                    super::super::host::CATALOG_ORDER.contains(id),
                    "{id} is on a shelf here but not in CATALOG_ORDER"
                );
            }
        }
    }

    #[test]
    fn every_catalog_id_sits_on_exactly_one_shelf() {
        for id in super::super::host::CATALOG_ORDER {
            let shelves: Vec<&str> = categories()
                .into_iter()
                .filter(|(_, _, members)| members.iter().any(|(m, _)| m == id))
                .map(|(title, _, _)| title)
                .collect();
            assert_eq!(shelves.len(), 1, "{id} sits on {shelves:?}");
        }
    }
}
