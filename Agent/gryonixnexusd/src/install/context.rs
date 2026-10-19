//! Install-time context for the AdGuard Home slice, sized to what AdGuard's declarative artifacts actually read

use crate::language::Language;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AutheliaProtection {
    Default,
    /// The app named a list
    Explicit(Vec<String>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Input {
    pub domain: String,
    pub additional_domains: Vec<String>,
    pub language: Language,
    pub local_only: bool,
    pub installed_services: Vec<String>,
    pub admin_username: String,
    pub adguard_path: String,
    /// `ServiceSettings.autheliaPath`, Swift default `/opt/authelia`.
    pub authelia_path: String,
    /// `ServiceSettings.autheliaHostname`; empty means `auth.<domain>`.
    pub authelia_hostname: String,
    /// `ServiceSettings.autheliaProtectedServices`, as catalog ids
    pub authelia_protected: AutheliaProtection,
    /// `ServiceSettings.homepagePath`, Swift default `/opt/homepage`.
    pub homepage_path: String,
    /// `ServiceSettings.homepageHostname`; empty means `start.<domain>`.
    pub homepage_hostname: String,
    /// `ServiceSettings.piholePath`, Swift default `/opt/pihole`.
    pub pihole_path: String,
    /// `ServiceSettings.piholeHostname`; empty means `dns.<domain>`.
    pub pihole_hostname: String,
    /// `ServiceSettings.piholeUpstreams`, Pi-hole's own semicolon syntax.
    pub pihole_upstreams: String,
    /// `ServiceSettings.piholeServesNetwork`
    pub pihole_serves_network: bool,
    pub adguard_hostname: String,
    pub headscale_path: String,
    pub headscale_hostname: String,
    pub headscale_base_domain: String,
    pub tailscale_node_path: String,
    pub tailscale_node_name: String,
    /// Which coordination service the node joins — empty means Tailscale's own.
    pub tailscale_login_server: String,
    pub tailscale_auth_key: String,
    pub cloudflared_path: String,
    /// The tunnel's connector credential, when the caller has one
    pub cloudflared_token: String,
    pub vaultwarden_hostname: String,
    pub vaultwarden_container: String,
    pub vaultwarden_data_path: String,
    pub vaultwarden_allow_signups: bool,
    pub jellyfin_hostname: String,
    pub jellyfin_path: String,
    pub jellyfin_media_path: String,
    /// `ServiceSettings.homeAssistantPath`, Swift default `/opt/home-assistant`.
    pub home_assistant_path: String,
    /// `ServiceSettings.homeAssistantHostname`; empty means `home.<domain>`.
    pub home_assistant_hostname: String,
    /// `ServiceSettings.machineAtHome` — whether this machine stands inside the house
    pub machine_at_home: bool,
    pub home_assistant_usb_device: String,
    /// `ServiceSettings.mosquittoPath`, Swift default `/opt/mosquitto`.
    pub mosquitto_path: String,
    /// `ServiceSettings.zigbee2MQTTPath`, Swift default `/opt/zigbee2mqtt`.
    pub zigbee2mqtt_path: String,
    /// `ServiceSettings.zigbee2MQTTHostname`; empty means `zigbee.<domain>`.
    pub zigbee2mqtt_hostname: String,
    // The game servers and the panel in front of them.
    pub minecraft_java_path: String,
    pub minecraft_java_version: String,
    pub minecraft_java_flavour: String,
    pub minecraft_java_memory_mb: u32,
    pub minecraft_java_port: u16,
    pub minecraft_java_accepts_eula: bool,
    pub minecraft_java_whitelist: String,
    pub minecraft_java_operators: String,
    pub minecraft_java_mods: String,
    pub minecraft_bedrock_path: String,
    pub minecraft_bedrock_version: String,
    pub minecraft_bedrock_port: u16,
    pub minecraft_bedrock_accepts_eula: bool,
    pub crafty_path: String,
    pub crafty_hostname: String,
    pub ollama_path: String,
    pub ollama_uses_gpu: bool,
    pub open_webui_path: String,
    pub open_webui_hostname: String,
    /// Open registration on the chat
    pub open_webui_allow_signups: bool,
    /// Where the gateway's compose file and routing table live
    pub litellm_path: String,
    /// `ServiceSettings.liteLLMHostname`; empty means `llm.<domain>`.
    pub litellm_hostname: String,
    pub n8n_path: String,
    /// `ServiceSettings.n8nHostname`; empty means `flows.<domain>`.
    pub n8n_hostname: String,
    pub anythingllm_path: String,
    /// `ServiceSettings.anythingLLMHostname`; empty means `docs.<domain>`.
    pub anythingllm_hostname: String,
    /// Where the vector store keeps its segments
    pub qdrant_path: String,
    pub searxng_path: String,
    pub openclaw_path: String,
    /// `ServiceSettings.openclawHostname`; empty means `agent.<domain>`.
    pub openclaw_hostname: String,
    pub photoprism_hostname: String,
    pub photoprism_path: String,
    pub immich_hostname: String,
    pub immich_path: String,
    pub nextcloud_hostname: String,
    pub nextcloud_path: String,
    pub forgejo_hostname: String,
    pub forgejo_path: String,
    pub forgejo_ssh_port: u16,
    pub gitlab_hostname: String,
    pub gitlab_path: String,
    pub gitlab_ssh_port: u16,
    pub seafile_hostname: String,
    pub seafile_path: String,
    pub psono_hostname: String,
    pub psono_path: String,
    /// Third and last product on the `passwords` shelf
    pub passbolt_hostname: String,
    pub passbolt_path: String,
    pub vpn_hostname: String,
    /// `ServiceSettings.vpnClientAccess` — "app", "panel" or "both"
    pub vpn_client_access: String,
    pub wireguard_vpn_port: u16,
    pub amnezia_wg_path: String,
    pub amnezia_wg_port: u16,
    pub shadowsocks_path: String,
    pub shadowsocks_port: u16,
    pub xray_reality_path: String,
    pub xray_reality_port: u16,
    pub xray_reality_sni: String,
    /// One request for a new Reality key, by its token
    pub xray_reality_new_key: String,
    pub openvpn_path: String,
    pub openvpn_port: u16,
    pub mailcow_path: String,
    /// `ServiceSettings.dockerMailserverPath`
    pub docker_mailserver_path: String,
    /// `ServiceSettings.mailuPath`.
    pub mailu_path: String,
    /// `ServiceSettings.mailuSubnet`
    pub mailu_subnet: String,
    /// Whether this deployment wants CrowdSec on the host at all
    pub crowdsec_enabled: bool,
}

impl Default for Input {
    fn default() -> Self {
        Self {
            domain: String::new(),
            additional_domains: Vec::new(),
            language: Language::En,
            local_only: false,
            installed_services: Vec::new(),
            admin_username: "admin".to_string(),
            adguard_path: "/opt/adguardhome".to_string(),
            authelia_path: "/opt/authelia".to_string(), authelia_hostname: String::new(),
            authelia_protected: AutheliaProtection::Default,
            homepage_path: "/opt/homepage".to_string(), homepage_hostname: String::new(),
            pihole_path: "/opt/pihole".to_string(), pihole_hostname: String::new(),
            pihole_upstreams: "1.1.1.1;1.0.0.1".to_string(), pihole_serves_network: false,
            adguard_hostname: String::new(),
            headscale_path: "/opt/headscale".to_string(), headscale_hostname: String::new(),
            headscale_base_domain: String::new(),
            tailscale_node_path: "/opt/tailscale".to_string(), tailscale_node_name: String::new(),
            tailscale_login_server: String::new(), tailscale_auth_key: String::new(),
            cloudflared_path: "/opt/cloudflared".to_string(), cloudflared_token: String::new(),
            vaultwarden_hostname: String::new(), vaultwarden_container: "vaultwarden".to_string(),
            vaultwarden_data_path: "/opt/vaultwarden/data".to_string(), vaultwarden_allow_signups: false,
            jellyfin_hostname: String::new(), jellyfin_path: "/opt/jellyfin".to_string(),
            jellyfin_media_path: "/srv/media".to_string(),
            home_assistant_path: "/opt/home-assistant".to_string(), home_assistant_hostname: String::new(),
            machine_at_home: false,
            home_assistant_usb_device: String::new(),
            mosquitto_path: "/opt/mosquitto".to_string(),
            zigbee2mqtt_path: "/opt/zigbee2mqtt".to_string(), zigbee2mqtt_hostname: String::new(),
            minecraft_java_path: "/opt/minecraft-java".to_string(), minecraft_java_version: String::new(),
            minecraft_java_flavour: "PAPER".to_string(), minecraft_java_memory_mb: 2048, minecraft_java_port: 25565,
            minecraft_java_accepts_eula: false, minecraft_java_whitelist: String::new(),
            minecraft_java_operators: String::new(), minecraft_java_mods: String::new(),
            minecraft_bedrock_path: "/opt/minecraft-bedrock".to_string(), minecraft_bedrock_version: String::new(),
            minecraft_bedrock_port: 19132, minecraft_bedrock_accepts_eula: false,
            crafty_path: "/opt/crafty".to_string(), crafty_hostname: String::new(),
            ollama_path: "/opt/ollama".to_string(), ollama_uses_gpu: false,
            open_webui_path: "/opt/open-webui".to_string(), open_webui_hostname: String::new(),
            open_webui_allow_signups: false,
            litellm_path: "/opt/litellm".to_string(), litellm_hostname: String::new(),
            n8n_path: "/opt/n8n".to_string(), n8n_hostname: String::new(),
            anythingllm_path: "/opt/anythingllm".to_string(), anythingllm_hostname: String::new(),
            qdrant_path: "/opt/qdrant".to_string(),
            searxng_path: "/opt/searxng".to_string(),
            openclaw_path: "/opt/openclaw".to_string(), openclaw_hostname: String::new(),
            photoprism_hostname: String::new(), photoprism_path: "/opt/photoprism".to_string(),
            immich_hostname: String::new(), immich_path: "/opt/immich".to_string(),
            nextcloud_hostname: String::new(), nextcloud_path: "/opt/nextcloud".to_string(),
            forgejo_hostname: String::new(), forgejo_path: "/opt/forgejo".to_string(), forgejo_ssh_port: 2222,
            gitlab_hostname: String::new(),
            gitlab_path: "/opt/gitlab-ce".to_string(),
            gitlab_ssh_port: 2223,
            seafile_hostname: String::new(), seafile_path: "/opt/seafile".to_string(),
            psono_hostname: String::new(), psono_path: "/opt/psono".to_string(),
            passbolt_hostname: String::new(), passbolt_path: "/opt/passbolt".to_string(),
            vpn_hostname: String::new(), vpn_client_access: "both".to_string(),
            wireguard_vpn_port: 51820,
            amnezia_wg_path: "/opt/awgvpn".to_string(), amnezia_wg_port: 51822,
            shadowsocks_path: "/opt/shadowsocks".to_string(), shadowsocks_port: 8388,
            xray_reality_path: "/opt/xray".to_string(), xray_reality_port: 8443,
            xray_reality_sni: "www.apple.com".to_string(),
            xray_reality_new_key: String::new(),
            openvpn_path: "/opt/openvpn".to_string(), openvpn_port: 1194,
            mailcow_path: "/opt/mailcow-dockerized".to_string(),
            docker_mailserver_path: "/opt/docker-mailserver".to_string(),
            mailu_path: "/opt/mailu".to_string(), mailu_subnet: "10.254.29.0/24".to_string(),
            crowdsec_enabled: true,
        }
    }
}

impl Input {
    pub fn mirrored_hostnames(&self, hostname: &str) -> Vec<String> {
        let suffix = format!(".{}", self.domain);
        let Some(prefix) = hostname.strip_suffix(&suffix) else {
            return Vec::new();
        };
        self.additional_domains.iter().map(|d| format!("{prefix}.{d}")).collect()
    }

    #[allow(dead_code)]
    pub fn served_hostnames(&self, hostname: &str) -> Vec<String> {
        let mut names = vec![hostname.to_string()];
        names.extend(self.mirrored_hostnames(hostname));
        names
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Input {
        Input { domain: "example.com".to_string(), ..Input::default() }
    }

    #[test]
    fn mirrors_only_names_under_the_primary_domain() {
        let mut input = base();
        input.additional_domains = vec!["example.org".to_string()];
        assert!(input.mirrored_hostnames("dns.other.net").is_empty());
        assert_eq!(input.mirrored_hostnames("dns.example.com"), vec!["dns.example.org".to_string()]);
    }

    #[test]
    fn served_hostnames_prepends_the_name_itself_in_order() {
        let mut input = base();
        input.additional_domains = vec!["example.org".to_string(), "example.net".to_string()];
        assert_eq!(
            input.served_hostnames("dns.example.com"),
            vec!["dns.example.com".to_string(), "dns.example.org".to_string(), "dns.example.net".to_string()]
        );
    }
}
