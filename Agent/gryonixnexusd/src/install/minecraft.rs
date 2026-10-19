//! The Minecraft servers' declarative install artifacts — a port of `MinecraftJavaService.swift` and `MinecraftBedrockService.swift`, declarative halves only

use super::context::Input;

pub const JAVA_IMAGE: &str = "itzg/minecraft-server:2026.8.1-java25";
pub const JAVA_COMPOSE_PROJECT: &str = "minecraft-java";
pub const JAVA_CONTAINER: &str = "minecraft-java";
pub const JAVA_RCON_PORT: u16 = 25575;

pub const BEDROCK_IMAGE: &str = "itzg/minecraft-bedrock-server:2026.8.2";
pub const BEDROCK_COMPOSE_PROJECT: &str = "minecraft-bedrock";
pub const BEDROCK_CONTAINER: &str = "minecraft-bedrock";

pub fn java_compose_contents(input: &Input) -> String {
    let path = &input.minecraft_java_path;
    let eula = if input.minecraft_java_accepts_eula { "TRUE" } else { "FALSE" };
    let flavour = &input.minecraft_java_flavour;
    let memory = input.minecraft_java_memory_mb;
    let port = input.minecraft_java_port;
    let mut environment = format!(
        "      EULA: \"{eula}\"\n      TYPE: \"{flavour}\"\n      MEMORY: \"{memory}M\"\n      # Enabled so the panel and the backup wrapper can ask a\n      # RUNNING server to flush its world before anything reads it.\n      ENABLE_RCON: \"true\"\n      RCON_PASSWORD: \"${{RCON_PASSWORD}}\""
    );
    let version = input.minecraft_java_version.trim();
    if !version.is_empty() {
        environment.push_str(&format!("\n      VERSION: \"{version}\""));
    }
    let whitelist = input.minecraft_java_whitelist.trim();
    if !whitelist.is_empty() {
        environment.push_str(&format!("\n      WHITELIST: \"{whitelist}\""));
        environment.push_str("\n      ENFORCE_WHITELIST: \"true\"");
    }
    let operators = input.minecraft_java_operators.trim();
    if !operators.is_empty() {
        environment.push_str(&format!("\n      OPS: \"{operators}\""));
    }
    let mods = input.minecraft_java_mods.trim();
    if !mods.is_empty() {
        environment.push_str(&format!("\n      MODRINTH_PROJECTS: \"{mods}\""));
        environment.push_str("\n      MODRINTH_DOWNLOAD_DEPENDENCIES: \"required\"");
    }
    format!(
        "services:\n  minecraft-java:\n    image: {JAVA_IMAGE}\n    container_name: {JAVA_CONTAINER}\n    restart: unless-stopped\n    # The server reads commands from its own stdin, and that is how\n    # both a clean stop and the panel's console work. Without these\n    # two the container can only be killed, which is how a world\n    # gets corrupted.\n    stdin_open: true\n    tty: true\n    environment:\n{environment}\n    volumes:\n      - {path}/data:/data\n      # The image's own drop-in directories, and this is where an\n      # uploaded file lands: content here is SYNCHRONISED into\n      # /data/mods (and /data/plugins) at every start, so a jar the\n      # owner sent from the app survives a restart, an image update\n      # and every change to the Modrinth list — which manages only\n      # what it installed itself. Read-only: the server has no\n      # business writing back into what somebody uploaded.\n      #\n      # Both, always, because the answer to \"mods or plugins?\" is\n      # the TYPE, and the TYPE is a setting that can change on a\n      # server that already exists.\n      - {path}/mods:/mods:ro\n      - {path}/plugins:/plugins:ro\n    ports:\n      - \"{port}:25565\"\n      # RCON stays on loopback: its password is the whole of its\n      # security, and the panel reaches it from the same host.\n      - \"127.0.0.1:{JAVA_RCON_PORT}:25575\""
    )
}

/// A port of `MinecraftJavaService.composeFile(_:).envTemplate`
pub fn java_env_template() -> String {
    "RCON_PASSWORD=__RANDOM__".to_string()
}

/// A port of `MinecraftBedrockService.composeFile(_:).composeContents`.
pub fn bedrock_compose_contents(input: &Input) -> String {
    let path = &input.minecraft_bedrock_path;
    let eula = if input.minecraft_bedrock_accepts_eula { "TRUE" } else { "FALSE" };
    let port = input.minecraft_bedrock_port;
    let mut environment = format!("      EULA: \"{eula}\"\n      SERVER_PORT: \"{port}\"");
    let version = input.minecraft_bedrock_version.trim();
    if !version.is_empty() {
        environment.push_str(&format!("\n      VERSION: \"{version}\""));
    }
    format!(
        "services:\n  minecraft-bedrock:\n    image: {BEDROCK_IMAGE}\n    container_name: {BEDROCK_CONTAINER}\n    restart: unless-stopped\n    # Same reason as the Java server: a clean stop is a command\n    # written to the server's stdin, and without a terminal the\n    # only way out is a kill.\n    stdin_open: true\n    tty: true\n    environment:\n{environment}\n    volumes:\n      - {path}/data:/data\n    ports:\n      # UDP, and that is the whole protocol — Bedrock is RakNet\n      # over UDP, so a TCP rule here would open nothing at all.\n      - \"{port}:{port}/udp\""
    )
}

#[allow(dead_code)]
pub fn dns_hostnames(input: &Input) -> Vec<String> {
    vec![format!("play.{}", input.domain)]
}

/// A port of `MinecraftJavaService.firewallPorts(_:)`
pub fn java_firewall_ports(input: &Input) -> Vec<(u16, &'static str)> {
    vec![(input.minecraft_java_port, "tcp")]
}

/// A port of `MinecraftBedrockService.firewallPorts(_:)`
pub fn bedrock_firewall_ports(input: &Input) -> Vec<(u16, &'static str)> {
    vec![(input.minecraft_bedrock_port, "udp")]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Input {
        Input { domain: "example.com".to_string(), ..Input::default() }
    }

    #[test]
    fn the_license_is_written_exactly_as_it_was_answered() {
        assert!(java_compose_contents(&base()).contains("EULA: \"FALSE\""));
        let mut input = base();
        input.minecraft_java_accepts_eula = true;
        assert!(java_compose_contents(&input).contains("EULA: \"TRUE\""));
    }

    #[test]
    fn a_whitelist_is_always_written_together_with_its_enforcement() {
        let mut input = base();
        assert!(!java_compose_contents(&input).contains("WHITELIST"));
        input.minecraft_java_whitelist = "dana,alex".to_string();
        let compose = java_compose_contents(&input);
        assert!(compose.contains("WHITELIST: \"dana,alex\""));
        assert!(compose.contains("ENFORCE_WHITELIST: \"true\""));
    }

    #[test]
    fn bedrock_is_udp_on_both_sides() {
        let input = base();
        assert!(bedrock_compose_contents(&input).contains("- \"19132:19132/udp\""));
        assert_eq!(bedrock_firewall_ports(&input), vec![(19132, "udp")]);
        assert_eq!(java_firewall_ports(&input), vec![(25565, "tcp")]);
    }

    #[test]
    fn no_mods_means_no_modrinth_keys_at_all() {
        let compose = java_compose_contents(&base());
        assert!(!compose.contains("MODRINTH_PROJECTS"));
        assert!(!compose.contains("MODRINTH_DOWNLOAD_DEPENDENCIES"));
        let mut input = base();
        input.minecraft_java_mods = "   ".to_string();
        assert!(!java_compose_contents(&input).contains("MODRINTH_PROJECTS"));
        input.minecraft_java_mods = "fabric-api:bQZpGIz0".to_string();
        let compose = java_compose_contents(&input);
        assert!(compose.contains("MODRINTH_PROJECTS: \"fabric-api:bQZpGIz0\""));
        assert!(compose.contains("MODRINTH_DOWNLOAD_DEPENDENCIES: \"required\""));
    }

    #[test]
    fn the_drop_in_directories_are_always_mounted_read_only() {
        let compose = java_compose_contents(&base());
        assert!(compose.contains("- /opt/minecraft-java/mods:/mods:ro"));
        assert!(compose.contains("- /opt/minecraft-java/plugins:/plugins:ro"));
    }

    /// RCON is never published beyond loopback.
    #[test]
    fn rcon_is_bound_to_loopback() {
        assert!(java_compose_contents(&base()).contains("- \"127.0.0.1:25575:25575\""));
    }
}

#[cfg(test)]
mod fixture_parity {
    use super::*;

    fn fixture(name: &str) -> String {
        let path = format!("{}/tests/fixtures/install/{name}", env!("CARGO_MANIFEST_DIR"));
        std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("missing fixture {path}: {err}"))
    }

    fn base() -> Input {
        let mut input = Input { domain: "example.com".to_string(), ..Input::default() };
        input.minecraft_java_accepts_eula = true;
        input.minecraft_bedrock_accepts_eula = true;
        input
    }

    #[test]
    fn java_default_public_en() {
        assert_eq!(
            java_compose_contents(&base()),
            fixture("mc-java-default-public-en__docker-compose.yml")
        );
        assert_eq!(
            dns_hostnames(&base()).join("\n"),
            fixture("mc-java-default-public-en__dns-hostnames.txt")
        );
    }

    #[test]
    fn java_configured_public_en() {
        let mut input = base();
        input.minecraft_java_version = "1.21.4".to_string();
        input.minecraft_java_flavour = "FABRIC".to_string();
        input.minecraft_java_memory_mb = 6144;
        input.minecraft_java_port = 25566;
        input.minecraft_java_whitelist = "dana,alex".to_string();
        input.minecraft_java_operators = "dana".to_string();
        input.minecraft_java_path = "/srv/mc".to_string();
        assert_eq!(
            java_compose_contents(&input),
            fixture("mc-java-configured-public-en__docker-compose.yml")
        );
    }

    #[test]
    fn java_with_mods_public_en() {
        let mut input = base();
        input.minecraft_java_version = "1.21.4".to_string();
        input.minecraft_java_flavour = "FABRIC".to_string();
        input.minecraft_java_memory_mb = 6144;
        input.minecraft_java_port = 25566;
        input.minecraft_java_whitelist = "dana,alex".to_string();
        input.minecraft_java_operators = "dana".to_string();
        input.minecraft_java_path = "/srv/mc".to_string();
        input.minecraft_java_mods = "fabric-api:bQZpGIz0,sodium:AANobbMO".to_string();
        assert_eq!(
            java_compose_contents(&input),
            fixture("mc-java-mods-public-en__docker-compose.yml")
        );
    }

    #[test]
    fn java_without_the_license_public_en() {
        let input = Input { domain: "example.com".to_string(), ..Input::default() };
        assert_eq!(
            java_compose_contents(&input),
            fixture("mc-java-noeula-public-en__docker-compose.yml")
        );
    }

    #[test]
    fn bedrock_default_public_en() {
        assert_eq!(
            bedrock_compose_contents(&base()),
            fixture("mc-bedrock-default-public-en__docker-compose.yml")
        );
    }

    #[test]
    fn bedrock_configured_public_en() {
        let mut input = base();
        input.minecraft_bedrock_version = "1.21.44".to_string();
        input.minecraft_bedrock_port = 19133;
        input.minecraft_bedrock_path = "/srv/bedrock".to_string();
        assert_eq!(
            bedrock_compose_contents(&input),
            fixture("mc-bedrock-configured-public-en__docker-compose.yml")
        );
    }
}
