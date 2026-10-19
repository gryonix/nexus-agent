//! SearXNG's declarative install artifacts — a port of `SearXNGService.swift`, declarative half only

use super::context::Input;

pub const SERVICE_ID: &str = "searxng";

pub const IMAGE: &str = "searxng/searxng:2026.9.7-3e454637f";
pub const COMPOSE_PROJECT: &str = "searxng";
pub const CONTAINER: &str = "searxng";
/// Loopback port the neighbours query.
pub const WEB_UI_PORT: u16 = 8101;
/// The port inside the container — their entrypoint's own default.
pub const CONTAINER_PORT: u16 = 8080;

/// The URL a neighbour on this host queries
pub fn query_url() -> String {
    super::ai_network::url(CONTAINER, CONTAINER_PORT) + "/search?q=<query>"
}

pub fn settings_path(input: &Input) -> String {
    format!("{}/config/settings.yml", input.searxng_path)
}

/// A port of `SearXNGService.settingsFile(_:)`
pub fn settings_file() -> String {
    "# Written by gryonixNexus. Upstream's defaults are NOT copied here —\n# they are read out of the image, and only what this deployment\n# changes is named below.\nuse_default_settings: true\n\nsearch:\n  # A program asks for JSON; the default is html only, and a chat that\n  # queries this engine gets a refusal without this line.\n  formats:\n    - html\n    - json".to_string()
}

/// A port of `SearXNGService.composeFile(_:).composeContents`.
pub fn compose_contents(input: &Input) -> String {
    compose_services(input) + super::ai_network::COMPOSE_TAIL
}

/// The services block, before the shared network joins it
fn compose_services(input: &Input) -> String {
    let path = &input.searxng_path;
    format!("services:\n  searxng:\n    image: {IMAGE}\n    container_name: {CONTAINER}\n    restart: unless-stopped\n    environment:\n      # Signs the form state their pages carry. Generated on the\n      # server; regenerating it on every start would invalidate\n      # every open tab, which is why it lives in `.env`.\n      SEARXNG_SECRET: ${{SEARXNG_SECRET}}\n      SEARXNG_PORT: {CONTAINER_PORT}\n      # Their default is the rate limiter OFF, and this deployment\n      # is the case it was written for: the port answers on\n      # loopback only, so the callers are the containers on this\n      # host. A limiter here would also need the datastore it\n      # counts in, which is a second container for a queue nobody\n      # outside can join.\n      SEARXNG_LIMITER: \"false\"\n    volumes:\n      # Their entrypoint writes a settings file here when it finds\n      # none. The install below always leaves one, so what runs is\n      # always the file this repository generated.\n      - {path}/config:/etc/searxng\n      - {path}/cache:/var/cache/searxng\n    ports:\n      # Loopback. The neighbours reach it on the shared AI\n      # network; nothing publishes it.\n      - \"127.0.0.1:{WEB_UI_PORT}:{CONTAINER_PORT}\"")
}

/// A port of `SearXNGService.composeFile(_:).envTemplate`.
pub fn env_template() -> String {
    "SEARXNG_SECRET=__RANDOM__".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Input {
        Input { domain: "example.com".to_string(), ..Input::default() }
    }

    /// Loopback, and nothing else
    #[test]
    fn the_engine_is_bound_to_loopback_only() {
        let text = compose_contents(&base());
        assert!(text.contains(&format!("\"127.0.0.1:{WEB_UI_PORT}:{CONTAINER_PORT}\"")));
        assert!(!text.contains("0.0.0.0"));
    }

    #[test]
    fn the_settings_turn_json_on_without_taking_html_away() {
        let text = settings_file();
        assert!(text.contains("- json"));
        assert!(text.contains("- html"));
    }

    #[test]
    fn the_settings_are_ours_and_stay_short() {
        let text = settings_file();
        assert!(text.contains("use_default_settings: true"));
        assert!(text.lines().count() < 20, "this file is ours; anything this long is theirs");
    }
}

/// Byte-for-byte parity against REAL Swift-generated output.
#[cfg(test)]
mod fixture_parity {
    use super::*;

    fn fixture(name: &str) -> String {
        let path = format!("{}/tests/fixtures/install/{name}", env!("CARGO_MANIFEST_DIR"));
        std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("missing fixture {path}: {err}"))
    }

    #[test]
    fn default_public_en() {
        let input = Input { domain: "example.com".to_string(), ..Input::default() };
        assert_eq!(
            compose_contents(&input),
            fixture("searxng-default-public-en__docker-compose.yml")
        );
        assert_eq!(settings_file(), fixture("searxng-default-public-en__settings.yml"));
        assert_eq!(env_template(), fixture("searxng-default-public-en__env.template"));
    }

    #[test]
    fn custompath_public_en() {
        let mut input = Input { domain: "example.com".to_string(), ..Input::default() };
        input.searxng_path = "/srv/searxng".to_string();
        assert_eq!(
            compose_contents(&input),
            fixture("searxng-custompath-public-en__docker-compose.yml")
        );
    }
}
