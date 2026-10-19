//! GitLab CE's declarative install artifacts — a port of `Packages/gryonixNexus/Sources/ServiceCatalog/Services/GitLabService.swift`, declarative half only

use super::caddy::{self, WebIngress};
use super::context::Input;

pub const SERVICE_ID: &str = "gitlab";

pub const IMAGE: &str = "gitlab/gitlab-ce:19.2.1-ce.0";
pub const COMPOSE_PROJECT: &str = "gitlab";
pub const CONTAINER: &str = "gitlab";
pub const WEB_UI_PORT: u16 = 8084;

/// A port of `GitLabService.hostname(_:)`.
pub fn hostname(input: &Input) -> String {
    if input.gitlab_hostname.is_empty() {
        super::hostnames::default_hostname(
            SERVICE_ID, &input.domain, &input.installed_services)
    } else {
        input.gitlab_hostname.clone()
    }
}

pub fn ssh_port(input: &Input) -> Option<u16> {
    if input.gitlab_ssh_port > 0 {
        Some(input.gitlab_ssh_port)
    } else {
        None
    }
}

/// A port of `GitLabService.composeFile(_:).composeContents`, both branches
pub fn compose_contents(input: &Input) -> String {
    let path = &input.gitlab_path;
    let host = hostname(input);
    let (ssh_setting, ssh_publish) = match ssh_port(input) {
        Some(port) => (
            format!("\n        gitlab_rails['gitlab_shell_ssh_port'] = {port}"),
            format!("\n      - \"{port}:22\""),
        ),
        None => (String::new(), String::new()),
    };
    format!(
        "services:\n  gitlab:\n    image: {IMAGE}\n    container_name: {CONTAINER}\n    restart: unless-stopped\n    hostname: {host}\n    # Upstream's own compose example raises this: the stock 64 MB\n    # of /dev/shm is not enough for the omnibus PostgreSQL.\n    shm_size: \"256m\"\n    environment:\n      # Passed separately so the secret stays in .env (0600) and\n      # never lands in docker-compose.yml; the omnibus config below\n      # reads it through ENV, which also keeps every literal `$`\n      # out of a file docker compose interpolates.\n      GITLAB_ROOT_PASSWORD: ${{GITLAB_ROOT_PASSWORD}}\n      GITLAB_OMNIBUS_CONFIG: |\n        external_url 'https://{host}'\n        # Caddy terminates TLS and proxies plain HTTP to the\n        # loopback port; without these two the bundled nginx binds\n        # HTTPS itself and answers the proxy with a redirect loop.\n        # Key names are VERSION-SPECIFIC and were read out of the\n        # pinned release's own gitlab.rb.template: master has since\n        # moved them under gitlab_rails['nginx'], and an omnibus\n        # that does not recognise a key simply ignores it — the\n        # failure would be a silently HTTPS-only nginx, not an error.\n        nginx['listen_port'] = 80\n        nginx['listen_https'] = false\n        # An https external_url turns omnibus' own Let's Encrypt\n        # client ON by default. It would race Caddy for the same\n        # name and burn that name's ACME failure quota, and the\n        # certificate it fought for is one nothing here serves.\n        letsencrypt['enable'] = false\n        # Applied on the FIRST reconfigure only (omnibus ignores it\n        # once the database is seeded), so a re-run never resets a\n        # password the user has since changed.\n        gitlab_rails['initial_root_password'] = ENV['GITLAB_ROOT_PASSWORD']\n        # The image otherwise writes the password it used into\n        # /etc/gitlab/initial_root_password and deletes it after\n        # 24 h. Ours is already in .env and in the install report —\n        # a third copy is one more place to leak it from, and one\n        # that disappears on its own schedule.\n        gitlab_rails['store_initial_root_password'] = false\n        gitlab_rails['display_initial_root_password'] = false\n        # The bundled Prometheus/exporter stack is the largest\n        # slice of idle memory here and duplicates the metrics\n        # collector this project installs on the host anyway.\n        prometheus_monitoring['enable'] = false\n        # Two workers is upstream's own guidance for a small\n        # install; the default scales to a machine nobody here has.\n        puma['worker_processes'] = 2{ssh_setting}\n    volumes:\n      - {path}/config:/etc/gitlab\n      - {path}/logs:/var/log/gitlab\n      - {path}/data:/var/opt/gitlab\n      - /etc/localtime:/etc/localtime:ro\n    ports:\n      - \"127.0.0.1:{WEB_UI_PORT}:80\"{ssh_publish}"
    )
}

/// A port of `GitLabService.composeFile(_:).envTemplate`
pub fn env_template() -> String {
    "GITLAB_ROOT_PASSWORD=__RANDOM__".to_string()
}

/// A port of `GitLabService.dnsHostnames(_:)`
#[allow(dead_code)]
pub fn dns_hostnames(input: &Input) -> Vec<String> {
    vec![hostname(input)]
}

pub fn web_ingress(input: &Input) -> WebIngress {
    WebIngress { hostname: hostname(input), upstream_port: WEB_UI_PORT, admin_guard: true, upstream_https: false, public_paths: Vec::new() }
}

/// The Caddy site NAMES this ingress publishes — see `adguard::caddy_site_names`
pub fn caddy_site_names(input: &Input) -> Vec<String> {
    let ingress = web_ingress(input);
    let mut names = vec![ingress.hostname.clone()];
    names.extend(input.mirrored_hostnames(&ingress.hostname));
    names
}

/// A port of the GitLab slice of `ServiceInfraSections.writeCaddyfile`.
pub fn caddy_site(input: &Input) -> String {
    let ingress = web_ingress(input);
    let joined = caddy_site_names(input).join(", ");
    caddy::site(SERVICE_ID, &joined, ingress.upstream_port, ingress.admin_guard, ingress.upstream_https, input.local_only)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base(domain: &str) -> Input {
        Input { domain: domain.to_string(), ..Input::default() }
    }

    #[test]
    fn hostname_defaults_to_the_plain_git_name_when_it_is_the_only_forge() {
        assert_eq!(hostname(&base("example.com")), "git.example.com");
        let mut both = base("example.com");
        both.installed_services = vec!["forgejo".to_string(), SERVICE_ID.to_string()];
        assert_eq!(hostname(&both), "gitlab.example.com");
    }

    #[test]
    fn omnibus_is_told_to_serve_plain_http_and_leave_acme_alone() {
        let compose = compose_contents(&base("example.com"));
        assert!(compose.contains("nginx['listen_port'] = 80"));
        assert!(compose.contains("nginx['listen_https'] = false"));
        assert!(compose.contains("letsencrypt['enable'] = false"));
    }

    #[test]
    fn the_root_password_travels_through_the_environment() {
        let compose = compose_contents(&base("example.com"));
        assert!(compose.contains("GITLAB_ROOT_PASSWORD: ${GITLAB_ROOT_PASSWORD}"));
        assert!(compose.contains("gitlab_rails['initial_root_password'] = ENV['GITLAB_ROOT_PASSWORD']"));
        assert!(compose.contains("gitlab_rails['store_initial_root_password'] = false"));
    }

    /// Port 0 is OFF: nothing published and nothing advertised.
    #[test]
    fn a_zero_port_switches_git_over_ssh_off_entirely() {
        let mut input = base("example.com");
        input.gitlab_ssh_port = 0;
        assert_eq!(ssh_port(&input), None);
        let compose = compose_contents(&input);
        assert!(!compose.contains("gitlab_shell_ssh_port"));
        assert!(!compose.contains(":22\""));
    }

    #[test]
    fn the_advertised_port_is_the_published_one() {
        let mut input = base("example.com");
        input.gitlab_ssh_port = 2224;
        let compose = compose_contents(&input);
        assert!(compose.contains("gitlab_rails['gitlab_shell_ssh_port'] = 2224"));
        assert!(compose.contains("- \"2224:22\""));
    }
}

/// Byte-for-byte parity against REAL Swift-generated output — same discipline as `adguard::fixture_parity`
#[cfg(test)]
mod fixture_parity {
    use super::*;

    fn fixture(name: &str) -> String {
        let path = format!("{}/tests/fixtures/install/{name}", env!("CARGO_MANIFEST_DIR"));
        std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("missing fixture {path}: {err}"))
    }

    fn base(domain: &str) -> Input {
        Input { domain: domain.to_string(), ..Input::default() }
    }

    fn ingress_text(ingress: &WebIngress) -> String {
        format!(
            "hostname={}\nupstreamPort={}\nadminGuard={}\nupstreamHTTPS={}",
            ingress.hostname, ingress.upstream_port, ingress.admin_guard, ingress.upstream_https
        )
    }

    fn assert_parity(input: &Input, scenario: &str) {
        assert_eq!(
            compose_contents(input),
            fixture(&format!("{scenario}__docker-compose.yml")),
            "{scenario}: docker-compose.yml"
        );
        assert_eq!(env_template(), fixture(&format!("{scenario}__env.template")), "{scenario}: env.template");
        assert_eq!(hostname(input), fixture(&format!("{scenario}__hostname.txt")), "{scenario}: hostname.txt");
        assert_eq!(
            dns_hostnames(input).join("\n"),
            fixture(&format!("{scenario}__dns-hostnames.txt")),
            "{scenario}: dns-hostnames.txt"
        );
        assert_eq!(caddy_site(input), fixture(&format!("{scenario}__caddy-site.txt")), "{scenario}: caddy-site.txt");
        assert_eq!(
            ingress_text(&web_ingress(input)),
            fixture(&format!("{scenario}__ingress.txt")),
            "{scenario}: ingress.txt"
        );
    }

    #[test]
    fn default_public_en() {
        assert_parity(&base("example.com"), "gl-default-public-en");
    }

    #[test]
    fn mirrored_public_en() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string(), "example.net".to_string()];
        assert_parity(&input, "gl-mirrored-public-en");
    }

    #[test]
    fn localonly_en() {
        let mut input = base("home.local");
        input.local_only = true;
        assert_parity(&input, "gl-localonly-en");
    }

    #[test]
    fn customhost_public_en() {
        let mut input = base("example.com");
        input.gitlab_hostname = "forge.example.com".to_string();
        assert_parity(&input, "gl-customhost-public-en");
    }

    #[test]
    fn custompath_public_en() {
        let mut input = base("example.com");
        input.gitlab_path = "/srv/gitlab".to_string();
        input.gitlab_ssh_port = 2224;
        assert_parity(&input, "gl-custompath-public-en");
    }

    #[test]
    fn nossh_public_en() {
        let mut input = base("example.com");
        input.gitlab_ssh_port = 0;
        assert_parity(&input, "gl-nossh-public-en");
    }

    /// The mirroring GUARD — see `adguard::fixture_parity`.
    #[test]
    fn foreignhost_mirrored_public_en() {
        let mut input = base("example.com");
        input.additional_domains = vec!["example.org".to_string()];
        input.gitlab_hostname = "gitlab.other-company.net".to_string();
        assert_parity(&input, "gl-foreignhost-mirrored-public-en");
    }
}
