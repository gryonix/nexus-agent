//! AmneziaWG — a DPI-resistant WireGuard variant behind the `amnezia-wg-easy` panel, on its own subnet and its own compose project

use crate::install::context::Input;

/// `AmneziaWGVPNService.composeProject`.
pub const COMPOSE_PROJECT: &str = "awgvpn";

/// `AmneziaWGVPNService.containerName`, pinned for the dashboard's restart literal
pub const CONTAINER: &str = "awgvpn";

pub const IMAGE: &str = "ghcr.io/deckersu/amnezia-wg-easy:14";

const BCRYPT_COST: u32 = 12;

/// The panel's own web port inside the container
const WEB_UI_PORT: u16 = 51823;

/// The host directory, from settings.
pub fn dir(input: &Input) -> &str {
    &input.amnezia_wg_path
}

pub fn env_path(input: &Input) -> String {
    format!("{}/.env", dir(input))
}

/// A port of `AmneziaWGVPNService.composeFile`.
pub fn compose_contents(input: &Input) -> String {
    let path = dir(input);
    let port = input.amnezia_wg_port;
    let host = super::super::panel::hostname(input);
    format!(
        "services:
  amnezia-wg-easy:
    image: {IMAGE}
    container_name: {CONTAINER}
    restart: unless-stopped
    cap_add:
      - NET_ADMIN
      - SYS_MODULE
    # Most kernels have no AmneziaWG module, so awg-quick falls back
    # to the userspace amneziawg-go, which needs a TUN device to
    # bring wg0 up. Without it the container crashlooped with
    # \"RTNETLINK: Not supported\" / \"Protocol not supported\".
    devices:
      - /dev/net/tun:/dev/net/tun
    sysctls:
      - net.ipv4.ip_forward=1
      - net.ipv4.conf.all.src_valid_mark=1
    environment:
      WG_HOST: {host}
      WG_PORT: \"{port}\"
      # 10.10.0.x: clear of the relay tunnel (10.8.0.0/24) and the
      # plain WireGuard VPN (10.9.0.0/24).
      WG_DEFAULT_ADDRESS: 10.10.0.x
      PASSWORD_HASH: ${{PASSWORD_HASH}}
      PORT: \"{WEB_UI_PORT}\"
    volumes:
      # The deckersu fork stores its config under
      # /etc/amnezia/amneziawg (NOT wg-easy's /etc/wireguard) — the
      # container ENOENT-crashlooped saving wg0.json when mounted at
      # the wrong path, and the panel (which reads <path>/data/
      # wg0.json) saw nothing. Mount at the path the fork uses.
      - {path}/data:/etc/amnezia/amneziawg
    ports:
      # The wg-easy fork sets the wg0 interface's ListenPort to
      # WG_PORT (the same value advertised to clients), so the
      # container listens on `port` INTERNALLY — not on a fixed
      # 51820. Publishing host:port onto a different container port
      # (the old 51820) sent every UDP packet to a port nothing
      # listened on: clients handshook into a black hole. The
      # container port must equal WG_PORT. (The unified VPN panel's
      # own wgpanel already does this right — host:wgPort→wgPort.)
      - \"{port}:{port}/udp\"
      - \"127.0.0.1:{WEB_UI_PORT}:{WEB_UI_PORT}\""
    )
}

/// The `.env`, in the generator's own two `printf` shapes
pub fn env_contents(password: &str, hash: Option<&str>) -> String {
    match hash {
        Some(hash) => format!("ADMIN_PASSWORD={password}\nPASSWORD_HASH={}\n", escape_hash(hash)),
        None => format!("ADMIN_PASSWORD={password}\nPASSWORD_HASH=\n"),
    }
}

pub fn escape_hash(hash: &str) -> String {
    let mut out = String::with_capacity(hash.len() + 4);
    let mut chars = hash.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '$' {
            out.push(c);
            continue;
        }
        while chars.peek() == Some(&'$') {
            chars.next();
        }
        out.push_str("$$");
    }
    out
}

/// bcrypt hash (`$2b$`) of a panel password
pub fn hash_password(password: &str, salt: [u8; 16]) -> Option<String> {
    let parts = bcrypt::hash_with_salt(password, BCRYPT_COST, salt).ok()?;
    Some(parts.format_for_version(bcrypt::Version::TwoB).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hash_verifies_against_its_password() {
        let hash = hash_password("s3cret", [7; 16]).unwrap();
        assert!(hash.starts_with("$2b$12$"), "{hash}");
        assert_eq!(hash.len(), 60);
        assert!(bcrypt::verify("s3cret", &hash).unwrap());
        assert!(!bcrypt::verify("other", &hash).unwrap());
    }

    #[test]
    fn the_same_salt_gives_the_same_hash() {
        assert_eq!(hash_password("pw", [1; 16]), hash_password("pw", [1; 16]));
        assert_ne!(hash_password("pw", [1; 16]), hash_password("pw", [2; 16]));
    }

    #[test]
    fn a_hash_from_bcryptjs_verifies() {
        let from_bcryptjs = "$2b$12$3ZKWNtCqpfNJCuUJ.A.0e.Zaw1eHL5klNn0r7DcIPbCgQj9t7Cz4i";
        assert!(bcrypt::verify("abc123", from_bcryptjs).unwrap());
    }

    #[test]
    fn escaping_a_hash_is_idempotent() {
        let raw = "$2b$12$Kix4Cl/pw";
        let once = escape_hash(raw);
        assert_eq!(once, "$$2b$$12$$Kix4Cl/pw");
        assert_eq!(escape_hash(&once), once, "a second pass must not grow it");
        assert_eq!(escape_hash("$$$$a"), "$$a", "a run of any length collapses to $$");
        assert_eq!(escape_hash("plain"), "plain");
    }

    #[test]
    fn the_degraded_env_still_names_both_keys() {
        assert_eq!(env_contents("pw", None), "ADMIN_PASSWORD=pw\nPASSWORD_HASH=\n");
        assert_eq!(
            env_contents("pw", Some("$2b$x")),
            "ADMIN_PASSWORD=pw\nPASSWORD_HASH=$$2b$$x\n"
        );
    }
}

#[cfg(test)]
mod fixture_parity {
    use super::*;
    use crate::install::vpn::protocols::tests_support::{fixture, scenario_input};

    fn env_from_fixture(steps: &str, degraded: bool, password: &str, hash: &str) -> String {
        let needle = if degraded { "PASSWORD_HASH=\\n'" } else { "PASSWORD_HASH=%s\\n'" };
        let line = steps
            .lines()
            .find(|line| line.trim_start().starts_with("printf 'ADMIN_PASSWORD=") && line.contains(needle))
            .unwrap_or_else(|| panic!("no printf for the {} .env", if degraded { "degraded" } else { "hashed" }));
        let format = line
            .trim_start()
            .trim_start_matches("printf '")
            .split_once("' ")
            .expect("a quoted format followed by arguments")
            .0;
        let mut out = String::new();
        let mut values = [password, hash].into_iter();
        let mut rest = format;
        while let Some(at) = rest.find("%s") {
            out.push_str(&rest[..at]);
            out.push_str(values.next().expect("one value per %s"));
            rest = &rest[at + 2..];
        }
        out.push_str(rest);
        out.replace("\\n", "\n")
    }

    fn assert_parity(scenario: &str) {
        let input = scenario_input(scenario);
        let steps = fixture(&format!("awg-{scenario}__setup-steps.txt"));
        assert_eq!(
            compose_contents(&input),
            fixture(&format!("awg-{scenario}__docker-compose.yml")),
            "{scenario}: docker-compose.yml"
        );
        assert_eq!(
            dir(&input),
            fixture(&format!("awg-{scenario}__compose-directory.txt")),
            "{scenario}: compose directory"
        );
        assert_eq!(
            env_contents("PW", Some("HASH")),
            env_from_fixture(&steps, false, "PW", "HASH"),
            "{scenario}: .env (hashed)"
        );
        assert_eq!(
            env_contents("PW", None),
            env_from_fixture(&steps, true, "PW", ""),
            "{scenario}: .env (degraded)"
        );
    }

    #[test]
    fn default_public_en() {
        assert_parity("default-public-en");
    }

    #[test]
    fn custompaths_public_en() {
        assert_parity("custompaths-public-en");
    }

    #[test]
    fn customhost_public_en() {
        assert_parity("customhost-public-en");
        assert!(compose_contents(&scenario_input("customhost-public-en"))
            .contains("WG_HOST: tunnel.example.com"));
    }

    #[test]
    fn default_public_ru() {
        assert_parity("default-public-ru");
        let en = scenario_input("default-public-en");
        let ru = scenario_input("default-public-ru");
        assert_eq!(compose_contents(&en), compose_contents(&ru));
    }
}
