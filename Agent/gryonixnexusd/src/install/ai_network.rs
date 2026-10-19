//! The Docker network the AI services reach each other on.
//!
//! A port of `AIServicesNetwork`. External, so a service's `compose down`
//! never takes it from the others, and each member creates it if missing.

/// The network's name.
pub const NAME: &str = "gryonixnexus-ai";

/// Joins a service to the network; ends its compose file.
pub const COMPOSE_TAIL: &str = "\n    networks:\n      - gryonixnexus-ai\nnetworks:\n  gryonixnexus-ai:\n    external: true";

/// A neighbour's address on the shared network.
pub fn url(container: &str, port: u16) -> String {
    format!("http://{container}:{port}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tail_names_the_network_it_declares() {
        assert_eq!(COMPOSE_TAIL.matches(NAME).count(), 2);
        assert_eq!(url("ollama", 11434), "http://ollama:11434");
    }
}
