//! The mail engines' install surface — declarative AND imperative, for all three now

pub mod dockermailserver;
pub mod mailcow;
pub mod mailu;
/// A free range for Mailu's network
pub mod subnet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallPort {
    pub port: u16,
    pub proto: Proto,
    /// Why this port is open
    pub comment: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    #[allow(dead_code)]
    Udp,
}

impl Proto {
    #[allow(dead_code)]
    pub fn as_str(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        }
    }
}

impl FirewallPort {
    pub fn tcp(port: u16, comment: &str) -> Self {
        Self { port, proto: Proto::Tcp, comment: comment.to_string() }
    }

    /// Unused today for the same reason `Proto::Udp` is.
    #[allow(dead_code)]
    pub fn udp(port: u16, comment: &str) -> Self {
        Self { port, proto: Proto::Udp, comment: comment.to_string() }
    }
}
