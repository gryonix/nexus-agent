//! Tells systemd the agent still answers, for its watchdog.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::state;

/// Silence after which systemd restarts the agent
pub const TIMEOUT: Duration = Duration::from_secs(180);

/// The message that turns the watchdog on
pub fn enable_message() -> String {
    format!("WATCHDOG_USEC={}", TIMEOUT.as_micros())
}

/// The datagram address systemd listens on
fn socket_address(path: &str) -> std::io::Result<std::os::unix::net::SocketAddr> {
    #[cfg(target_os = "linux")]
    if let Some(name) = path.strip_prefix('@') {
        use std::os::linux::net::SocketAddrExt;
        return std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes());
    }
    std::os::unix::net::SocketAddr::from_pathname(path)
}

fn notify(path: &str, message: &str) {
    let Ok(socket) = std::os::unix::net::UnixDatagram::unbound() else { return };
    if let Ok(address) = socket_address(path) {
        let _ = socket.send_to_addr(message.as_bytes(), &address);
    }
}

/// The store answers within a few seconds
async fn store_answers(store: &Arc<Mutex<state::Store>>) -> bool {
    let store = store.clone();
    let probe = tokio::task::spawn_blocking(move || drop(store.lock()));
    matches!(tokio::time::timeout(Duration::from_secs(10), probe).await, Ok(Ok(())))
}

/// Pings systemd while the runtime and store respond
pub fn spawn(store: Arc<Mutex<state::Store>>) {
    let Ok(path) = std::env::var("NOTIFY_SOCKET") else { return };
    let every = TIMEOUT / 3;
    tokio::spawn(async move {
        notify(&path, &enable_message());
        loop {
            if store_answers(&store).await {
                notify(&path, "WATCHDOG=1");
            }
            tokio::time::sleep(every).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_agent_asks_for_a_three_minute_watchdog() {
        assert_eq!(enable_message(), "WATCHDOG_USEC=180000000");
    }

    #[test]
    fn a_ping_reaches_a_path_socket() {
        let path = std::env::temp_dir().join(format!("gryonixnexusd-wd-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let listener = std::os::unix::net::UnixDatagram::bind(&path).unwrap();
        notify(&path.display().to_string(), "WATCHDOG=1");
        let mut buf = [0u8; 32];
        let n = listener.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"WATCHDOG=1");
        let _ = std::fs::remove_file(&path);
    }
}
