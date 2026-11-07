//! The agent's own memory, connections and start time.

use std::sync::OnceLock;

use crate::pb;

static STARTED_AT: OnceLock<i64> = OnceLock::new();

/// Remembers when the daemon started
pub fn mark_start() {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as i64);
    let _ = STARTED_AT.set(now);
}

/// A `VmRSS:`-style line from /proc status, in bytes
pub fn status_bytes(status: &str, key: &str) -> u64 {
    status
        .lines()
        .find_map(|line| line.strip_prefix(key))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|kb| kb.parse::<u64>().ok())
        .map_or(0, |kb| kb * 1024)
}

/// A process command line is a bridge
pub fn is_bridge(cmdline: &[u8]) -> bool {
    let mut parts = cmdline.split(|b| *b == 0).filter(|part| !part.is_empty());
    let program = parts.next().unwrap_or_default();
    program.ends_with(b"gryonixnexusd") && parts.next() == Some(b"bridge".as_slice())
}

fn open_bridges() -> u32 {
    let Ok(entries) = std::fs::read_dir("/proc") else { return 0 };
    entries
        .flatten()
        .filter(|entry| entry.file_name().to_string_lossy().bytes().all(|b| b.is_ascii_digit()))
        .filter_map(|entry| std::fs::read(entry.path().join("cmdline")).ok())
        .filter(|cmdline| is_bridge(cmdline))
        .count() as u32
}

/// The daemon's current footprint
pub fn read() -> pb::AgentHealth {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    pb::AgentHealth {
        memory_bytes: status_bytes(&status, "VmRSS:"),
        peak_memory_bytes: status_bytes(&status, "VmHWM:"),
        open_channels: open_bridges(),
        started_at: STARTED_AT.get().copied().unwrap_or_default(),
        modules: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_lines_read_as_bytes() {
        let status = "Name:\tgryonixnexusd\nVmHWM:\t   40960 kB\nVmRSS:\t   33040 kB\n";
        assert_eq!(status_bytes(status, "VmRSS:"), 33040 * 1024);
        assert_eq!(status_bytes(status, "VmHWM:"), 40960 * 1024);
        assert_eq!(status_bytes(status, "VmSwap:"), 0);
    }

    #[test]
    fn only_bridge_processes_count_as_channels() {
        assert!(is_bridge(b"/usr/local/bin/gryonixnexusd\0bridge\0"));
        assert!(!is_bridge(b"/usr/local/bin/gryonixnexusd\0"));
        assert!(!is_bridge(b"sudo\0-n\0/usr/local/bin/gryonixnexusd\0bridge\0"), "sudo is not the bridge");
    }
}
