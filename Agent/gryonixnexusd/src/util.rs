//! Small shared helpers.

use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub fn strip_ansi(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\u{1B}' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            // CSI: parameters/intermediates until a final byte 0x40–0x7E.
            Some('[') => {
                for byte in chars.by_ref() {
                    if ('\u{40}'..='\u{7E}').contains(&byte) {
                        break;
                    }
                }
            }
            // OSC: terminated by BEL or ESC \.
            Some(']') => {
                while let Some(byte) = chars.next() {
                    if byte == '\u{07}' {
                        break;
                    }
                    if byte == '\u{1B}' {
                        if chars.peek() == Some(&'\\') {
                            chars.next();
                        }
                        break;
                    }
                }
            }
            // Any other two-byte escape: both bytes are consumed already.
            _ => {}
        }
    }
    out.split('\n')
        .map(|line| match line.rfind('\r') {
            Some(index) => &line[index + '\r'.len_utf8()..],
            None => line,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn write_file_atomic(path: &std::path::Path, contents: &[u8], mode: u32) -> std::io::Result<()> {
    let staged = stage_file(path, contents, mode)?;
    std::fs::rename(&staged, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&staged);
    })
}

pub fn create_file_atomic_if_absent(path: &std::path::Path, contents: &[u8], mode: u32) -> std::io::Result<bool> {
    let staged = stage_file(path, contents, mode)?;
    let linked = std::fs::hard_link(&staged, path);
    let _ = std::fs::remove_file(&staged);
    match linked {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(err) => Err(err),
    }
}

fn stage_file(path: &std::path::Path, contents: &[u8], mode: u32) -> std::io::Result<std::path::PathBuf> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let staged = path.with_file_name(format!(".{name}.tmp-{}-{}", std::process::id(), COUNTER.fetch_add(1, Ordering::Relaxed)));
    let _ = std::fs::remove_file(&staged);
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&staged)
        .and_then(|mut file| {
            file.write_all(contents)?;
            std::fs::set_permissions(&staged, std::os::unix::fs::PermissionsExt::from_mode(mode))?;
            file.sync_all()
        });
    match written {
        Ok(()) => Ok(staged),
        Err(err) => {
            let _ = std::fs::remove_file(&staged);
            Err(err)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_create_keeps_the_first_file_and_the_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("gnx-util-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("secret");
        assert!(create_file_atomic_if_absent(&path, b"one", 0o600).unwrap());
        assert!(!create_file_atomic_if_absent(&path, b"two", 0o600).unwrap());
        assert_eq!(std::fs::read(&path).unwrap(), b"one");
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_file_atomic(&path, b"three", 0o600).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"three");
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn colour_codes_are_removed_and_the_words_are_kept() {
        assert_eq!(
            strip_ansi("\u{1B}[1;31mERROR\u{1B}[0m  Mailbox data directory does not exist"),
            "ERROR  Mailbox data directory does not exist"
        );
        assert_eq!(strip_ansi("plain text"), "plain text");
    }

    #[test]
    fn an_osc_sequence_and_a_redrawn_progress_line_collapse() {
        assert_eq!(strip_ansi("\u{1B}]0;title\u{07}done"), "done");
        assert_eq!(strip_ansi("\u{1B}]0;title\u{1B}\\done"), "done");
        assert_eq!(strip_ansi("10%\r50%\r100%\nnext"), "100%\nnext");
    }

    #[test]
    fn a_truncated_escape_does_not_eat_the_rest_of_the_output() {
        assert_eq!(strip_ansi("head\u{1B}"), "head");
        assert_eq!(strip_ansi("a\u{1B}[31"), "a");
    }
}

/// The agent's own state directory
pub fn state_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(
        std::env::var("GRYONIXNEXUSD_STATE_DIR").unwrap_or_else(|_| "/var/lib/gryonixnexus/agent".to_string()),
    )
}

/// One process-wide lock for tests that touch the ENVIRONMENT
#[cfg(test)]
pub static STATE_DIR_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
