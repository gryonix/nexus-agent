//! The machine's USB serial adapters, as udev names them under /dev/serial/by-id

use std::path::{Component, Path, PathBuf};

use crate::pb;

/// Where udev keeps the stable names. Overridable for tests only.
const DEFAULT_DIR: &str = "/dev/serial/by-id";

fn directory() -> PathBuf {
    PathBuf::from(
        std::env::var("GRYONIXNEXUSD_SERIAL_DIR").unwrap_or_else(|_| DEFAULT_DIR.to_string()),
    )
}

/// Everything udev currently lists, sorted by path.
pub fn list() -> pb::SerialDeviceList {
    let dir = directory();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return pb::SerialDeviceList {
            devices: Vec::new(),
            directory_present: false,
        };
    };
    let mut devices: Vec<pb::SerialDevice> = entries
        .flatten()
        .map(|entry| describe(&dir, &entry.file_name().to_string_lossy()))
        .collect();
    devices.sort_by(|left, right| left.path.cmp(&right.path));
    pb::SerialDeviceList {
        devices,
        directory_present: true,
    }
}

fn describe(dir: &Path, name: &str) -> pb::SerialDevice {
    let path = dir.join(name);
    let target = std::fs::read_link(&path)
        .map(|link| resolve(dir, &link))
        .unwrap_or_default();
    pb::SerialDevice {
        path: path.to_string_lossy().into_owned(),
        target,
        label: label(name),
    }
}

fn resolve(dir: &Path, link: &Path) -> String {
    if link.is_absolute() {
        return link.to_string_lossy().into_owned();
    }
    let mut parts: Vec<Component> = dir.components().collect();
    for part in link.components() {
        match part {
            Component::ParentDir => {
                if !matches!(parts.last(), Some(Component::RootDir) | None) {
                    parts.pop();
                }
            }
            Component::CurDir => {}
            other => parts.push(other),
        }
    }
    parts
        .into_iter()
        .collect::<PathBuf>()
        .to_string_lossy()
        .into_owned()
}

/// The udev name without its wiring: `usb-ITead_Sonoff_Plus-if00-port0` → `ITead Sonoff Plus`
fn label(name: &str) -> String {
    let mut text = name.strip_prefix("usb-").unwrap_or(name).to_string();
    while let Some(cut) = trailing_wiring(&text) {
        text.truncate(cut);
    }
    text.replace('_', " ").trim().to_string()
}

fn trailing_wiring(text: &str) -> Option<usize> {
    let cut = text.rfind('-')?;
    let tail = &text[cut + 1..];
    let digits = tail
        .strip_prefix("port")
        .or_else(|| tail.strip_prefix("if"))?;
    if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(cut)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests share one process environment
    static ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn fixture(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "gryonixnexusd-serial-{}-{name}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn link(dir: &Path, name: &str, target: &str) {
        std::os::unix::fs::symlink(target, dir.join(name)).unwrap();
    }

    #[test]
    fn a_machine_that_never_saw_a_stick_is_empty_and_says_the_directory_is_gone() {
        let dir = fixture("absent");
        std::fs::remove_dir_all(&dir).unwrap();
        let _env = ENV.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("GRYONIXNEXUSD_SERIAL_DIR", &dir);
        let list = list();
        assert!(list.devices.is_empty());
        assert!(!list.directory_present);
        std::env::remove_var("GRYONIXNEXUSD_SERIAL_DIR");
    }

    #[test]
    fn an_empty_directory_is_no_stick_plugged_in_not_a_machine_without_usb() {
        let dir = fixture("empty");
        let _env = ENV.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("GRYONIXNEXUSD_SERIAL_DIR", &dir);
        let list = list();
        assert!(list.devices.is_empty());
        assert!(list.directory_present);
        std::env::remove_var("GRYONIXNEXUSD_SERIAL_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn each_entry_carries_its_by_id_path_its_current_node_and_a_label() {
        let dir = fixture("entries");
        link(
            &dir,
            "usb-ITead_Sonoff_Zigbee_3.0_USB_Dongle_Plus-if00-port0",
            "../../ttyUSB0",
        );
        link(
            &dir,
            "usb-Silicon_Labs_slae.sh_cc2652rb_stick-if00-port0",
            "../../ttyACM0",
        );
        let _env = ENV.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("GRYONIXNEXUSD_SERIAL_DIR", &dir);
        let list = list();
        assert_eq!(list.devices.len(), 2);
        // Sorted by path: ITead before Silicon_Labs, whatever read_dir said.
        assert!(list.devices[0].path.ends_with("Plus-if00-port0"));
        assert_eq!(
            list.devices[0].label,
            "ITead Sonoff Zigbee 3.0 USB Dongle Plus"
        );
        assert!(list.devices[0].target.ends_with("ttyUSB0"));
        assert!(!list.devices[0].target.contains(".."));
        assert_eq!(list.devices[1].label, "Silicon Labs slae.sh cc2652rb stick");
        assert!(list.devices[1].target.ends_with("ttyACM0"));
        std::env::remove_var("GRYONIXNEXUSD_SERIAL_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_path_keeps_the_wiring_the_label_drops() {
        let dir = fixture("twins");
        link(&dir, "usb-ITead_Sonoff-if00-port0", "../../ttyUSB0");
        link(&dir, "usb-ITead_Sonoff-if00-port1", "../../ttyUSB1");
        let _env = ENV.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("GRYONIXNEXUSD_SERIAL_DIR", &dir);
        let list = list();
        assert_eq!(list.devices.len(), 2);
        assert_ne!(list.devices[0].path, list.devices[1].path);
        assert_eq!(list.devices[0].label, list.devices[1].label);
        std::env::remove_var("GRYONIXNEXUSD_SERIAL_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_name_whose_tail_is_not_wiring_keeps_it() {
        assert_eq!(label("usb-Acme_Stick-port"), "Acme Stick-port");
        assert_eq!(label("usb-Acme_iffy"), "Acme iffy");
        assert_eq!(label("usb-Acme_Stick-if00-port0"), "Acme Stick");
    }

    #[test]
    fn an_absolute_link_target_is_taken_as_written() {
        let dir = fixture("absolute");
        link(&dir, "usb-Acme_Stick-if00-port0", "/dev/ttyUSB7");
        let _env = ENV.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("GRYONIXNEXUSD_SERIAL_DIR", &dir);
        let list = list();
        assert_eq!(list.devices[0].target, "/dev/ttyUSB7");
        std::env::remove_var("GRYONIXNEXUSD_SERIAL_DIR");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
