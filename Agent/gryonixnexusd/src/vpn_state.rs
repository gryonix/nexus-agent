//! Packs and unpacks the VPN's directories to move it between machines.
//!
//! Only `/opt/<name>` directories travel. An import checks every entry of
//! the archive before unpacking and puts a replaced directory back when
//! unpacking fails.

use std::path::{Path, PathBuf};

use hyper::StatusCode;

use crate::api::{connect_error, Codec, Resp};
use crate::pb;

const MAX_ARCHIVE: usize = 16 * 1024 * 1024;
const MAX_DIRECTORIES: usize = 8;
const ROOT_ENV: &str = "GRYONIXNEXUSD_VPN_STATE_ROOT";
const TAR_ENV: &str = "GRYONIXNEXUSD_VPN_STATE_TAR";
/// The panel's sources; the install writes them again
const SKIPPED: &str = "opt/gryonix-vpn-panel/build";
const PREVIOUS_SUFFIX: &str = ".gryonixnexus-previous";

fn root() -> PathBuf {
    PathBuf::from(std::env::var(ROOT_ENV).unwrap_or_else(|_| "/".to_string()))
}

fn tar() -> String {
    std::env::var(TAR_ENV).unwrap_or_else(|_| "tar".to_string())
}

/// `/opt/<name>` with a plain name, else nothing
pub fn checked_directory(text: &str) -> Option<String> {
    let name = text.trim().strip_prefix("/opt/")?.trim_end_matches('/');
    let plain = crate::move_transfer::safe_name(name) && !name.starts_with('.');
    plain.then(|| format!("/opt/{name}"))
}

/// One to eight checked directories, once each
pub fn checked_all(directories: &[String]) -> Result<Vec<String>, String> {
    let mut clean: Vec<String> = Vec::new();
    for text in directories {
        let dir = checked_directory(text).ok_or_else(|| format!("not a VPN directory: {text}"))?;
        if !clean.contains(&dir) {
            clean.push(dir);
        }
    }
    match clean.len() {
        0 => Err("name the VPN's directories".to_string()),
        n if n > MAX_DIRECTORIES => Err(format!("at most {MAX_DIRECTORIES} directories")),
        _ => Ok(clean),
    }
}

/// Whether every archive entry lies inside one of the directories
pub fn entries_inside(listing: &str, directories: &[String]) -> bool {
    listing.lines().map(|line| line.trim_start_matches("./")).filter(|entry| !entry.is_empty()).all(|entry| {
        let escapes = entry.starts_with('/') || entry.split('/').any(|part| part == "..");
        !escapes
            && directories.iter().any(|dir| {
                let relative = dir.trim_start_matches('/');
                entry == relative || entry.starts_with(&format!("{relative}/"))
            })
    })
}

fn relative(dir: &str) -> String {
    dir.trim_start_matches('/').to_string()
}

fn on_disk(dir: &str) -> PathBuf {
    root().join(relative(dir))
}

fn refuse(message: &str) -> Resp {
    connect_error(StatusCode::BAD_REQUEST, "invalid_argument", message)
}

fn failed(message: &str) -> Resp {
    connect_error(StatusCode::UNPROCESSABLE_ENTITY, "failed_precondition", message)
}

fn internal(message: &str) -> Resp {
    connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", message)
}

fn encode<T: prost::Message + serde::Serialize>(codec: Codec, message: &T) -> Resp {
    codec.encode(message).unwrap_or_else(|err| internal(&err.to_string()))
}

pub async fn export(codec: Codec, req: pb::ExportVpnStateRequest) -> Resp {
    let directories = match checked_all(&req.directories) {
        Ok(directories) => directories,
        Err(why) => return refuse(&why),
    };
    let present: Vec<String> = directories.into_iter().filter(|dir| on_disk(dir).is_dir()).collect();
    if present.is_empty() {
        return failed("this machine has no VPN to move");
    }
    match pack(&present).await {
        Ok(archive) if archive.len() <= MAX_ARCHIVE => encode(codec, &pb::VpnState { archive, directories: present }),
        Ok(_) => failed("the VPN's directories are too large to move this way"),
        Err(why) => internal(&why),
    }
}

async fn pack(directories: &[String]) -> Result<Vec<u8>, String> {
    let output = tokio::process::Command::new(tar())
        .arg("-czf")
        .arg("-")
        .arg("-C")
        .arg(root())
        .arg(format!("--exclude={SKIPPED}"))
        .arg("--")
        .args(directories.iter().map(|dir| relative(dir)))
        .output()
        .await
        .map_err(|err| format!("could not run tar: {err}"))?;
    if !output.status.success() {
        return Err(format!("packing the VPN failed: {}", String::from_utf8_lossy(&output.stderr).trim()));
    }
    Ok(output.stdout)
}

pub async fn import(codec: Codec, req: pb::ImportVpnStateRequest) -> Resp {
    let directories = match checked_all(&req.directories) {
        Ok(directories) => directories,
        Err(why) => return refuse(&why),
    };
    if req.archive.is_empty() || req.archive.len() > MAX_ARCHIVE {
        return refuse("the VPN archive is empty or too large");
    }
    if !req.replace {
        if let Some(taken) = directories.iter().find(|dir| holds_something(&on_disk(dir))) {
            return failed(&format!("{taken} already exists on this machine"));
        }
    }
    match unpack_checked(&req.archive, &directories, req.replace).await {
        Ok(()) => encode(codec, &pb::ImportVpnStateResponse { directories }),
        Err(why) => failed(&why),
    }
}

fn holds_something(path: &Path) -> bool {
    std::fs::read_dir(path).map(|mut entries| entries.next().is_some()).unwrap_or(false)
}

async fn unpack_checked(archive: &[u8], directories: &[String], replace: bool) -> Result<(), String> {
    let file = crate::util::state_dir().join(format!("vpn-state-{}.tar.gz", std::process::id()));
    std::fs::create_dir_all(crate::util::state_dir()).map_err(|err| err.to_string())?;
    std::fs::write(&file, archive).map_err(|err| format!("could not keep the archive: {err}"))?;
    let result = check_then_unpack(&file, directories, replace).await;
    let _ = std::fs::remove_file(&file);
    result
}

async fn check_then_unpack(file: &Path, directories: &[String], replace: bool) -> Result<(), String> {
    let listing = run_tar(&["-tzf".as_ref(), file.as_os_str()]).await?;
    if !entries_inside(&listing, directories) {
        return Err("the archive holds files outside the VPN's directories".to_string());
    }
    if replace {
        release_containers(directories).await?;
    }
    let moved = if replace { set_aside(directories)? } else { Vec::new() };
    let unpacked = run_tar(&["-xzf".as_ref(), file.as_os_str(), "-C".as_ref(), root().as_os_str()]).await;
    match unpacked {
        Ok(_) => {
            for dir in &moved {
                keep_built_sources(dir);
                let _ = std::fs::remove_dir_all(previous(dir));
            }
            Ok(())
        }
        Err(why) => {
            put_back(&moved);
            Err(why)
        }
    }
}

/// Removes containers holding the directories about to be swapped
async fn release_containers(directories: &[String]) -> Result<(), String> {
    let Some(listing) = docker(&["ps", "-aq", "--no-trunc"]).await else { return Ok(()) };
    let ids: Vec<&str> = listing.split_whitespace().collect();
    if ids.is_empty() {
        return Ok(());
    }
    let mut args = vec!["inspect", "--format", "{{.Id}} {{range .Mounts}}{{.Source}} {{end}}"];
    args.extend(&ids);
    let Some(mounts) = docker(&args).await else { return Ok(()) };
    for id in holders(&mounts, directories) {
        docker(&["rm", "-f", &id]).await.ok_or_else(|| format!("could not remove container {id}"))?;
    }
    Ok(())
}

/// Containers whose mounts sit inside the directories
pub fn holders(inspect: &str, directories: &[String]) -> Vec<String> {
    let roots: Vec<PathBuf> = directories.iter().map(|dir| on_disk(dir)).collect();
    inspect
        .lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            let id = words.next()?;
            words.any(|source| roots.iter().any(|root| Path::new(source).starts_with(root))).then(|| id.to_string())
        })
        .collect()
}

async fn docker(args: &[&str]) -> Option<String> {
    let output = tokio::process::Command::new(crate::install::execute::docker_bin()).args(args).output().await.ok()?;
    output.status.success().then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Brings back the skipped sources; the image stays built
fn keep_built_sources(dir: &str) {
    let Some(inside) = SKIPPED.strip_prefix(&format!("{}/", relative(dir))) else { return };
    let (kept, unpacked) = (previous(dir).join(inside), on_disk(dir).join(inside));
    if kept.is_dir() && !unpacked.exists() {
        let _ = std::fs::rename(kept, unpacked);
    }
}

fn previous(dir: &str) -> PathBuf {
    PathBuf::from(format!("{}{PREVIOUS_SUFFIX}", on_disk(dir).display()))
}

/// Moves existing directories aside; answers which moved
fn set_aside(directories: &[String]) -> Result<Vec<String>, String> {
    let mut moved = Vec::new();
    for dir in directories.iter().filter(|dir| on_disk(dir).exists()) {
        let _ = std::fs::remove_dir_all(previous(dir));
        if let Err(err) = std::fs::rename(on_disk(dir), previous(dir)) {
            put_back(&moved);
            return Err(format!("could not set {dir} aside: {err}"));
        }
        moved.push(dir.clone());
    }
    Ok(moved)
}

fn put_back(moved: &[String]) {
    for dir in moved {
        let _ = std::fs::remove_dir_all(on_disk(dir));
        let _ = std::fs::rename(previous(dir), on_disk(dir));
    }
}

async fn run_tar(args: &[&std::ffi::OsStr]) -> Result<String, String> {
    let output = tokio::process::Command::new(tar())
        .args(args)
        .output()
        .await
        .map_err(|err| format!("could not run tar: {err}"))?;
    if !output.status.success() {
        return Err(format!("tar failed: {}", String::from_utf8_lossy(&output.stderr).trim()));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dirs(list: &[&str]) -> Vec<String> {
        list.iter().map(|dir| dir.to_string()).collect()
    }

    #[test]
    fn only_plain_opt_directories_travel() {
        assert_eq!(checked_directory("/opt/awgvpn/"), Some("/opt/awgvpn".to_string()));
        for bad in ["/etc/passwd", "/opt/", "/opt/../etc", "/opt/a/b", "/opt/.hidden", "opt/xray", "/opt/a b"] {
            assert_eq!(checked_directory(bad), None, "{bad}");
        }
        assert!(checked_all(&[]).is_err());
        assert_eq!(checked_all(&dirs(&["/opt/xray", "/opt/xray/"])).unwrap(), dirs(&["/opt/xray"]));
    }

    #[test]
    fn containers_mounting_a_swapped_directory_are_found() {
        let _guard = crate::util::STATE_DIR_ENV_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        std::env::remove_var(ROOT_ENV);
        let inspect = "aaa /opt/xray/config /etc/localtime \nbbb /opt/mailcow-dockerized \nccc \nddd /opt/gryonix-vpn-panel/data /opt/xray \n";
        let found = holders(inspect, &dirs(&["/opt/xray", "/opt/gryonix-vpn-panel"]));
        assert_eq!(found, vec!["aaa".to_string(), "ddd".to_string()]);
        assert!(holders(inspect, &dirs(&["/opt/xr"])).is_empty(), "a name prefix is not a parent");
    }

    #[test]
    fn entries_outside_the_directories_are_caught() {
        let allowed = dirs(&["/opt/xray", "/opt/gryonix-vpn-panel"]);
        assert!(entries_inside("opt/xray/\nopt/xray/config/config.json\n./opt/gryonix-vpn-panel/.env\n", &allowed));
        assert!(!entries_inside("opt/xray/../../srv/escape\n", &allowed));
        assert!(!entries_inside("/srv/escape\n", &allowed));
        assert!(!entries_inside("opt/xray-evil/x\n", &allowed));
        assert!(!entries_inside("opt/awgvpn/data\n", &allowed));
    }

    struct Scratch {
        root: PathBuf,
        _guard: std::sync::MutexGuard<'static, ()>,
    }

    impl Scratch {
        fn new(tag: &str) -> Self {
            let guard = crate::util::STATE_DIR_ENV_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
            let root = std::env::temp_dir().join(format!("vpn-state-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(&root).unwrap();
            std::env::set_var(ROOT_ENV, &root);
            std::env::set_var("GRYONIXNEXUSD_STATE_DIR", root.join("state"));
            Scratch { root, _guard: guard }
        }

        fn write(&self, path: &str, text: &str) {
            let file = self.root.join(path);
            std::fs::create_dir_all(file.parent().unwrap()).unwrap();
            std::fs::write(file, text).unwrap();
        }

        fn read(&self, path: &str) -> Option<String> {
            std::fs::read_to_string(self.root.join(path)).ok()
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            std::env::remove_var(ROOT_ENV);
            std::env::remove_var("GRYONIXNEXUSD_STATE_DIR");
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[tokio::test]
    async fn keys_and_devices_survive_a_pack_and_unpack() {
        let scratch = Scratch::new("roundtrip");
        scratch.write("opt/gryonix-vpn-panel/data/clients.json", "[\"phone\"]");
        scratch.write("opt/gryonix-vpn-panel/build/app.py", "sources");
        scratch.write("opt/xray/config/config.json", "{\"id\":\"U\"}");
        let wanted = dirs(&["/opt/gryonix-vpn-panel", "/opt/xray", "/opt/awgvpn"]);
        let archive = pack(&dirs(&["/opt/gryonix-vpn-panel", "/opt/xray"])).await.unwrap();
        std::fs::remove_dir_all(scratch.root.join("opt")).unwrap();
        unpack_checked(&archive, &wanted, false).await.unwrap();
        assert_eq!(scratch.read("opt/gryonix-vpn-panel/data/clients.json").as_deref(), Some("[\"phone\"]"));
        assert_eq!(scratch.read("opt/xray/config/config.json").as_deref(), Some("{\"id\":\"U\"}"));
        assert_eq!(scratch.read("opt/gryonix-vpn-panel/build/app.py"), None, "sources are written by the install");
    }

    #[tokio::test]
    async fn an_archive_naming_other_directories_is_refused() {
        let scratch = Scratch::new("outside");
        scratch.write("opt/awgvpn/.env", "K=1");
        let archive = pack(&dirs(&["/opt/awgvpn"])).await.unwrap();
        std::fs::remove_dir_all(scratch.root.join("opt")).unwrap();
        assert!(unpack_checked(&archive, &dirs(&["/opt/xray"]), false).await.is_err());
        assert_eq!(scratch.read("opt/awgvpn/.env"), None);
    }

    #[tokio::test]
    async fn a_replaced_directory_is_swapped_and_its_old_copy_cleared() {
        let scratch = Scratch::new("replace");
        scratch.write("opt/xray/config/config.json", "new");
        let archive = pack(&dirs(&["/opt/xray"])).await.unwrap();
        scratch.write("opt/xray/config/config.json", "old");
        scratch.write("opt/xray/stale", "x");
        unpack_checked(&archive, &dirs(&["/opt/xray"]), true).await.unwrap();
        assert_eq!(scratch.read("opt/xray/config/config.json").as_deref(), Some("new"));
        assert_eq!(scratch.read("opt/xray/stale"), None);
        assert!(!scratch.root.join("opt/xray.gryonixnexus-previous").exists());
    }

    #[tokio::test]
    async fn a_replaced_panel_keeps_its_built_sources() {
        let scratch = Scratch::new("built");
        scratch.write("opt/gryonix-vpn-panel/data/clients.json", "new");
        let archive = pack(&dirs(&["/opt/gryonix-vpn-panel"])).await.unwrap();
        scratch.write("opt/gryonix-vpn-panel/data/clients.json", "old");
        scratch.write("opt/gryonix-vpn-panel/build/.built-digest", "abc");
        unpack_checked(&archive, &dirs(&["/opt/gryonix-vpn-panel"]), true).await.unwrap();
        assert_eq!(scratch.read("opt/gryonix-vpn-panel/data/clients.json").as_deref(), Some("new"));
        assert_eq!(scratch.read("opt/gryonix-vpn-panel/build/.built-digest").as_deref(), Some("abc"));
        assert!(!scratch.root.join("opt/gryonix-vpn-panel.gryonixnexus-previous").exists());
    }

    #[tokio::test]
    async fn a_broken_archive_puts_the_old_directory_back() {
        let scratch = Scratch::new("broken");
        scratch.write("opt/xray/config/config.json", "old");
        assert!(unpack_checked(b"not a tar", &dirs(&["/opt/xray"]), true).await.is_err());
        assert_eq!(scratch.read("opt/xray/config/config.json").as_deref(), Some("old"));
    }
}
