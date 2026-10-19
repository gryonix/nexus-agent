//! gryonixnexusd — control-plane agent for a single gryonixNexus deployment

mod agent_removal;
mod agent_update;
mod api;
mod backup;
mod backup_drive;
mod drive_watch;
mod container_backup;
mod container_backup_run;
mod container_ops;
mod container_removal;
mod container_schedule;
mod container_update;
mod containers;
mod cert_watch;
mod control;
mod discover;
mod dkim;
mod history;
mod install;
mod jobs;
mod language;
mod lockdown;
mod mailbox;
mod security;
/// Dynamic DNS — the host keeps its own A records current
mod ddns;
mod device_keys;
mod mesh;
mod metrics;
mod models;
mod mods;
mod move_run;
mod move_transfer;
mod move_upstream;
mod health_watch;
mod live;
mod live_tunnel;
mod notify;
mod notify_send;
mod panel_broker;
mod pre_restore;
mod ssh_watch;
mod storage_array;
mod storage_cache;
mod storage_task;
mod system_ctl;
mod restore;
mod serial;
mod setup_guard;
mod trusted_sources;
mod state;
mod uninstall;
mod vpn_clients;
mod vpn_dns;
mod vpn_dns_priority;
mod vpn_dns_relay;
mod vpn_state;
mod update;
mod util;
/// The deployment's own service passwords, sealed at rest
mod vault;
mod vaultwarden_2fa;
mod wake;

/// Types generated from ../proto/gryonixnexusd/v1/gryonixnexusd.proto at build time.
pub mod pb {
    include!(concat!(env!("OUT_DIR"), "/gryonixnexusd.v1.rs"));
}

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::{Arc, Mutex};

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;

const SOCKET_PATH: &str = "/run/gryonixnexusd.sock";
const STATE_DIR: &str = "/var/lib/gryonixnexus/agent";
const PAIRING_CODE_TTL_SECS: i64 = 600;

const COMMANDS: [&str; 5] = ["bridge", "version", "--version", "-V", "pair-code"];

fn ensure_socket_free(path: &str) -> std::io::Result<()> {
    if std::os::unix::net::UnixStream::connect(path).is_ok() {
        return Err(std::io::Error::new(std::io::ErrorKind::AddrInUse, format!("another agent is serving {path}")));
    }
    Ok(())
}

fn bind_socket(path: &str) -> std::io::Result<tokio::net::UnixListener> {
    ensure_socket_free(path)?;
    let _ = std::fs::remove_file(path);
    let listener = tokio::net::UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(listener)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let socket_path = std::env::var("GRYONIXNEXUSD_SOCKET").unwrap_or_else(|_| SOCKET_PATH.to_string());
    let state_dir = std::env::var("GRYONIXNEXUSD_STATE_DIR").unwrap_or_else(|_| STATE_DIR.to_string());
    let command = std::env::args().nth(1);
    if let Some(unknown) = command.as_deref().filter(|c| !COMMANDS.contains(c)) {
        eprintln!("unknown command {unknown:?}; known: {}", COMMANDS.join(", "));
        std::process::exit(2);
    }

    if !matches!(command.as_deref(), Some("bridge") | Some("version") | Some("--version") | Some("-V")) {
        agent_update::guard_startup();
    }

    if command.as_deref() == Some("bridge") {
        return run_bridge(&socket_path).await;
    }

    if matches!(command.as_deref(), Some("version") | Some("--version") | Some("-V")) {
        println!("gryonixnexusd {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    if command.is_none() {
        ensure_socket_free(&socket_path)?;
    }
    let store = open_state(&state_dir)?;

    if command.as_deref() == Some("pair-code") {
        let code = store.issue_pairing_code(PAIRING_CODE_TTL_SECS)?;
        println!("Pairing code (valid 10 minutes): {}-{}", &code[..4], &code[4..]);
        return Ok(());
    }

    let store = Arc::new(Mutex::new(store));
    spawn_background_work(&store);

    let listener = bind_socket(&socket_path)?;
    tracing::info!(socket = %socket_path, "gryonixnexusd listening");
    serve_forever(listener, store).await
}

fn open_state(state_dir: &str) -> anyhow::Result<state::Store> {
    std::fs::create_dir_all(state_dir)?;
    std::fs::set_permissions(state_dir, std::fs::Permissions::from_mode(0o700))?;
    let store = state::Store::open(Path::new(state_dir).join("state.db"))?;
    install::journal::sweep_abandoned();
    jobs::sweep_abandoned();
    Ok(store)
}

/// Starts the timers and watchers that run beside the API
fn spawn_background_work(store: &Arc<Mutex<state::Store>>) {
    container_schedule::spawn(store.clone());
    notify::spawn(store.clone());
    wake::spawn();
    device_keys::spawn();
    panel_broker::spawn();
    vpn_dns::spawn();
    setup_guard::spawn();
    tokio::spawn(async {
        loop {
            match security::keep_trusted_sources().await {
                Ok(0) => {}
                Ok(changed) => tracing::info!(changed, "kept the pair and the VPN trusted"),
                Err(err) => tracing::warn!(%err, "could not keep the trusted sources"),
            }
            tokio::time::sleep(std::time::Duration::from_secs(600)).await;
        }
    });
    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        loop {
            if let Err(err) = install::execute::reconcile_home_network().await {
                tracing::warn!(%err, "home network access not in step");
            }
            tokio::time::sleep(std::time::Duration::from_secs(600)).await;
        }
    });
    agent_update::reconcile_on_startup();
    tokio::task::spawn_blocking(backup_drive::upgrade_fstab);
    tokio::task::spawn_blocking(install::host::backup_ctl_store::refresh_on_startup);
    agent_update::spawn();
    tokio::spawn(async {
        loop {
            keep_host_tools().await;
            tokio::time::sleep(std::time::Duration::from_secs(600)).await;
        }
    });
}

async fn serve_forever(listener: tokio::net::UnixListener, store: Arc<Mutex<state::Store>>) -> anyhow::Result<()> {
    let allowed_uid = unsafe { libc::geteuid() };
    loop {
        let (stream, _addr) = listener.accept().await?;
        match stream.peer_cred() {
            Ok(cred) if cred.uid() == allowed_uid => {}
            Ok(cred) => {
                tracing::warn!(uid = cred.uid(), "rejected connection from an unexpected local uid");
                continue;
            }
            Err(err) => {
                tracing::warn!(?err, "could not read the peer's credentials — rejecting the connection");
                continue;
            }
        }
        let io = TokioIo::new(stream);
        let store = store.clone();
        tokio::spawn(async move {
            let service = service_fn(move |req| api::serve(req, store.clone()));
            if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                tracing::warn!(?err, "connection error");
            }
        });
    }
}

async fn run_bridge(socket_path: &str) -> anyhow::Result<()> {
    bridge(socket_path, tokio::io::stdin(), tokio::io::stdout()).await
}

async fn bridge<R, W>(socket_path: &str, mut input: R, mut output: W) -> anyhow::Result<()>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;

    let stream = tokio::net::UnixStream::connect(socket_path).await?;
    let (mut socket_read, mut socket_write) = stream.into_split();

    tokio::spawn(async move {
        let _ = tokio::io::copy(&mut input, &mut socket_write).await;
        socket_write.forget();
    });

    tokio::io::copy(&mut socket_read, &mut output).await?;
    output.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn stdin_reaching_eof_does_not_close_the_agent_side_of_the_socket() {
        let path = std::env::temp_dir().join(format!("gryonixnexusd-bridge-test-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let listener = tokio::net::UnixListener::bind(&path).unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 4];
            stream.read_exact(&mut request).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            let mut probe = [0u8; 1];
            let peer_hung_up = matches!(stream.try_read(&mut probe), Ok(0));
            stream
                .write_all(if peer_hung_up { b"GONE" } else { b"HERE" })
                .await
                .unwrap();
        });

        let mut reply = Vec::new();
        super::bridge(path.to_str().unwrap(), std::io::Cursor::new(b"PING".to_vec()), &mut reply)
            .await
            .unwrap();
        server.await.unwrap();
        let _ = std::fs::remove_file(&path);

        assert_eq!(
            String::from_utf8_lossy(&reply),
            "HERE",
            "the agent saw the bridge hang up while it was still working"
        );
    }

    #[tokio::test]
    async fn the_socket_is_locked_to_owner_only_regardless_of_umask() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!("gryonixnexusd-mode-test-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let wide_umask = unsafe { libc::umask(0o000) };
        let listener = super::bind_socket(path.to_str().unwrap()).unwrap();
        unsafe {
            libc::umask(wide_umask);
        }
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        drop(listener);
        let _ = std::fs::remove_file(&path);
        assert_eq!(mode, 0o700, "the socket must be owner-only no matter the process umask");
    }

    #[tokio::test]
    async fn a_socket_another_agent_answers_on_is_left_alone() {
        let path = std::env::temp_dir().join(format!("gryonixnexusd-busy-test-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let running = super::bind_socket(path.to_str().unwrap()).unwrap();
        let second = super::bind_socket(path.to_str().unwrap());
        let still_answers = std::os::unix::net::UnixStream::connect(&path).is_ok();
        drop(running);
        let _ = std::fs::remove_file(&path);
        assert_eq!(second.err().map(|e| e.kind()), Some(std::io::ErrorKind::AddrInUse));
        assert!(still_answers, "the running agent's socket must survive a second start");
    }

    #[test]
    fn cargo_lock_records_the_crate_version_the_manifest_declares() {
        let lock = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.lock"))
            .expect("Cargo.lock sits beside Cargo.toml");
        let locked = lock
            .split("[[package]]")
            .find(|block| block.contains("name = \"gryonixnexusd\""))
            .and_then(|block| {
                block
                    .lines()
                    .find_map(|line| line.trim().strip_prefix("version = "))
            })
            .map(|value| value.trim().trim_matches('"').to_string())
            .expect("Cargo.lock has an entry for this crate");
        assert_eq!(
            locked,
            env!("CARGO_PKG_VERSION"),
            "Cargo.lock says {locked}, Cargo.toml says {} — run `cargo update -p gryonixnexusd`",
            env!("CARGO_PKG_VERSION")
        );
    }
}

async fn keep_host_tools() {
    cert_watch::retry_missing().await;
    match system_ctl::install_if_needed() {
        Ok(true) => tracing::info!("wrote the system updater"),
        Ok(false) => {}
        Err(err) => tracing::warn!(%err, "could not write the system updater"),
    }
    match install::execute::add_host_grants_if_missing().await {
        Ok(true) => tracing::info!("added host permissions to the sudoers whitelist"),
        Ok(false) => {}
        Err(err) => tracing::warn!(%err, "could not add host permissions"),
    }
    match install::relay_routes::refresh_script() {
        Ok(true) => tracing::info!("refreshed the relay route sync"),
        Ok(false) => {}
        Err(err) => tracing::warn!(%err, "could not refresh the relay route sync"),
    }
    match install::host::ddns::refresh_script() {
        Ok(true) => tracing::info!("refreshed the dynamic DNS updater"),
        Ok(false) => {}
        Err(err) => tracing::warn!(%err, "could not refresh the dynamic DNS updater"),
    }
    match install::mail::mailcow::refresh_dkim_dump_script() {
        Ok(true) => tracing::info!("refreshed the mailcow DKIM wrapper"),
        Ok(false) => {}
        Err(err) => tracing::warn!(%err, "could not refresh the mailcow DKIM wrapper"),
    }
    match install::execute::refresh_portal_split_sites().await {
        Ok(true) => tracing::info!("rebuilt the mail sites: calendars and contacts sync without the VPN"),
        Ok(false) => {}
        Err(err) => tracing::warn!(%err, "could not rebuild the webmail sites"),
    }
    match install::execute::refresh_mail_autoconfig_site().await {
        Ok(true) => tracing::info!("mail apps can now configure themselves"),
        Ok(false) => {}
        Err(err) => tracing::warn!(%err, "could not add the mail autoconfig site"),
    }
    match lockdown::refresh_guard().await {
        Ok(true) => tracing::info!("refreshed the admin lockdown"),
        Ok(false) => {}
        Err(err) => tracing::warn!(%err, "could not refresh the admin lockdown"),
    }
    match install::host::update_ctl::refresh_current_check() {
        Ok(true) => tracing::info!("scheduled updates skip services with nothing new"),
        Ok(false) => {}
        Err(err) => tracing::warn!(%err, "could not refresh the update wrapper"),
    }
    match install::host::uninstall::refresh_image_reclaim() {
        Ok(true) => tracing::info!("removals now reclaim their images"),
        Ok(false) => {}
        Err(err) => tracing::warn!(%err, "could not refresh the removal wrapper"),
    }
    match install::firewall_base::refresh_home_masquerade().await {
        Ok(true) => tracing::info!("the host reaches its own names through the tunnel"),
        Ok(false) => {}
        Err(err) => tracing::warn!(%err, "could not refresh the home firewall"),
    }
}
