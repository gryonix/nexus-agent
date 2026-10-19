//! The provider keys the gateway uses, rendered from the agent's own vault

use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};

use crate::pb;

/// One model provider the gateway can hold a key for.
pub struct Provider {
    /// Second half of the vault entry's `service_secret` (`litellm/openai`).
    pub id: &'static str,
    pub environment_key: &'static str,
}

/// In the same order as `LLMProvider.all` on the Swift side
pub const PROVIDERS: &[Provider] = &[
    Provider { id: "openai", environment_key: "OPENAI_API_KEY" },
    Provider { id: "anthropic", environment_key: "ANTHROPIC_API_KEY" },
    Provider { id: "deepseek", environment_key: "DEEPSEEK_API_KEY" },
    Provider { id: "gemini", environment_key: "GEMINI_API_KEY" },
    Provider { id: "groq", environment_key: "GROQ_API_KEY" },
    Provider { id: "mistral", environment_key: "MISTRAL_API_KEY" },
    Provider { id: "openrouter", environment_key: "OPENROUTER_API_KEY" },
    Provider { id: "xai", environment_key: "XAI_API_KEY" },
];

/// The catalog id whose secrets this module renders.
pub const SERVICE_ID: &str = "litellm";
/// Beside the backup passphrase, and root-only for the same reason
#[allow(dead_code)]
pub const SHARED_CONFIG_DIR: &str = "/etc/gryonixnexus";
pub const KEYS_ENV_PATH: &str = "/etc/gryonixnexus/litellm-keys.env";

/// The container restarted when the file changes.
pub const CONTAINER: &str = "litellm";

fn keys_env_path() -> String {
    std::env::var("GRYONIXNEXUSD_LLM_KEYS_PATH").unwrap_or_else(|_| KEYS_ENV_PATH.to_string())
}

fn docker_bin() -> String {
    std::env::var("GRYONIXNEXUSD_INSTALL_DOCKER_BIN").unwrap_or_else(|_| "docker".to_string())
}

pub fn provider(service_secret: &str) -> Option<&'static Provider> {
    let (service, id) = service_secret.split_once('/')?;
    if service != SERVICE_ID {
        return None;
    }
    PROVIDERS.iter().find(|p| p.id == id)
}

/// The secret a vault entry carries
fn secret_of(entry: &pb::VaultEntry) -> &str {
    if !entry.token.trim().is_empty() {
        entry.token.trim()
    } else {
        entry.password.trim()
    }
}

fn is_writable_value(value: &str) -> bool {
    !value.is_empty() && !value.chars().any(|c| c.is_control())
}

/// The whole file, from what the vault holds
pub fn render(entries: &[pb::VaultEntry]) -> String {
    let mut rows: Vec<(&str, &str)> = Vec::new();
    for entry in entries {
        if entry.deleted {
            continue;
        }
        let Some(provider) = provider(&entry.service_secret) else { continue };
        let value = secret_of(entry);
        if !is_writable_value(value) {
            continue;
        }
        rows.push((provider.environment_key, value));
    }
    rows.sort_by(|a, b| a.0.cmp(b.0));
    rows.dedup_by(|a, b| a.0 == b.0);
    let mut out = String::new();
    for (key, value) in rows {
        out.push_str(key);
        out.push('=');
        out.push_str(value);
        out.push('\n');
    }
    out
}

pub fn write_if_changed(body: &str) -> Result<bool> {
    let path_string = keys_env_path();
    let path = Path::new(&path_string);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    if let Ok(existing) = fs::read_to_string(path) {
        if existing == body {
            return Ok(false);
        }
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("writing {}", path.display()))?;
    file.write_all(body.as_bytes())?;
    file.sync_all()?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(true)
}

fn compose_file_of(container: &str) -> Option<String> {
    let out = Command::new(docker_bin())
        .args([
            "inspect",
            "-f",
            "{{index .Config.Labels \"com.docker.compose.project.config_files\"}}",
            container,
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .split(',')
        .next()
        .map(str::to_string)
        .filter(|file| !file.is_empty() && file != "<no value>")
}

/// Puts the newly rendered file INTO the running gateway
pub fn restart_gateway() -> bool {
    if let Some(file) = compose_file_of(CONTAINER) {
        let recreated = Command::new(docker_bin())
            .args([
                "compose",
                "-p",
                crate::install::litellm::COMPOSE_PROJECT,
                "-f",
                &file,
                "up",
                "-d",
                "--force-recreate",
                CONTAINER,
            ])
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false);
        if recreated {
            return true;
        }
    }
    Command::new(docker_bin())
        .args(["restart", CONTAINER])
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

pub fn reconcile(entries: &[pb::VaultEntry]) -> Result<bool> {
    let body = render(entries);
    if body.is_empty() && !Path::new(&keys_env_path()).exists() {
        return Ok(false);
    }
    let changed = write_if_changed(&body)?;
    if changed {
        restart_gateway();
    }
    Ok(changed)
}

pub fn ensure_gateway_key(path: &Path) -> Result<String> {
    ensure_shared_secret(path, "sk-")
}

pub fn ensure_shared_secret(path: &Path, prefix: &str) -> Result<String> {
    if let Ok(existing) = fs::read_to_string(path) {
        let trimmed = existing.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(trimmed);
        }
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    let mut bytes = [0u8; 24];
    std::io::Read::read_exact(&mut fs::File::open("/dev/urandom")?, &mut bytes)
        .context("reading /dev/urandom")?;
    let key = format!("{prefix}{}", bytes.iter().map(|b| format!("{b:02x}")).collect::<String>());
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("writing {}", path.display()))?;
    file.write_all(format!("{key}\n").as_bytes())?;
    file.sync_all()?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(key)
}

pub fn set_env_value(path: &Path, key: &str, value: &str) -> Result<()> {
    let existing = fs::read_to_string(path).unwrap_or_default();
    let mut lines: Vec<String> = Vec::new();
    let mut replaced = false;
    for line in existing.lines() {
        if line.starts_with(&format!("{key}=")) {
            lines.push(format!("{key}={value}"));
            replaced = true;
        } else {
            lines.push(line.to_string());
        }
    }
    if !replaced {
        lines.push(format!("{key}={value}"));
    }
    let mut body = lines.join("\n");
    body.push('\n');
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("writing {}", path.display()))?;
    file.write_all(body.as_bytes())?;
    file.sync_all()?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

/// Creates the provider-keys file EMPTY when it is missing
pub fn ensure_keys_file(path: &Path) -> Result<()> {
    if path.exists() {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    static ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        ENV.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    use super::*;

    fn entry(secret: &str, token: &str) -> pb::VaultEntry {
        pb::VaultEntry {
            id: format!("single|{secret}"),
            service_secret: secret.to_string(),
            token: token.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn the_gateway_key_is_minted_once_and_never_rotated() {
        let dir = std::env::temp_dir().join(format!("gryonix-gwkey-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("llm-gateway.key");
        let _ = std::fs::remove_file(&path);

        let first = ensure_gateway_key(&path).unwrap();
        assert!(first.starts_with("sk-"), "got: {first}");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(ensure_gateway_key(&path).unwrap(), first);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn setting_a_variable_twice_leaves_one_line_for_it() {
        let dir = std::env::temp_dir().join(format!("gryonix-setenv-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(".env");
        std::fs::write(&path, "OTHER=1\n").unwrap();

        set_env_value(&path, "LLM_GATEWAY_KEY", "sk-one").unwrap();
        set_env_value(&path, "LLM_GATEWAY_KEY", "sk-two").unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        assert_eq!(body, "OTHER=1\nLLM_GATEWAY_KEY=sk-two\n", "got: {body:?}");
        assert_eq!(body.matches("LLM_GATEWAY_KEY=").count(), 1);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_known_provider_becomes_its_own_variable() {
        let body = render(&[entry("litellm/openai", "sk-abc")]);
        assert_eq!(body, "OPENAI_API_KEY=sk-abc\n");
    }

    #[test]
    fn anything_outside_the_allowlist_is_ignored_rather_than_written() {
        let body = render(&[
            entry("litellm/not-a-provider", "x"),
            entry("otherservice/openai", "x"),
            // An ordinary account row: no service_secret at all.
            pb::VaultEntry { id: "single|Vaultwarden".into(), password: "hunter2".into(), ..Default::default() },
        ]);
        assert_eq!(body, "");
    }

    #[test]
    fn a_value_that_could_forge_a_second_variable_is_refused() {
        let body = render(&[entry("litellm/openai", "sk-abc\nADMIN=1")]);
        assert_eq!(body, "", "a control character was written into the env file");
    }

    #[test]
    fn a_tombstone_takes_its_key_out() {
        let mut gone = entry("litellm/openai", "sk-abc");
        gone.deleted = true;
        assert_eq!(render(&[gone]), "");
    }

    #[test]
    fn the_password_field_is_read_when_the_token_is_empty() {
        let mut row = entry("litellm/anthropic", "");
        row.password = "sk-ant".into();
        assert_eq!(render(&[row]), "ANTHROPIC_API_KEY=sk-ant\n");
    }

    #[test]
    fn the_same_vault_renders_the_same_bytes_whatever_the_order() {
        let a = render(&[entry("litellm/openai", "one"), entry("litellm/groq", "two")]);
        let b = render(&[entry("litellm/groq", "two"), entry("litellm/openai", "one")]);
        assert_eq!(a, b);
        assert_eq!(a, "GROQ_API_KEY=two\nOPENAI_API_KEY=one\n");
    }

    #[test]
    fn the_file_is_written_0600_and_only_when_it_changed() {
        let _env = env_guard();
        let dir = std::env::temp_dir().join(format!("gryonix-llmkeys-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("litellm-keys.env");
        // SAFETY: single-threaded test, and the seam exists for exactly this.
        unsafe { std::env::set_var("GRYONIXNEXUSD_LLM_KEYS_PATH", &path) };

        assert!(write_if_changed("OPENAI_API_KEY=one\n").unwrap());
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the provider keys are readable by somebody else");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "OPENAI_API_KEY=one\n");

        assert!(!write_if_changed("OPENAI_API_KEY=one\n").unwrap(), "an unchanged file was rewritten");
        assert!(write_if_changed("OPENAI_API_KEY=two\n").unwrap());

        unsafe { std::env::remove_var("GRYONIXNEXUSD_LLM_KEYS_PATH") };
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_vault_with_no_provider_keys_creates_no_file() {
        let _env = env_guard();
        let dir = std::env::temp_dir().join(format!("gryonix-llmkeys-none-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("litellm-keys.env");
        unsafe { std::env::set_var("GRYONIXNEXUSD_LLM_KEYS_PATH", &path) };

        let written = reconcile(&[pb::VaultEntry {
            id: "single|Vaultwarden".into(),
            password: "hunter2".into(),
            ..Default::default()
        }])
        .unwrap();
        assert!(!written);
        assert!(!path.exists(), "an empty secret file was created on a host with no gateway");

        unsafe { std::env::remove_var("GRYONIXNEXUSD_LLM_KEYS_PATH") };
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_gateway_is_recreated_from_its_compose_file_not_merely_restarted() {
        let _env = env_guard();
        let dir = std::env::temp_dir().join(format!("gryonix-llmkeys-recreate-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let argv = dir.join("argv");
        let stub = dir.join("docker-stub");
        std::fs::write(
            &stub,
            format!(
                "#!/bin/sh\nif [ \"$1\" = inspect ]; then echo /opt/litellm/docker-compose.yml; \
                 else echo \"$@\" >> {}; fi\nexit 0\n",
                argv.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
        unsafe { std::env::set_var("GRYONIXNEXUSD_INSTALL_DOCKER_BIN", &stub) };

        assert!(restart_gateway());
        let asked = std::fs::read_to_string(&argv).unwrap_or_default();
        assert!(
            asked.contains("compose -p litellm -f /opt/litellm/docker-compose.yml up -d --force-recreate litellm"),
            "the gateway has to be re-created, not bounced: {asked}"
        );
        assert!(!asked.contains("restart litellm"),
                "the plain restart is the FALLBACK, and compose answered: {asked}");

        unsafe { std::env::remove_var("GRYONIXNEXUSD_INSTALL_DOCKER_BIN") };
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_container_with_no_compose_labels_falls_back_to_the_bounce() {
        let _env = env_guard();
        let dir = std::env::temp_dir().join(format!("gryonix-llmkeys-nolabel-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let argv = dir.join("argv");
        let stub = dir.join("docker-stub");
        std::fs::write(
            &stub,
            format!(
                "#!/bin/sh\nif [ \"$1\" = inspect ]; then echo ''; \
                 else echo \"$@\" >> {}; fi\nexit 0\n",
                argv.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
        unsafe { std::env::set_var("GRYONIXNEXUSD_INSTALL_DOCKER_BIN", &stub) };

        assert!(restart_gateway());
        let asked = std::fs::read_to_string(&argv).unwrap_or_default();
        assert!(asked.contains("restart litellm"), "expected the fallback: {asked}");

        unsafe { std::env::remove_var("GRYONIXNEXUSD_INSTALL_DOCKER_BIN") };
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn removing_the_last_key_empties_the_file_that_already_exists() {
        let _env = env_guard();
        let dir = std::env::temp_dir().join(format!("gryonix-llmkeys-empty-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("litellm-keys.env");
        unsafe { std::env::set_var("GRYONIXNEXUSD_LLM_KEYS_PATH", &path) };
        let stub = dir.join("docker-stub");
        std::fs::write(&stub, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
        unsafe { std::env::set_var("GRYONIXNEXUSD_INSTALL_DOCKER_BIN", &stub) };

        write_if_changed("OPENAI_API_KEY=one\n").unwrap();
        assert!(reconcile(&[]).unwrap());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "");

        unsafe { std::env::remove_var("GRYONIXNEXUSD_LLM_KEYS_PATH") };
        unsafe { std::env::remove_var("GRYONIXNEXUSD_INSTALL_DOCKER_BIN") };
        std::fs::remove_dir_all(&dir).ok();
    }
}
