//! Users of catalog services, managed through each service's own tools

pub mod docker;
pub mod forgejo;
pub mod http;
pub mod home_assistant;
pub mod immich;
pub mod jellyfin;
pub mod nextcloud;
pub mod headscale;
pub mod n8n;
pub mod pihole;
pub mod adguard;
pub mod minecraft_bedrock;
pub mod minecraft_java;
pub mod crafty;
pub mod anythingllm;
pub mod litellm;
pub mod passbolt;
pub mod psono;
pub mod authelia;
pub mod mosquitto;
pub mod photoprism;
pub mod openwebui;
pub mod gitlab;
pub mod seafile;
pub mod token_store;
pub mod vaultwarden;
pub mod ws;

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::api::{connect_error, Codec, Resp};
use crate::state::Store;
use crate::{discover, pb};
use hyper::StatusCode;

pub const CALL_TIMEOUT_SECS: u64 = 60;
const MIN_PASSWORD: usize = 8;
const MAX_PASSWORD: usize = 128;
const MAX_LOGIN: usize = 64;
const MAX_NAME: usize = 128;
const MAX_EMAIL: usize = 254;
pub const ADMIN_ROLE: &str = "admin";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    NotInstalled,
    NotSupported,
    InvalidLogin,
    InvalidRole,
    InvalidEmail,
    InvalidName,
    InvalidQuota,
    EmptyPassword,
    InvalidPassword,
    CannotRemoveAdmin,
    UnknownUser,
    ServiceTimeout,
    ServiceDown,
    NeedsAdminToken,
    AdminNotSetUp,
    AdminLoginFailed,
    Failed,
}

impl Refusal {
    pub fn code(self) -> &'static str {
        match self {
            Refusal::NotInstalled => "not_installed",
            Refusal::NotSupported => "not_supported",
            Refusal::InvalidLogin => "invalid_login",
            Refusal::InvalidRole => "invalid_role",
            Refusal::InvalidEmail => "invalid_email",
            Refusal::InvalidName => "invalid_name",
            Refusal::InvalidQuota => "invalid_quota",
            Refusal::EmptyPassword => "empty_password",
            Refusal::InvalidPassword => "invalid_password",
            Refusal::CannotRemoveAdmin => "cannot_remove_admin",
            Refusal::UnknownUser => "unknown_user",
            Refusal::ServiceTimeout => "service_timeout",
            Refusal::ServiceDown => "service_down",
            Refusal::NeedsAdminToken => "needs_admin_token",
            Refusal::AdminNotSetUp => "admin_not_set_up",
            Refusal::AdminLoginFailed => "admin_login_failed",
            Refusal::Failed => "service_error",
        }
    }
}

pub struct NewUser {
    pub login: String,
    pub display_name: String,
    pub email: String,
    pub password: String,
    pub role: String,
    pub quota_bytes: i64,
}

type Users = Result<Vec<pb::ServiceUser>, Refusal>;
type Done = Result<(), Refusal>;

pub trait UserBackend: Sync {
    fn capabilities(&self) -> pb::UserCapabilities;
    fn list(&self) -> impl Future<Output = Users> + Send;
    fn create(&self, new: &NewUser) -> impl Future<Output = Done> + Send;
    fn delete(&self, user_id: &str) -> impl Future<Output = Done> + Send;
    fn set_password(&self, user_id: &str, password: &str) -> impl Future<Output = Done> + Send;
    fn set_role(&self, user_id: &str, role: &str) -> impl Future<Output = Done> + Send;
    fn set_enabled(&self, user_id: &str, enabled: bool) -> impl Future<Output = Done> + Send;
    fn set_quota(&self, user_id: &str, bytes: i64) -> impl Future<Output = Done> + Send;
}

// ─────────────────────────── Validation ───────────────────────────

pub fn valid_login(login: &str) -> bool {
    !login.is_empty()
        && login.chars().count() <= MAX_LOGIN
        && !login.starts_with('-')
        && login.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '@' | '-'))
}

pub fn valid_email(email: &str) -> bool {
    if email.is_empty() {
        return true;
    }
    let parts: Vec<&str> = email.split('@').collect();
    email.len() <= MAX_EMAIL
        && !email.starts_with('-')
        && parts.len() == 2
        && !parts[0].is_empty()
        && !parts[1].is_empty()
        && email.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '@' | '-' | '+' | '%'))
}

pub fn valid_display_name(name: &str) -> bool {
    name.chars().count() <= MAX_NAME && !name.chars().any(char::is_control)
}

pub fn check_password(password: &str) -> Done {
    if password.is_empty() {
        return Err(Refusal::EmptyPassword);
    }
    let length = password.chars().count();
    if !(MIN_PASSWORD..=MAX_PASSWORD).contains(&length) || password.chars().any(char::is_control) {
        return Err(Refusal::InvalidPassword);
    }
    Ok(())
}

fn check_login(login: &str) -> Done {
    if valid_login(login) { Ok(()) } else { Err(Refusal::InvalidLogin) }
}

fn check_role(caps: &pb::UserCapabilities, role: &str) -> Done {
    if caps.roles.iter().any(|known| known == role) { Ok(()) } else { Err(Refusal::InvalidRole) }
}

fn require(allowed: bool) -> Done {
    if allowed { Ok(()) } else { Err(Refusal::NotSupported) }
}

fn validate_new(caps: &pb::UserCapabilities, new: &NewUser) -> Done {
    if caps.user_id_is_email {
        if new.login.is_empty() || !valid_email(&new.login) {
            return Err(Refusal::InvalidEmail);
        }
    } else {
        check_login(&new.login)?;
    }
    if !valid_display_name(&new.display_name) {
        return Err(Refusal::InvalidName);
    }
    if !valid_email(&new.email) || (caps.needs_email && new.email.is_empty()) {
        return Err(Refusal::InvalidEmail);
    }
    if caps.can_set_password {
        check_password(&new.password)?;
    }
    if !caps.roles.is_empty() || !new.role.is_empty() {
        check_role(caps, &new.role)?;
    }
    if new.quota_bytes < 0 || (new.quota_bytes > 0 && !caps.can_set_quota) {
        return Err(Refusal::InvalidQuota);
    }
    Ok(())
}

// ─────────────────────────── Operations ───────────────────────────

enum Op {
    List,
    Create(NewUser),
    Delete(String),
    Password(String, String),
    Role(String, String),
    Enabled(String, bool),
    Quota(String, i64),
}

async fn timed<T>(call: impl Future<Output = Result<T, Refusal>>) -> Result<T, Refusal> {
    match tokio::time::timeout(Duration::from_secs(CALL_TIMEOUT_SECS), call).await {
        Ok(result) => result,
        Err(_) => Err(Refusal::ServiceTimeout),
    }
}

async fn guard_self<B: UserBackend>(backend: &B, user_id: &str) -> Done {
    let users = timed(backend.list()).await?;
    match users.iter().find(|user| user.id == user_id) {
        None => Err(Refusal::UnknownUser),
        Some(user) if user.is_self => Err(Refusal::CannotRemoveAdmin),
        Some(_) => Ok(()),
    }
}

async fn apply<B: UserBackend>(backend: &B, op: Op) -> Done {
    let caps = backend.capabilities();
    match op {
        Op::List => Ok(()),
        Op::Create(new) => {
            require(caps.can_create)?;
            validate_new(&caps, &new)?;
            timed(backend.create(&new)).await
        }
        Op::Delete(id) => {
            require(caps.can_delete)?;
            check_login(&id)?;
            guard_self(backend, &id).await?;
            timed(backend.delete(&id)).await
        }
        Op::Password(id, password) => {
            require(caps.can_set_password)?;
            check_login(&id)?;
            check_password(&password)?;
            timed(backend.set_password(&id, &password)).await
        }
        Op::Role(id, role) => {
            check_login(&id)?;
            check_role(&caps, &role)?;
            if role != ADMIN_ROLE {
                guard_self(backend, &id).await?;
            }
            timed(backend.set_role(&id, &role)).await
        }
        Op::Enabled(id, enabled) => {
            require(caps.can_set_enabled)?;
            check_login(&id)?;
            if !enabled {
                guard_self(backend, &id).await?;
            }
            timed(backend.set_enabled(&id, enabled)).await
        }
        Op::Quota(id, bytes) => {
            require(caps.can_set_quota)?;
            check_login(&id)?;
            if bytes < 0 {
                return Err(Refusal::InvalidQuota);
            }
            timed(backend.set_quota(&id, bytes)).await
        }
    }
}

fn answer(users: Vec<pb::ServiceUser>, refusal: Option<Refusal>) -> pb::ServiceUserList {
    pb::ServiceUserList { users, refusal: refusal.map(|r| r.code().to_string()).unwrap_or_default() }
}

/// Apply the operation, then always re-read the list
async fn run<B: UserBackend>(backend: &B, op: Op) -> pb::ServiceUserList {
    let refusal = apply(backend, op).await.err();
    match timed(backend.list()).await {
        Ok(users) => answer(users, refusal),
        Err(listing) => answer(Vec::new(), refusal.or(Some(listing))),
    }
}

enum Located {
    Nextcloud(nextcloud::Nextcloud),
    Vaultwarden(vaultwarden::Vaultwarden),
    Immich(immich::Immich),
    Jellyfin(jellyfin::Jellyfin),
    Seafile(seafile::Seafile),
    Forgejo(forgejo::Forgejo),
    Gitlab(gitlab::Gitlab),
    OpenWebui(openwebui::OpenWebui),
    Photoprism(photoprism::Photoprism),
    Mosquitto(mosquitto::Mosquitto),
    Authelia(authelia::Authelia),
    Psono(psono::Psono),
    Passbolt(passbolt::Passbolt),
    Litellm(litellm::Litellm),
    Anythingllm(anythingllm::Anythingllm),
    Crafty(crafty::Crafty),
    MinecraftJava(minecraft_java::MinecraftJava),
    MinecraftBedrock(minecraft_bedrock::MinecraftBedrock),
    Adguard(adguard::Adguard),
    Pihole(pihole::Pihole),
    N8n(n8n::N8n),
    Headscale(headscale::Headscale),
    HomeAssistant(home_assistant::HomeAssistant),
}

const SUPPORTED: [&str; 23] = [
    forgejo::SERVICE_ID,
    nextcloud::SERVICE_ID,
    vaultwarden::SERVICE_ID,
    immich::SERVICE_ID,
    jellyfin::SERVICE_ID,
    seafile::SERVICE_ID,
    gitlab::SERVICE_ID,
    openwebui::SERVICE_ID,
    photoprism::SERVICE_ID,
    mosquitto::SERVICE_ID,
    authelia::SERVICE_ID,
    psono::SERVICE_ID,
    passbolt::SERVICE_ID,
    litellm::SERVICE_ID,
    anythingllm::SERVICE_ID,
    crafty::SERVICE_ID,
    minecraft_java::SERVICE_ID,
    minecraft_bedrock::SERVICE_ID,
    adguard::SERVICE_ID,
    pihole::SERVICE_ID,
    n8n::SERVICE_ID,
    headscale::SERVICE_ID,
    home_assistant::SERVICE_ID,
];

fn supported(service_id: &str) -> Option<&'static str> {
    let known = discover::known_service_id(service_id)?;
    SUPPORTED.contains(&known).then_some(known)
}

async fn locate(service_id: &str, store: &Arc<Mutex<Store>>) -> Result<Located, Refusal> {
    let found = match supported(service_id) {
        Some(nextcloud::SERVICE_ID) => nextcloud::Nextcloud::find().await?.map(Located::Nextcloud),
        Some(vaultwarden::SERVICE_ID) => vaultwarden::Vaultwarden::find().await?.map(Located::Vaultwarden),
        Some(immich::SERVICE_ID) => immich::Immich::find(vault_login(store, "immich")).await?.map(Located::Immich),
        Some(jellyfin::SERVICE_ID) => jellyfin::Jellyfin::find(vault_login(store, "jellyfin")).await?.map(Located::Jellyfin),
        Some(seafile::SERVICE_ID) => seafile::Seafile::find(vault_login(store, "seafile")).await?.map(Located::Seafile),
        Some(forgejo::SERVICE_ID) => forgejo::Forgejo::find().await?.map(Located::Forgejo),
        Some(gitlab::SERVICE_ID) => gitlab::Gitlab::find().await?.map(Located::Gitlab),
        Some(openwebui::SERVICE_ID) => openwebui::OpenWebui::find(vault_login(store, "open-webui")).await?.map(Located::OpenWebui),
        Some(photoprism::SERVICE_ID) => photoprism::Photoprism::find().await?.map(Located::Photoprism),
        Some(mosquitto::SERVICE_ID) => mosquitto::Mosquitto::find().await?.map(Located::Mosquitto),
        Some(authelia::SERVICE_ID) => authelia::Authelia::find().await?.map(Located::Authelia),
        Some(psono::SERVICE_ID) => psono::Psono::find().await?.map(Located::Psono),
        Some(passbolt::SERVICE_ID) => passbolt::Passbolt::find().await?.map(Located::Passbolt),
        Some(litellm::SERVICE_ID) => litellm::Litellm::find().await?.map(Located::Litellm),
        Some(anythingllm::SERVICE_ID) => anythingllm::Anythingllm::find(vault_login(store, "anythingllm")).await?.map(Located::Anythingllm),
        Some(crafty::SERVICE_ID) => crafty::Crafty::find(vault_login(store, "crafty-controller")).await?.map(Located::Crafty),
        Some(minecraft_java::SERVICE_ID) => minecraft_java::MinecraftJava::find().await?.map(Located::MinecraftJava),
        Some(minecraft_bedrock::SERVICE_ID) => minecraft_bedrock::MinecraftBedrock::find().await?.map(Located::MinecraftBedrock),
        Some(adguard::SERVICE_ID) => adguard::Adguard::find().await?.map(Located::Adguard),
        Some(pihole::SERVICE_ID) => pihole::Pihole::find().await?.map(Located::Pihole),
        Some(n8n::SERVICE_ID) => n8n::N8n::find(vault_login(store, "n8n")).await?.map(Located::N8n),
        Some(headscale::SERVICE_ID) => headscale::Headscale::find().await?.map(Located::Headscale),
        Some(home_assistant::SERVICE_ID) => home_assistant::HomeAssistant::find(vault_login(store, "home-assistant")).await?.map(Located::HomeAssistant),
        _ => return Err(Refusal::NotSupported),
    };
    found.ok_or(Refusal::NotInstalled)
}

/// One variable from `docker inspect` environment JSON
pub fn env_value(env_json: &str, key: &str) -> Option<String> {
    let env: Vec<String> = serde_json::from_str(env_json.trim()).ok()?;
    let prefix = format!("{key}=");
    env.iter().find_map(|line| line.strip_prefix(&prefix)).map(String::from)
}

/// The environment of a container as docker reports it
pub async fn container_env(container: &str) -> Option<String> {
    let output = tokio::process::Command::new("docker")
        .args(["inspect", "--format", "{{json .Config.Env}}", container])
        .output()
        .await
        .ok()?;
    output.status.success().then(|| String::from_utf8_lossy(&output.stdout).to_string())
}

fn vault_login(store: &Arc<Mutex<Store>>, title: &str) -> Option<(String, String)> {
    let snapshot = store.lock().unwrap_or_else(|err| err.into_inner()).vault_snapshot().ok()?;
    snapshot
        .entries
        .into_iter()
        .find(|e| {
            !e.deleted && e.service_secret.is_empty() && e.title.eq_ignore_ascii_case(title)
                && !e.login.is_empty() && !e.password.is_empty()
        })
        .map(|e| (e.login, e.password))
}

async fn execute(service_id: &str, op: Op, store: &Arc<Mutex<Store>>) -> pb::ServiceUserList {
    match locate(service_id, store).await {
        Ok(Located::Nextcloud(backend)) => run(&backend, op).await,
        Ok(Located::Vaultwarden(backend)) => run(&backend, op).await,
        Ok(Located::Immich(backend)) => run(&backend, op).await,
        Ok(Located::Jellyfin(backend)) => run(&backend, op).await,
        Ok(Located::Seafile(backend)) => run(&backend, op).await,
        Ok(Located::Forgejo(backend)) => run(&backend, op).await,
        Ok(Located::Gitlab(backend)) => run(&backend, op).await,
        Ok(Located::OpenWebui(backend)) => run(&backend, op).await,
        Ok(Located::Photoprism(backend)) => run(&backend, op).await,
        Ok(Located::Mosquitto(backend)) => run(&backend, op).await,
        Ok(Located::Authelia(backend)) => run(&backend, op).await,
        Ok(Located::Psono(backend)) => run(&backend, op).await,
        Ok(Located::Passbolt(backend)) => run(&backend, op).await,
        Ok(Located::Litellm(backend)) => run(&backend, op).await,
        Ok(Located::Anythingllm(backend)) => run(&backend, op).await,
        Ok(Located::Crafty(backend)) => run(&backend, op).await,
        Ok(Located::MinecraftJava(backend)) => run(&backend, op).await,
        Ok(Located::MinecraftBedrock(backend)) => run(&backend, op).await,
        Ok(Located::Adguard(backend)) => run(&backend, op).await,
        Ok(Located::Pihole(backend)) => run(&backend, op).await,
        Ok(Located::N8n(backend)) => run(&backend, op).await,
        Ok(Located::Headscale(backend)) => run(&backend, op).await,
        Ok(Located::HomeAssistant(backend)) => run(&backend, op).await,
        Err(refusal) => answer(Vec::new(), Some(refusal)),
    }
}

pub fn capabilities_of(service_id: &str) -> pb::UserCapabilities {
    match supported(service_id) {
        Some(nextcloud::SERVICE_ID) => nextcloud::capabilities(),
        Some(vaultwarden::SERVICE_ID) => vaultwarden::capabilities(),
        Some(immich::SERVICE_ID) => immich::capabilities(),
        Some(jellyfin::SERVICE_ID) => jellyfin::capabilities(),
        Some(seafile::SERVICE_ID) => seafile::capabilities(),
        Some(forgejo::SERVICE_ID) => forgejo::capabilities(),
        Some(gitlab::SERVICE_ID) => gitlab::capabilities(),
        Some(openwebui::SERVICE_ID) => openwebui::capabilities(),
        Some(photoprism::SERVICE_ID) => photoprism::capabilities(),
        Some(mosquitto::SERVICE_ID) => mosquitto::capabilities(),
        Some(authelia::SERVICE_ID) => authelia::capabilities(),
        Some(psono::SERVICE_ID) => psono::capabilities(),
        Some(passbolt::SERVICE_ID) => passbolt::capabilities(),
        Some(litellm::SERVICE_ID) => litellm::capabilities(),
        Some(anythingllm::SERVICE_ID) => anythingllm::capabilities(),
        Some(crafty::SERVICE_ID) => crafty::capabilities(),
        Some(minecraft_java::SERVICE_ID) => minecraft_java::capabilities(),
        Some(minecraft_bedrock::SERVICE_ID) => minecraft_bedrock::capabilities(),
        Some(adguard::SERVICE_ID) => adguard::capabilities(),
        Some(pihole::SERVICE_ID) => pihole::capabilities(),
        Some(n8n::SERVICE_ID) => n8n::capabilities(),
        Some(headscale::SERVICE_ID) => headscale::capabilities(),
        Some(home_assistant::SERVICE_ID) => home_assistant::capabilities(),
        _ => pb::UserCapabilities::default(),
    }
}

// ─────────────────────────── RPCs ───────────────────────────

fn encode<T>(codec: Codec, message: &T) -> Resp
where
    T: prost::Message + serde::Serialize,
{
    codec.encode(message).unwrap_or_else(|err| {
        connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string())
    })
}

pub async fn get_user_capabilities(codec: Codec, req: pb::ServiceUsersRequest) -> Resp {
    encode(codec, &capabilities_of(&req.service_id))
}

pub async fn list_service_users(codec: Codec, req: pb::ServiceUsersRequest, store: Arc<Mutex<Store>>) -> Resp {
    encode(codec, &execute(&req.service_id, Op::List, &store).await)
}

pub async fn create_service_user(codec: Codec, req: pb::CreateServiceUserRequest, store: Arc<Mutex<Store>>) -> Resp {
    let new = NewUser {
        login: req.login,
        display_name: req.display_name,
        email: req.email,
        password: req.password,
        role: req.role,
        quota_bytes: req.quota_bytes,
    };
    encode(codec, &execute(&req.service_id, Op::Create(new), &store).await)
}

pub async fn delete_service_user(codec: Codec, req: pb::ServiceUserTarget, store: Arc<Mutex<Store>>) -> Resp {
    encode(codec, &execute(&req.service_id, Op::Delete(req.user_id), &store).await)
}

pub async fn set_service_user_password(codec: Codec, req: pb::SetServiceUserPasswordRequest, store: Arc<Mutex<Store>>) -> Resp {
    encode(codec, &execute(&req.service_id, Op::Password(req.user_id, req.password), &store).await)
}

pub async fn set_service_user_role(codec: Codec, req: pb::SetServiceUserRoleRequest, store: Arc<Mutex<Store>>) -> Resp {
    encode(codec, &execute(&req.service_id, Op::Role(req.user_id, req.role), &store).await)
}

pub async fn set_service_user_enabled(codec: Codec, req: pb::SetServiceUserEnabledRequest, store: Arc<Mutex<Store>>) -> Resp {
    encode(codec, &execute(&req.service_id, Op::Enabled(req.user_id, req.enabled), &store).await)
}

pub const TOKEN_SERVICES: [&str; 3] = ["anythingllm", "n8n", "home-assistant"];
pub const TOKEN_NOTE: &str = "admin_token";
const TOKEN_LOGIN: &str = "api-key";
const MIN_TOKEN: usize = 8;
const MAX_TOKEN: usize = 2048;

pub fn plausible_token(token: &str) -> bool {
    (MIN_TOKEN..=MAX_TOKEN).contains(&token.len()) && token.chars().all(|c| !c.is_whitespace() && !c.is_control())
}

pub fn token_entry(existing: Option<pb::VaultEntry>, service_id: &str, token: &str, now: i64) -> pb::VaultEntry {
    let mut entry = existing.unwrap_or_else(|| pb::VaultEntry {
        id: format!("single|{service_id}"),
        host: "single".to_string(),
        title: service_id.to_string(),
        ..Default::default()
    });
    if entry.login.is_empty() {
        entry.login = TOKEN_LOGIN.to_string();
    }
    entry.password = token.to_string();
    entry.deleted = false;
    entry.updated_at = now;
    entry.updated_by = "agent".to_string();
    entry
}

fn store_token(service_id: &str, token: &str, store: &Arc<Mutex<Store>>) -> Done {
    if !TOKEN_SERVICES.contains(&service_id) {
        return Err(Refusal::NotSupported);
    }
    if !plausible_token(token) {
        return Err(Refusal::EmptyPassword);
    }
    let guard = store.lock().unwrap_or_else(|err| err.into_inner());
    let snapshot = guard.vault_snapshot().map_err(|_| Refusal::Failed)?;
    let existing = snapshot
        .entries
        .into_iter()
        .find(|e| !e.deleted && e.service_secret.is_empty() && e.title.eq_ignore_ascii_case(service_id));
    let entry = token_entry(existing, service_id, token, crate::util::now_millis());
    guard.put_vault_entries(&[entry]).map(|_| ()).map_err(|_| Refusal::Failed)
}

pub async fn set_service_admin_token(codec: Codec, req: pb::SetServiceAdminTokenRequest, store: Arc<Mutex<Store>>) -> Resp {
    let known = supported(&req.service_id).unwrap_or_default();
    let saved = store_token(known, req.token.trim(), &store);
    let list = match saved {
        Ok(()) => execute(known, Op::List, &store).await,
        Err(refusal) => answer(Vec::new(), Some(refusal)),
    };
    encode(codec, &list)
}

pub async fn set_service_user_quota(codec: Codec, req: pb::SetServiceUserQuotaRequest, store: Arc<Mutex<Store>>) -> Resp {
    encode(codec, &execute(&req.service_id, Op::Quota(req.user_id, req.quota_bytes), &store).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct Fake {
        users: Vec<pb::ServiceUser>,
        calls: Mutex<Vec<String>>,
    }

    fn user(id: &str, is_self: bool) -> pb::ServiceUser {
        pb::ServiceUser { id: id.into(), login: id.into(), is_self, enabled: true, ..Default::default() }
    }

    fn fake() -> Fake {
        Fake { users: vec![user("operator", true), user("anna", false)], calls: Mutex::new(Vec::new()) }
    }

    impl Fake {
        fn note(&self, call: &str) -> Done {
            self.calls.lock().unwrap().push(call.to_string());
            Ok(())
        }
        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl UserBackend for Fake {
        fn capabilities(&self) -> pb::UserCapabilities {
            nextcloud::capabilities()
        }
        async fn list(&self) -> Users {
            Ok(self.users.clone())
        }
        async fn create(&self, new: &NewUser) -> Done {
            self.note(&format!("create {}", new.login))
        }
        async fn delete(&self, id: &str) -> Done {
            self.note(&format!("delete {id}"))
        }
        async fn set_password(&self, id: &str, _: &str) -> Done {
            self.note(&format!("password {id}"))
        }
        async fn set_role(&self, id: &str, role: &str) -> Done {
            self.note(&format!("role {id} {role}"))
        }
        async fn set_enabled(&self, id: &str, enabled: bool) -> Done {
            self.note(&format!("enabled {id} {enabled}"))
        }
        async fn set_quota(&self, id: &str, bytes: i64) -> Done {
            self.note(&format!("quota {id} {bytes}"))
        }
    }

    fn new_user(login: &str, password: &str) -> NewUser {
        NewUser {
            login: login.into(),
            display_name: String::new(),
            email: String::new(),
            password: password.into(),
            role: "user".into(),
            quota_bytes: 0,
        }
    }

    #[test]
    fn logins_follow_the_whitelist() {
        let longest = "a".repeat(64);
        let too_long = "a".repeat(65);
        for good in ["anna", "a.b_c-d", "anna@example.org", longest.as_str()] {
            assert!(valid_login(good), "{good}");
        }
        for bad in ["", "-anna", "an na", "anna;ls", "an\nna", "ännä", too_long.as_str()] {
            assert!(!valid_login(bad), "{bad:?}");
        }
    }

    #[test]
    fn passwords_are_bounded_and_never_empty() {
        assert_eq!(check_password(""), Err(Refusal::EmptyPassword));
        assert_eq!(check_password("short"), Err(Refusal::InvalidPassword));
        let huge = "x".repeat(129);
        assert_eq!(check_password(&huge), Err(Refusal::InvalidPassword));
        assert_eq!(check_password("long enough"), Ok(()));
    }

    #[tokio::test]
    async fn the_agents_own_admin_cannot_be_removed_or_disabled_or_demoted() {
        let backend = fake();
        for op in [
            Op::Delete("operator".into()),
            Op::Enabled("operator".into(), false),
            Op::Role("operator".into(), "user".into()),
        ] {
            assert_eq!(apply(&backend, op).await, Err(Refusal::CannotRemoveAdmin));
        }
        assert!(backend.calls().is_empty());
    }

    #[tokio::test]
    async fn an_unknown_user_is_refused_before_the_service_is_called() {
        let backend = fake();
        assert_eq!(apply(&backend, Op::Delete("boris".into())).await, Err(Refusal::UnknownUser));
        assert!(backend.calls().is_empty());
    }

    #[tokio::test]
    async fn bad_input_never_reaches_the_service() {
        let backend = fake();
        let bad_login = apply(&backend, Op::Create(new_user("an na", "long enough"))).await;
        assert_eq!(bad_login, Err(Refusal::InvalidLogin));
        let empty = apply(&backend, Op::Create(new_user("boris", ""))).await;
        assert_eq!(empty, Err(Refusal::EmptyPassword));
        let role = apply(&backend, Op::Role("anna".into(), "owner".into())).await;
        assert_eq!(role, Err(Refusal::InvalidRole));
        assert!(backend.calls().is_empty());
    }

    #[tokio::test]
    async fn a_mutation_answers_with_the_fresh_list() {
        let backend = fake();
        let answer = run(&backend, Op::Delete("anna".into())).await;
        assert_eq!(answer.refusal, "");
        assert_eq!(answer.users.len(), 2);
        assert_eq!(backend.calls(), ["delete anna"]);
    }

    #[tokio::test]
    async fn a_refusal_travels_in_the_list() {
        let answer = run(&fake(), Op::Delete("operator".into())).await;
        assert_eq!(answer.refusal, "cannot_remove_admin");
        assert_eq!(answer.users.len(), 2);
    }

    #[test]
    fn a_token_is_checked_before_it_is_kept() {
        assert!(plausible_token("n8n_api_0123456789"));
        for bad in ["", "short", "has space in it 123", "line\nbreak-token-123"] {
            assert!(!plausible_token(bad), "{bad:?}");
        }
        assert!(!plausible_token(&"x".repeat(2049)));
    }

    #[test]
    fn a_new_token_row_is_named_after_the_service_and_found_by_its_title() {
        let entry = token_entry(None, "n8n", "n8n_api_0123456789", 42);
        assert_eq!((entry.id.as_str(), entry.title.as_str(), entry.login.as_str()), ("single|n8n", "n8n", "api-key"));
        assert_eq!((entry.password.as_str(), entry.updated_at, entry.updated_by.as_str()), ("n8n_api_0123456789", 42, "agent"));
        assert!(entry.service_secret.is_empty() && !entry.deleted);
    }

    #[test]
    fn an_existing_row_keeps_its_id_and_login_and_comes_back_to_life() {
        let old = pb::VaultEntry {
            id: "vps|n8n".into(),
            title: "N8N".into(),
            login: "owner".into(),
            password: "old".into(),
            deleted: true,
            ..Default::default()
        };
        let entry = token_entry(Some(old), "n8n", "n8n_api_0123456789", 7);
        assert_eq!((entry.id.as_str(), entry.login.as_str(), entry.deleted), ("vps|n8n", "owner", false));
        assert_eq!(entry.password, "n8n_api_0123456789");
    }

    #[test]
    fn only_token_services_ask_for_a_token() {
        for id in TOKEN_SERVICES {
            assert_eq!(capabilities_of(id).note, TOKEN_NOTE, "{id}");
        }
        assert_ne!(capabilities_of("litellm").note, TOKEN_NOTE);
    }

    #[test]
    fn an_unsupported_service_has_no_users() {
        assert!(!capabilities_of("mailcow").supported);
        assert!(!capabilities_of("nope").supported);
        assert!(capabilities_of("vaultwarden").supported);
        assert!(capabilities_of("immich").supported);
        assert!(capabilities_of("jellyfin").supported);
        assert!(capabilities_of("seafile").supported);
        assert!(capabilities_of("forgejo").supported);
        assert!(capabilities_of("headscale").supported);
        assert!(capabilities_of("n8n").supported);
        assert!(capabilities_of("pihole").supported);
        assert!(capabilities_of("adguard-home").supported);
        assert!(capabilities_of("minecraft-bedrock").supported);
        assert!(capabilities_of("minecraft-java").supported);
        assert!(capabilities_of("crafty-controller").supported);
        assert!(capabilities_of("anythingllm").supported);
        assert!(capabilities_of("litellm").supported);
        assert!(capabilities_of("passbolt").supported);
        assert!(capabilities_of("psono").supported);
        assert!(capabilities_of("authelia").supported);
        assert!(capabilities_of("mosquitto").supported);
        assert!(capabilities_of("photoprism").supported);
        assert!(capabilities_of("open-webui").supported);
        assert!(capabilities_of("gitlab").supported);
        assert_eq!(env_value("[\"A=1\",\"B=two\"]", "B").as_deref(), Some("two"));
        assert_eq!(env_value("[\"A=1\"]", "B"), None);
        assert!(capabilities_of("home-assistant").supported);
        assert!(capabilities_of("nextcloud").supported);
    }
}
