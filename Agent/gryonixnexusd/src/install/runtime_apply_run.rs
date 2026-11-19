//! Runs runtime settings against Nextcloud, GitLab, AdGuard and Jellyfin.

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;

use super::context::Input;
use super::execute::EventSink;
use super::runtime_apply_cmds::{self as cmds, AdguardChange};
use super::{adguard, gitlab, nextcloud};
use crate::service_users::docker::{self, Call};
use crate::service_users::http;
use crate::service_users::{adguard as adguard_users, jellyfin as jellyfin_users, vault_login, Refusal};
use crate::state::Store;
use crate::discover;

const TRIES: u32 = 12;
const PAUSE_SECS: u64 = 5;
const GITLAB_TRIES: u32 = 36;
const GITLAB_RUN_SECS: u64 = 120;

async fn retrying<T, F, Fut>(tries: u32, mut attempt: F) -> Result<T, Refusal>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, Refusal>>,
{
    let mut failure = Refusal::Failed;
    for round in 0..tries {
        if round > 0 {
            tokio::time::sleep(Duration::from_secs(PAUSE_SECS)).await;
        }
        match attempt().await {
            Ok(done) => return Ok(done),
            Err(Refusal::AdminLoginFailed) => return Err(Refusal::AdminLoginFailed),
            Err(refusal) => failure = refusal,
        }
    }
    Err(failure)
}

async fn report(sink: &EventSink, name: &str, outcome: Result<(), Refusal>) {
    match outcome {
        Ok(()) => {
            let _ = sink.step(format!("applied settings to the running {name}")).await;
        }
        Err(refusal) => {
            let _ = sink
                .warn(format!(
                    "{name}: settings are stored but could not be applied to the running service ({}); re-apply once it is up",
                    refusal.code()
                ))
                .await;
        }
    }
}

async fn run_all(calls: &[Call]) -> Result<(), Refusal> {
    for call in calls {
        docker::run(call).await?;
    }
    Ok(())
}

pub async fn nextcloud(input: &Input, sink: &EventSink) {
    let Some(container) = nextcloud_container().await else { return report(sink, "Nextcloud", Err(Refusal::ServiceDown)).await };
    let mut calls = cmds::nextcloud_mail_calls(&container, input);
    calls.extend(cmds::nextcloud_extra_calls(&container, input));
    if calls.is_empty() {
        return;
    }
    report(sink, "Nextcloud", retrying(TRIES, || run_all(&calls)).await).await;
}

async fn nextcloud_container() -> Option<String> {
    let snapshot = discover::service_snapshot(nextcloud::SERVICE_ID).await.ok()??;
    crate::service_users::nextcloud::pick_app_container(&snapshot.containers)
}

pub async fn gitlab(input: &Input, sink: &EventSink) {
    let Some(args) = cmds::gitlab_settings_args(input) else { return };
    let mut full = vec!["exec".to_string(), gitlab::CONTAINER.to_string()];
    full.extend(args);
    let run = || async {
        let call = Call { args: full.clone(), stdin: None };
        let wait = Duration::from_secs(GITLAB_RUN_SECS);
        tokio::time::timeout(wait, docker::run(&call)).await.map_err(|_| Refusal::ServiceTimeout)?.map(|_| ())
    };
    report(sink, "GitLab", retrying(GITLAB_TRIES, run).await).await;
}

/// The sign-in header for AdGuard's API
fn adguard_auth(input: &Input, store: &Arc<Mutex<Store>>) -> Option<String> {
    let (user, password) = vault_login(store, adguard::SERVICE_ID).or_else(|| adguard_from_files(input))?;
    let pair = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"));
    Some(format!("Basic {pair}"))
}

fn adguard_from_files(input: &Input) -> Option<(String, String)> {
    let dir = std::path::Path::new(&input.adguard_path);
    let env = std::fs::read_to_string(dir.join(".env")).ok()?;
    let password = env.lines().find_map(|line| line.strip_prefix("ADGUARD_ADMIN_PASSWORD="))?;
    let yaml = std::fs::read_to_string(dir.join("conf/AdGuardHome.yaml")).ok()?;
    let account = adguard_users::parse(&yaml).into_iter().next()?;
    Some((account.name, password.to_string()))
}

pub async fn adguard(input: &Input, store: &Arc<Mutex<Store>>, sink: &EventSink) {
    let changes = cmds::adguard_changes(input);
    if changes.is_empty() {
        return;
    }
    let Some(auth) = adguard_auth(input, store) else {
        return report(sink, "AdGuard Home", Err(Refusal::AdminNotSetUp)).await;
    };
    let outcome = retrying(TRIES, || adguard_apply(&auth, &changes)).await;
    report(sink, "AdGuard Home", outcome).await;
}

async fn adguard_send(auth: &str, method: &'static str, path: &str, body: Option<String>) -> Result<String, Refusal> {
    let request = cmds::adguard_request(auth, method, adguard::WEB_UI_PORT, path, body);
    let answer = http::send(&request).await?;
    match answer.status {
        401 | 403 => Err(Refusal::AdminLoginFailed),
        _ if answer.ok() => Ok(answer.body),
        _ => Err(Refusal::Failed),
    }
}

async fn adguard_apply(auth: &str, changes: &[AdguardChange]) -> Result<(), Refusal> {
    for change in changes {
        match change {
            AdguardChange::Toggle(area, on) => {
                adguard_send(auth, "POST", &cmds::toggle_path(area, *on), None).await?;
            }
            AdguardChange::Merge { read, write, on } => {
                let current = adguard_send(auth, "GET", read, None).await?;
                let body = cmds::with_enabled(&current, *on).ok_or(Refusal::Failed)?;
                adguard_send(auth, "PUT", write, Some(body)).await?;
            }
        }
    }
    Ok(())
}

pub async fn jellyfin(input: &Input, store: &Arc<Mutex<Store>>, sink: &EventSink) {
    let flags = cmds::jellyfin_flags(input);
    if flags.is_empty() {
        return;
    }
    let login = || vault_login(store, jellyfin_users::SERVICE_ID);
    let apply = || async {
        let server = jellyfin_users::Jellyfin::find(login()).await?.ok_or(Refusal::ServiceDown)?;
        server.set_server_flags(&flags).await
    };
    report(sink, "Jellyfin", retrying(TRIES, apply).await).await;
}
