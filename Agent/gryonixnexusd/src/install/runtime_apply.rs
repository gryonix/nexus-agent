//! Applies settings a service keeps in its own database to the running service.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::app_settings;
use super::context::Input;
use super::runtime_apply_cmds::webui_toggles;
use super::runtime_apply_run as run;
use super::execute::EventSink;
use crate::service_users::{openwebui, vault_login, Refusal};
use crate::state::Store;

const SIGN_IN_TRIES: u32 = 12;
const SIGN_IN_PAUSE_SECS: u64 = 5;

/// The gitlab-rails arguments that set sign-up
pub fn gitlab_signup_args(open: bool) -> Vec<String> {
    let script = format!("ApplicationSetting.last.update!(signup_enabled: {})", if open { "true" } else { "false" });
    vec!["gitlab-rails".to_string(), "runner".to_string(), script]
}

/// Runs after a service install or re-apply finished
pub async fn after_install(label: &str, input: &Input, store: &Arc<Mutex<Store>>, sink: &EventSink) {
    match label {
        openwebui::SERVICE_ID => open_webui(input, store, sink).await,
        "nextcloud" => run::nextcloud(input, sink).await,
        "gitlab" => run::gitlab(input, sink).await,
        "adguard-home" => run::adguard(input, store, sink).await,
        "jellyfin" => run::jellyfin(input, store, sink).await,
        _ => {}
    }
}

async fn open_webui(input: &Input, store: &Arc<Mutex<Store>>, sink: &EventSink) {
    let Some((email, password)) = vault_login(store, openwebui::SERVICE_ID) else {
        let _ = sink.step("Open WebUI: no administrator yet, registration settings are stored and apply from its first start").await;
        return;
    };
    let role = app_settings::value(input, "open_webui_default_role");
    let toggles = webui_toggles(input);
    let mut failure = Refusal::Failed;
    for attempt in 0..SIGN_IN_TRIES {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_secs(SIGN_IN_PAUSE_SECS)).await;
        }
        let outcome = match openwebui::OpenWebui::sign_in(&email, &password).await {
            Ok(session) => session.set_registration(input.open_webui_allow_signups, role, &toggles).await,
            Err(refusal) => Err(refusal),
        };
        match outcome {
            Ok(()) => {
                let _ = sink.step("applied registration settings to the running Open WebUI").await;
                return;
            }
            Err(Refusal::AdminLoginFailed) => {
                failure = Refusal::AdminLoginFailed;
                break;
            }
            Err(refusal) => failure = refusal,
        }
    }
    let _ = sink
        .warn(format!(
            "Open WebUI: registration settings are stored but could not be applied to the running service ({}); change them in its admin panel or re-apply once it is up",
            failure.code()
        ))
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_gitlab_command_carries_only_a_boolean() {
        assert_eq!(gitlab_signup_args(true)[2], "ApplicationSetting.last.update!(signup_enabled: true)");
        assert_eq!(gitlab_signup_args(false)[2], "ApplicationSetting.last.update!(signup_enabled: false)");
        assert_eq!(&gitlab_signup_args(true)[..2], ["gitlab-rails", "runner"]);
    }
}
