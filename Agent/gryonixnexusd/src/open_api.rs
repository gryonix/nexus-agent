//! Which API paths of each site answer without the VPN.

use std::collections::BTreeMap;
use std::path::PathBuf;

use hyper::StatusCode;

use crate::api::{connect_error, Codec, Resp};
use crate::install::open_sites::{self, OpenSite};
use crate::pb;

const STORE_FILE: &str = "open-api.json";
const MAX_PATHS: usize = 40;

fn store_path() -> PathBuf {
    crate::util::state_dir().join(STORE_FILE)
}

/// The stored choices, by service
fn load_choices() -> BTreeMap<String, Vec<String>> {
    std::fs::read_to_string(store_path())
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

fn save_choice(owner: &str, open: &[String]) -> Result<(), String> {
    let mut choices = load_choices();
    choices.insert(owner.to_string(), open.to_vec());
    let text = serde_json::to_string_pretty(&choices).map_err(|err| err.to_string())?;
    crate::util::write_file_atomic(&store_path(), text.as_bytes(), 0o600)
        .map_err(|err| format!("could not save the choice: {err}"))
}

/// The Caddyfile with the stored choices put back
pub fn reapplied(caddyfile: &str) -> String {
    with_choices(caddyfile, &load_choices())
}

fn with_choices(caddyfile: &str, choices: &BTreeMap<String, Vec<String>>) -> String {
    choices.iter().fold(caddyfile.to_string(), |text, (owner, open)| {
        open_sites::with_open_paths(&text, owner, open).unwrap_or(text)
    })
}

fn is_valid_owner(owner: &str) -> bool {
    !owner.is_empty() && owner.len() <= 64 && owner.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

fn validated(req: &pb::SetOpenApiRequest) -> Result<Vec<String>, String> {
    if !is_valid_owner(&req.service_id) {
        return Err("service_id is not a service".to_string());
    }
    if req.paths.len() > MAX_PATHS {
        return Err(format!("at most {MAX_PATHS} paths"));
    }
    if let Some(bad) = req.paths.iter().find(|path| !open_sites::is_valid_path(path)) {
        return Err(format!("{bad} is not a path that can be opened"));
    }
    let mut open: Vec<String> = Vec::new();
    for path in &req.paths {
        if !open.contains(path) {
            open.push(path.clone());
        }
    }
    Ok(open)
}

fn state(sites: Vec<OpenSite>) -> pb::OpenApiState {
    pb::OpenApiState {
        sites: sites
            .into_iter()
            .map(|site| pb::OpenApiSite { service_id: site.owner, paths: site.paths, editable: site.editable })
            .collect(),
    }
}

fn encode(codec: Codec, message: &pb::OpenApiState) -> Resp {
    codec.encode(message).unwrap_or_else(|err| connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string()))
}

pub async fn get_open_api(codec: Codec, _req: pb::GetOpenApiRequest) -> Resp {
    let caddyfile = crate::install::execute::current_caddyfile();
    encode(codec, &state(open_sites::open_sites(&caddyfile)))
}

/// Opens or closes one service's API paths
pub async fn set_open_api(codec: Codec, req: pb::SetOpenApiRequest) -> Resp {
    let open = match validated(&req) {
        Ok(open) => open,
        Err(why) => return connect_error(StatusCode::BAD_REQUEST, "invalid_argument", &why),
    };
    if let Err(why) = crate::install::execute::apply_open_paths(&req.service_id, &open).await {
        return connect_error(StatusCode::UNPROCESSABLE_ENTITY, "failed_precondition", &why);
    }
    if let Err(why) = save_choice(&req.service_id, &open) {
        tracing::warn!(%why, "open API choice not saved");
    }
    let caddyfile = crate::install::execute::current_caddyfile();
    encode(codec, &state(open_sites::open_sites(&caddyfile)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(id: &str, paths: &[&str]) -> pb::SetOpenApiRequest {
        pb::SetOpenApiRequest { service_id: id.to_string(), paths: paths.iter().map(|p| p.to_string()).collect() }
    }

    #[test]
    fn a_good_request_keeps_its_paths_once() {
        let open = validated(&request("vaultwarden", &["/api/*", "/api/*", "/identity/*"])).unwrap();
        assert_eq!(open, vec!["/api/*".to_string(), "/identity/*".to_string()]);
    }

    #[test]
    fn bad_services_and_paths_are_refused() {
        assert!(validated(&request("", &[])).is_err());
        assert!(validated(&request("vault warden", &[])).is_err());
        assert!(validated(&request("vaultwarden", &["/*"])).is_err());
        assert!(validated(&request("vaultwarden", &["/api/* {"])).is_err());
        assert!(validated(&request("vaultwarden", &[])).is_ok());
    }

    #[test]
    fn stored_choices_win_over_a_fresh_render() {
        let open = vec!["/api/*".to_string()];
        let fresh = crate::install::caddy::site_with_public_paths(
            "vaultwarden", "vault.example.net", 8082, true, false, false, false, &open, false,
        );
        let mut choices = BTreeMap::new();
        choices.insert("vaultwarden".to_string(), Vec::new());
        let closed = with_choices(&fresh, &choices);
        assert!(!closed.contains("gryonixnexus_open"));
        choices.insert("gone".to_string(), vec!["/x/*".to_string()]);
        assert_eq!(with_choices(&closed, &choices), closed);
    }
}
