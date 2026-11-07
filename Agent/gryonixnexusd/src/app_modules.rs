//! The app's module switches, kept per server for every device.

use hyper::StatusCode;

use crate::api::{connect_error, Codec, Resp};
use crate::pb;

const FILE: &str = "app-modules.txt";
const MAX_MODULES: usize = 32;

/// Plain ids only, sorted, without repeats
fn cleaned(ids: &[String]) -> Vec<String> {
    let mut kept: Vec<String> = ids
        .iter()
        .map(|id| id.trim().to_string())
        .filter(|id| !id.is_empty() && id.len() <= 40 && id.chars().all(|c| c.is_ascii_alphanumeric()))
        .collect();
    kept.sort();
    kept.dedup();
    kept.truncate(MAX_MODULES);
    kept
}

fn read() -> Vec<String> {
    let text = std::fs::read_to_string(crate::util::state_dir().join(FILE)).unwrap_or_default();
    cleaned(&text.lines().map(String::from).collect::<Vec<_>>())
}

fn reply(codec: Codec, on: Vec<String>) -> Resp {
    codec
        .encode(&pb::AppModuleSet { on })
        .unwrap_or_else(|err| connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string()))
}

pub async fn get_app_modules(codec: Codec, _req: pb::GetAppModulesRequest) -> Resp {
    reply(codec, read())
}

pub async fn set_app_modules(codec: Codec, req: pb::AppModuleSet) -> Resp {
    let on = cleaned(&req.on);
    let dir = crate::util::state_dir();
    let mut text = on.join("\n");
    text.push('\n');
    let written = std::fs::create_dir_all(&dir)
        .and_then(|()| crate::util::write_file_atomic(&dir.join(FILE), text.as_bytes(), 0o644));
    if let Err(err) = written {
        return connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &format!("could not store the modules: {err}"));
    }
    reply(codec, read())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_plain_sorted_and_unique() {
        let given = ["ai", "dockerAdvanced", "ai", "../etc", " scripts ", ""].map(String::from);
        assert_eq!(cleaned(&given), ["ai", "dockerAdvanced", "scripts"]);
    }
}
