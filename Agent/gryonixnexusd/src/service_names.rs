//! Names given to services, kept per server for every device.

use std::collections::HashMap;

use hyper::StatusCode;

use crate::api::{connect_error, Codec, Resp};
use crate::pb;

const FILE: &str = "service-names.txt";
const MAX_NAMES: usize = 128;
const MAX_ID: usize = 64;
const MAX_NAME: usize = 60;

/// A catalog id: letters, digits, dash, dot, underscore
fn plain_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_ID
        && id.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

/// One line of text, trimmed and cut to length
fn cleaned(name: &str) -> String {
    let flat: String = name.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    flat.trim().chars().take(MAX_NAME).collect::<String>().trim_end().to_string()
}

fn parse(text: &str) -> HashMap<String, String> {
    text.lines()
        .filter_map(|line| line.split_once('\t'))
        .map(|(id, name)| (id.to_string(), cleaned(name)))
        .filter(|(id, name)| plain_id(id) && !name.is_empty())
        .take(MAX_NAMES)
        .collect()
}

fn render(names: &HashMap<String, String>) -> String {
    let mut lines: Vec<String> = names.iter().map(|(id, name)| format!("{id}\t{name}\n")).collect();
    lines.sort();
    lines.concat()
}

/// The stored names, by service id
pub fn read() -> HashMap<String, String> {
    parse(&std::fs::read_to_string(crate::util::state_dir().join(FILE)).unwrap_or_default())
}

fn reply(codec: Codec, names: HashMap<String, String>) -> Resp {
    codec
        .encode(&pb::ServiceNameSet { names })
        .unwrap_or_else(|err| connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string()))
}

pub async fn get_service_names(codec: Codec, _req: pb::GetServiceNamesRequest) -> Resp {
    reply(codec, read())
}

pub async fn set_service_name(codec: Codec, req: pb::SetServiceNameRequest) -> Resp {
    let id = req.service_id.trim();
    if !plain_id(id) {
        return connect_error(StatusCode::BAD_REQUEST, "invalid_argument", "that is not a service id");
    }
    let mut names = read();
    let name = cleaned(&req.name);
    if name.is_empty() {
        names.remove(id);
    } else if names.len() >= MAX_NAMES && !names.contains_key(id) {
        return connect_error(StatusCode::BAD_REQUEST, "invalid_argument", "too many service names are stored");
    } else {
        names.insert(id.to_string(), name);
    }
    let dir = crate::util::state_dir();
    let written = std::fs::create_dir_all(&dir)
        .and_then(|()| crate::util::write_file_atomic(&dir.join(FILE), render(&names).as_bytes(), 0o644));
    if let Err(err) = written {
        return connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &format!("could not store the name: {err}"));
    }
    reply(codec, read())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_id_is_plain_and_short() {
        assert!(plain_id("vaultwarden") && plain_id("docker-mailserver") && plain_id("a.b_c"));
        assert!(!plain_id("") && !plain_id("../etc") && !plain_id("two words") && !plain_id(&"x".repeat(65)));
    }

    #[test]
    fn a_name_is_one_trimmed_line_of_sixty_characters() {
        assert_eq!(cleaned("  Passwords \n"), "Passwords");
        assert_eq!(cleaned("My\tvault"), "My vault");
        assert_eq!(cleaned(&"я".repeat(80)).chars().count(), 60);
        assert_eq!(cleaned(" \n\t "), "");
    }

    #[test]
    fn stored_text_reads_back_and_drops_what_is_not_a_name() {
        let mut names = HashMap::new();
        names.insert("vaultwarden".to_string(), "Passwords".to_string());
        names.insert("nextcloud".to_string(), "Family files".to_string());
        let text = render(&names);
        assert_eq!(text, "nextcloud\tFamily files\nvaultwarden\tPasswords\n");
        assert_eq!(parse(&text), names);
        assert!(parse("no tab here\n../etc\tx\nvaultwarden\t   \n").is_empty());
    }
}
