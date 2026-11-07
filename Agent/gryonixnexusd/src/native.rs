//! Services that run as systemd units instead of containers.

use std::path::Path;

use tokio::process::Command;

use crate::install::{odio, uxplay};
use crate::pb;

/// One service the agent reads and drives through systemd
pub struct Native {
    pub id: &'static str,
    pub display: &'static str,
    marker: &'static str,
}

pub const ALL: &[Native] = &[
    Native { id: uxplay::SERVICE_ID, display: "AirPlay screen", marker: uxplay::UNIT_PATH },
    Native { id: odio::SERVICE_ID, display: "Audio hub (odio)", marker: odio::CONTROL_PATH },
];

pub fn find(id: &str) -> Option<&'static Native> {
    ALL.iter().find(|native| native.id == id)
}

pub const PROJECT_PREFIX: &str = "native:";

impl Native {
    pub fn installed(&self) -> bool {
        Path::new(self.marker).exists()
    }

    fn command(&self, verb: &str) -> (String, Vec<String>) {
        let unit = format!("{}.service", uxplay::UNIT);
        match (self.id, verb) {
            ("uxplay", "status") => ("systemctl".into(), ["show", &unit, "--property=Id", "--property=LoadState", "--property=ActiveState"].map(String::from).to_vec()),
            ("uxplay", "logs") => ("journalctl".into(), ["-u", &unit, "-n", "500", "--no-pager", "-o", "short-iso"].map(String::from).to_vec()),
            ("uxplay", verb) => ("systemctl".into(), vec![verb.to_string(), unit]),
            (_, verb) => (odio::CONTROL_PATH.into(), vec![verb.to_string()]),
        }
    }

    pub async fn run(&self, verb: &str) -> Result<String, String> {
        let (program, args) = self.command(verb);
        let output = Command::new(&program).args(&args).output().await.map_err(|err| format!("could not run {program}: {err}"))?;
        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
        }
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    pub async fn containers(&self) -> Vec<pb::Container> {
        match self.run("status").await {
            Ok(text) => parse_show(&text),
            Err(_) => Vec::new(),
        }
    }

    pub async fn snapshot(&self) -> Option<pb::Service> {
        if !self.installed() {
            return None;
        }
        let containers = self.containers().await;
        let status = crate::discover::status_from_containers(&containers).unwrap_or(pb::ServiceStatus::Stopped);
        Some(pb::Service {
            id: self.id.to_string(),
            display_name: self.display.to_string(),
            status: status as i32,
            version: if self.id == "odio" { odio::VERSION.to_string() } else { String::new() },
            containers,
            installed_outside: false,
        })
    }
}

/// `systemctl show` blocks into one container row per loaded unit
pub fn parse_show(text: &str) -> Vec<pb::Container> {
    text.split("\n\n")
        .filter_map(|block| {
            let field = |key: &str| block.lines().find_map(|line| line.strip_prefix(&format!("{key}=")));
            let name = field("Id")?;
            if field("LoadState") == Some("not-found") {
                return None;
            }
            let state = match field("ActiveState").unwrap_or("") {
                "active" | "reloading" => "running",
                "failed" => "dead",
                _ => "exited",
            };
            Some(pb::Container { name: name.to_string(), image: String::new(), health: String::new(), state: state.to_string(), ports: String::new() })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_loaded_units_become_rows() {
        let rows = parse_show("Id=odio-api.service\nLoadState=loaded\nActiveState=active\n\nId=mympd.service\nLoadState=not-found\nActiveState=inactive\n\nId=mpd.service\nLoadState=loaded\nActiveState=failed\n");
        assert_eq!(rows.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(), ["odio-api.service", "mpd.service"]);
        assert_eq!(rows.iter().map(|r| r.state.as_str()).collect::<Vec<_>>(), ["running", "dead"]);
    }

    #[test]
    fn each_service_is_driven_the_way_the_app_drives_it() {
        let screen = find("uxplay").unwrap();
        assert_eq!(screen.command("restart"), ("systemctl".to_string(), vec!["restart".to_string(), "gryonixnexus-uxplay.service".to_string()]));
        let hub = find("odio").unwrap();
        assert_eq!(hub.command("status"), (odio::CONTROL_PATH.to_string(), vec!["status".to_string()]));
        assert!(find("vaultwarden").is_none());
    }
}
