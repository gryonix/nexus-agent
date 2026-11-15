//! Docker networks the engine holds, and removing unused ones

use std::collections::{HashMap, HashSet};

use serde::Deserialize;

use crate::api::{Codec, Resp};
use crate::container_ops::capture;
use crate::pb;

const BUILTIN: [&str; 3] = ["bridge", "host", "none"];

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct Inspected {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Driver")]
    driver: String,
    #[serde(rename = "Scope")]
    scope: String,
    #[serde(rename = "Internal")]
    internal: bool,
    #[serde(rename = "Containers")]
    containers: Option<HashMap<String, serde_json::Value>>,
    #[serde(rename = "Labels")]
    labels: Option<HashMap<String, String>>,
    #[serde(rename = "IPAM")]
    ipam: Ipam,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct Ipam {
    #[serde(rename = "Config")]
    config: Option<Vec<IpamConfig>>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct IpamConfig {
    #[serde(rename = "Subnet")]
    subnet: String,
}

fn network_of(row: &Inspected, managed: &HashSet<String>) -> pb::DockerNetwork {
    let containers = row.containers.as_ref().map_or(0, |all| all.len() as u32);
    let project = row.labels.as_ref().and_then(|labels| labels.get("com.docker.compose.project"));
    let by_label = project.is_some_and(|name| managed.contains(name));
    let by_name = managed.iter().any(|name| row.name.starts_with(&format!("{name}_")));
    let subnet = row.ipam.config.iter().flatten().map(|c| c.subnet.clone()).find(|s| !s.is_empty());
    pb::DockerNetwork {
        id: row.id.chars().take(12).collect(),
        name: row.name.clone(),
        driver: row.driver.clone(),
        scope: row.scope.clone(),
        containers,
        in_use: containers > 0,
        managed: by_label || by_name,
        builtin: BUILTIN.contains(&row.name.as_str()),
        internal: row.internal,
        subnet: subnet.unwrap_or_default(),
    }
}

fn parse(raw: &str, managed: &HashSet<String>) -> Vec<pb::DockerNetwork> {
    let rows: Vec<Inspected> = serde_json::from_str(raw.trim()).unwrap_or_default();
    rows.iter().map(|row| network_of(row, managed)).collect()
}

async fn read_networks(managed: &HashSet<String>) -> Result<Vec<pb::DockerNetwork>, String> {
    let ids = capture("docker", &["network", "ls", "-q"].map(String::from), 60).await?;
    if !ids.success {
        return Err(ids.stderr.trim().to_string());
    }
    let mut args: Vec<String> = vec!["network".into(), "inspect".into()];
    args.extend(ids.stdout.split_whitespace().map(String::from));
    if args.len() == 2 {
        return Ok(Vec::new());
    }
    let out = capture("docker", &args, 60).await?;
    if !out.success {
        return Err(out.stderr.trim().to_string());
    }
    Ok(parse(&out.stdout, managed))
}

pub(crate) fn network_refusal(network: &pb::DockerNetwork) -> Option<&'static str> {
    if network.builtin {
        Some("this network belongs to the engine itself")
    } else if network.in_use {
        Some("a container is still attached to this network")
    } else if network.managed {
        Some("this network belongs to a managed service")
    } else {
        None
    }
}

fn encode<M: prost::Message + serde::Serialize>(codec: Codec, message: &M) -> Resp {
    codec.encode(message).unwrap_or_else(|err| {
        crate::api::connect_error(hyper::StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string())
    })
}

async fn managed_projects(names: &[(String, String)]) -> HashSet<String> {
    match crate::containers::inventory(names).await {
        Ok(inv) => inv.groups.into_iter().filter(|g| !g.service_id.is_empty()).map(|g| g.key).collect(),
        Err(_) => HashSet::new(),
    }
}

pub async fn list_networks(codec: Codec, names: &[(String, String)]) -> Resp {
    let managed = managed_projects(names).await;
    let inventory = match read_networks(&managed).await {
        Ok(networks) => pb::NetworkInventory { networks, unavailable_reason: String::new() },
        Err(why) => pb::NetworkInventory { networks: Vec::new(), unavailable_reason: why },
    };
    encode(codec, &inventory)
}

pub async fn remove_network(codec: Codec, req: pb::RemoveNetworkRequest, names: &[(String, String)]) -> Resp {
    let managed = managed_projects(names).await;
    let refused = |message: &str| pb::DockerRemovalResult { removed: false, message: message.to_string() };
    let outcome = match read_networks(&managed).await {
        Err(why) => refused(&why),
        Ok(all) => match all.into_iter().find(|n| n.name == req.name) {
            None => refused("this host reports no such network"),
            Some(network) => match network_refusal(&network) {
                Some(why) => refused(why),
                None => match capture("docker", &["network".into(), "rm".into(), network.name], 60).await {
                    Ok(out) if out.success => pb::DockerRemovalResult { removed: true, message: String::new() },
                    Ok(out) => refused(out.stderr.trim()),
                    Err(why) => refused(&why),
                },
            },
        },
    };
    encode(codec, &outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    const INSPECT: &str = r#"[
      {"Id":"0123456789abcdef","Name":"bridge","Driver":"bridge","Scope":"local","Internal":false,"Containers":{},"Labels":{},"IPAM":{"Config":[{"Subnet":"172.17.0.0/16"}]}},
      {"Id":"aaa","Name":"mail_default","Driver":"bridge","Scope":"local","Internal":false,"Containers":{},"Labels":{"com.docker.compose.project":"mail"},"IPAM":{"Config":[]}},
      {"Id":"bbb","Name":"leftover","Driver":"bridge","Scope":"local","Internal":true,"Containers":null,"Labels":null,"IPAM":{"Config":null}},
      {"Id":"ccc","Name":"busy","Driver":"bridge","Scope":"local","Internal":false,"Containers":{"x":{}},"Labels":{},"IPAM":{}}]"#;

    #[test]
    fn only_an_unused_strangers_network_may_go() {
        let managed: HashSet<String> = ["mail".to_string()].into();
        let networks = parse(INSPECT, &managed);
        assert_eq!(networks[0].id, "0123456789ab");
        assert_eq!(networks[0].subnet, "172.17.0.0/16");
        assert!(networks[0].builtin && network_refusal(&networks[0]).is_some());
        assert!(networks[1].managed && network_refusal(&networks[1]).is_some());
        assert!(networks[2].internal && network_refusal(&networks[2]).is_none());
        assert!(networks[3].in_use && network_refusal(&networks[3]).is_some());
    }

    #[test]
    fn unreadable_output_is_an_empty_answer() {
        assert!(parse("nope", &HashSet::new()).is_empty());
    }
}
