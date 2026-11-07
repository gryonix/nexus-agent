//! Images and volumes the engine holds, and removing the unused ones

use std::collections::HashSet;

use serde::Deserialize;

use crate::api::{Codec, Resp};
use crate::container_ops::capture;
use crate::pb;

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct DfImage {
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "Repository")]
    repository: String,
    #[serde(rename = "Tag")]
    tag: String,
    #[serde(rename = "Size")]
    size: String,
    #[serde(rename = "Containers")]
    containers: String,
    #[serde(rename = "CreatedSince")]
    created_since: String,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct DfVolume {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Driver")]
    driver: String,
    #[serde(rename = "Size")]
    size: String,
    #[serde(rename = "Links")]
    links: String,
    #[serde(rename = "Labels")]
    labels: String,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct Df {
    #[serde(rename = "Images")]
    images: Vec<DfImage>,
    #[serde(rename = "Volumes")]
    volumes: Vec<DfVolume>,
}

pub(crate) fn parse_size(text: &str) -> u64 {
    let text = text.trim();
    let split = text.find(|c: char| c.is_ascii_alphabetic()).unwrap_or(text.len());
    let Ok(number) = text[..split].trim().parse::<f64>() else {
        return 0;
    };
    let factor = match text[split..].to_ascii_lowercase().as_str() {
        "kb" => 1e3,
        "mb" => 1e6,
        "gb" => 1e9,
        "tb" => 1e12,
        _ => 1.0,
    };
    (number * factor) as u64
}

fn parse_df(raw: &str) -> Df {
    serde_json::from_str(raw.trim()).unwrap_or_default()
}

fn count(text: &str) -> u32 {
    text.trim().parse().unwrap_or(0)
}

fn image_of(row: &DfImage) -> pb::DockerImage {
    let tagged = !row.repository.is_empty() && row.repository != "<none>" && row.tag != "<none>";
    let containers = count(&row.containers);
    pb::DockerImage {
        id: row.id.clone(),
        repository: row.repository.clone(),
        tag: row.tag.clone(),
        size_bytes: parse_size(&row.size),
        containers,
        in_use: containers > 0,
        created_since: row.created_since.clone(),
        reference: if tagged {
            format!("{}:{}", row.repository, row.tag)
        } else {
            row.id.clone()
        },
    }
}

fn compose_project(labels: &str) -> Option<&str> {
    labels
        .split(',')
        .find_map(|pair| pair.strip_prefix("com.docker.compose.project="))
}

fn volume_of(row: &DfVolume, managed_projects: &HashSet<String>) -> pb::DockerVolume {
    let containers = count(&row.links);
    let by_label = compose_project(&row.labels).is_some_and(|p| managed_projects.contains(p));
    let by_name = managed_projects
        .iter()
        .any(|project| row.name.starts_with(&format!("{project}_")));
    pb::DockerVolume {
        name: row.name.clone(),
        driver: row.driver.clone(),
        size_bytes: parse_size(&row.size),
        containers,
        in_use: containers > 0,
        managed: by_label || by_name,
    }
}

async fn read_df() -> Result<Df, String> {
    let args = ["system", "df", "-v", "--format", "{{json .}}"].map(String::from);
    let out = capture("docker", &args, 60).await?;
    if !out.success {
        return Err(out.stderr.trim().to_string());
    }
    Ok(parse_df(&out.stdout))
}

async fn managed_projects(names: &[(String, String)]) -> HashSet<String> {
    match crate::containers::inventory(names).await {
        Ok(inv) => inv
            .groups
            .into_iter()
            .filter(|g| !g.service_id.is_empty())
            .map(|g| g.key)
            .collect(),
        Err(_) => HashSet::new(),
    }
}

fn images_from(df: &Df) -> Vec<pb::DockerImage> {
    df.images.iter().map(image_of).collect()
}

fn volumes_from(df: &Df, managed: &HashSet<String>) -> Vec<pb::DockerVolume> {
    df.volumes.iter().map(|v| volume_of(v, managed)).collect()
}

fn encode<M: prost::Message + serde::Serialize>(codec: Codec, message: &M) -> Resp {
    codec.encode(message).unwrap_or_else(|err| {
        crate::api::connect_error(hyper::StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string())
    })
}

pub async fn list_images(codec: Codec) -> Resp {
    let inventory = match read_df().await {
        Ok(df) => pb::ImageInventory { images: images_from(&df), unavailable_reason: String::new() },
        Err(why) => pb::ImageInventory { images: Vec::new(), unavailable_reason: why },
    };
    encode(codec, &inventory)
}

pub async fn list_volumes(codec: Codec, names: &[(String, String)]) -> Resp {
    let managed = managed_projects(names).await;
    let inventory = match read_df().await {
        Ok(df) => pb::VolumeInventory { volumes: volumes_from(&df, &managed), unavailable_reason: String::new() },
        Err(why) => pb::VolumeInventory { volumes: Vec::new(), unavailable_reason: why },
    };
    encode(codec, &inventory)
}

pub(crate) fn image_refusal(image: &pb::DockerImage) -> Option<&'static str> {
    image.in_use.then_some("a container still uses this image")
}

pub(crate) fn volume_refusal(volume: &pb::DockerVolume) -> Option<&'static str> {
    if volume.in_use {
        Some("a container still uses this volume")
    } else if volume.managed {
        Some("this volume belongs to a managed service")
    } else {
        None
    }
}

async fn docker_remove(args: Vec<String>) -> Result<(), String> {
    let out = capture("docker", &args, 120).await?;
    if out.success {
        Ok(())
    } else {
        Err(out.stderr.trim().to_string())
    }
}

fn result(removed: bool, message: &str) -> pb::DockerRemovalResult {
    pb::DockerRemovalResult { removed, message: message.to_string() }
}

pub async fn remove_image(codec: Codec, req: pb::RemoveImageRequest) -> Resp {
    let outcome = match read_df().await {
        Err(why) => result(false, &why),
        Ok(df) => match images_from(&df).into_iter().find(|i| i.reference == req.reference) {
            None => result(false, "this host reports no such image"),
            Some(image) => match image_refusal(&image) {
                Some(why) => result(false, why),
                None => match docker_remove(vec!["image".into(), "rm".into(), image.reference]).await {
                    Ok(()) => result(true, ""),
                    Err(why) => result(false, &why),
                },
            },
        },
    };
    encode(codec, &outcome)
}

pub async fn remove_volume(codec: Codec, req: pb::RemoveVolumeRequest, names: &[(String, String)]) -> Resp {
    let managed = managed_projects(names).await;
    let outcome = match read_df().await {
        Err(why) => result(false, &why),
        Ok(df) => match volumes_from(&df, &managed).into_iter().find(|v| v.name == req.name) {
            None => result(false, "this host reports no such volume"),
            Some(volume) => match volume_refusal(&volume) {
                Some(why) => result(false, why),
                None => match docker_remove(vec!["volume".into(), "rm".into(), volume.name]).await {
                    Ok(()) => result(true, ""),
                    Err(why) => result(false, &why),
                },
            },
        },
    };
    encode(codec, &outcome)
}

pub async fn prune_unused(codec: Codec, req: pb::PruneUnusedRequest, names: &[(String, String)]) -> Resp {
    let managed = managed_projects(names).await;
    let mut summary = pb::PruneUnusedResult::default();
    match read_df().await {
        Err(why) => summary.failures.push(why),
        Ok(df) => {
            if req.images {
                prune_images(&df, &mut summary).await;
            }
            if req.volumes {
                prune_volumes(&df, &managed, &mut summary).await;
            }
        }
    }
    encode(codec, &summary)
}

async fn prune_images(df: &Df, summary: &mut pb::PruneUnusedResult) {
    for image in images_from(df).into_iter().filter(|i| image_refusal(i).is_none()) {
        match docker_remove(vec!["image".into(), "rm".into(), image.reference.clone()]).await {
            Ok(()) => {
                summary.images_removed += 1;
                summary.reclaimed_bytes += image.size_bytes;
            }
            Err(why) => summary.failures.push(format!("{}: {why}", image.reference)),
        }
    }
}

async fn prune_volumes(df: &Df, managed: &HashSet<String>, summary: &mut pb::PruneUnusedResult) {
    for volume in volumes_from(df, managed).into_iter().filter(|v| volume_refusal(v).is_none()) {
        match docker_remove(vec!["volume".into(), "rm".into(), volume.name.clone()]).await {
            Ok(()) => {
                summary.volumes_removed += 1;
                summary.reclaimed_bytes += volume.size_bytes;
            }
            Err(why) => summary.failures.push(format!("{}: {why}", volume.name)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DF: &str = r#"{"Images":[
      {"ID":"aaa111","Repository":"nginx","Tag":"1.27","Size":"192MB","Containers":"1","CreatedSince":"2 weeks ago"},
      {"ID":"bbb222","Repository":"<none>","Tag":"<none>","Size":"12.5kB","Containers":"0","CreatedSince":"3 months ago"}],
      "Volumes":[
      {"Name":"mail_data","Driver":"local","Size":"1.5GB","Links":"0","Labels":"com.docker.compose.project=mail"},
      {"Name":"scratch","Driver":"local","Size":"0B","Links":"0","Labels":""},
      {"Name":"busy","Driver":"local","Size":"3MB","Links":"2","Labels":""}]}"#;

    #[test]
    fn sizes_read_in_decimal_units() {
        assert_eq!(parse_size("1.5GB"), 1_500_000_000);
        assert_eq!(parse_size("12.5kB"), 12_500);
        assert_eq!(parse_size("0B"), 0);
        assert_eq!(parse_size("junk"), 0);
    }

    #[test]
    fn untagged_images_are_named_by_id_and_use_is_a_flag() {
        let images = images_from(&parse_df(DF));
        assert_eq!(images[0].reference, "nginx:1.27");
        assert!(images[0].in_use);
        assert_eq!(images[1].reference, "bbb222");
        assert!(!images[1].in_use);
        assert!(image_refusal(&images[0]).is_some());
        assert!(image_refusal(&images[1]).is_none());
    }

    #[test]
    fn a_managed_services_volume_is_never_removable() {
        let managed: HashSet<String> = ["mail".to_string()].into();
        let volumes = volumes_from(&parse_df(DF), &managed);
        assert!(volumes[0].managed);
        assert!(volume_refusal(&volumes[0]).is_some());
        assert!(volume_refusal(&volumes[1]).is_none());
        assert!(volume_refusal(&volumes[2]).is_some());
    }

    #[test]
    fn a_volume_named_after_a_managed_project_counts_as_managed() {
        let managed: HashSet<String> = ["vault".to_string()].into();
        let row = DfVolume { name: "vault_data".into(), ..Default::default() };
        assert!(volume_of(&row, &managed).managed);
    }

    #[test]
    fn unreadable_output_is_an_empty_answer() {
        assert!(images_from(&parse_df("not json")).is_empty());
    }
}
