//! A quiet push with the server's summary, so phones redraw their widgets.

use std::sync::Mutex;
use std::time::Duration;

use serde_json::{json, Value};

use crate::notify::{self, Config};
use crate::pb;

/// A summary at least this old is sent again
const REFRESH_SECS: i64 = 3600;

/// The last steady summary sent, and when
static LAST: Mutex<Option<(String, i64)>> = Mutex::new(None);

/// Sends the summary when it changed or grew stale
pub async fn push(config: &mut Config) {
    if config.channel() != pb::NotifyChannel::Relay || config.server_id.is_empty() {
        return;
    }
    let summary = summary().await;
    let now = notify::now();
    let steady = steady_part(&summary);
    if !due(&steady, now, &LAST.lock().unwrap()) {
        return;
    }
    let body = body(&config.server_id, summary, now);
    if notify::deliver_quiet(config, &body).await == crate::notify_send::Sent::Ok {
        *LAST.lock().unwrap() = Some((steady, now));
    }
}

/// Whether the readings moved or the last push is old
fn due(steady: &str, now: i64, last: &Option<(String, i64)>) -> bool {
    match last {
        Some((sent, at)) => sent != steady || now - at >= REFRESH_SECS,
        None => true,
    }
}

/// The summary without the figures that change every run
fn steady_part(summary: &Value) -> String {
    let mut steady = summary.clone();
    steady.as_object_mut().map(|object| object.remove("metrics"));
    steady.to_string()
}

fn body(server_id: &str, summary: Value, now: i64) -> Vec<u8> {
    let mut data = json!({ "kind": "gnx.widgets", "server_id": server_id, "at": now });
    if let (Some(data), Some(summary)) = (data.as_object_mut(), summary.as_object()) {
        data.extend(summary.clone());
    }
    json!({ "data": data }).to_string().into_bytes()
}

async fn summary() -> Value {
    let (services, security, metrics, vpn) =
        tokio::join!(services(), crate::security::status(), metrics(), crate::vpn_clients::device_counts());
    json!({
        "services": services,
        "security": security_part(&security),
        "backups": backups_part(&crate::backup::read_backup_schedule()),
        "metrics": metrics,
        "vpn": vpn_part(vpn),
    })
}

/// VPN devices per protocol, or null without the panel
fn vpn_part(counts: Option<Vec<(&str, usize)>>) -> Value {
    match counts {
        Some(counts) => Value::Object(counts.into_iter().map(|(id, n)| (id.to_string(), json!(n))).collect()),
        None => Value::Null,
    }
}

async fn services() -> Value {
    let Ok(found) = crate::discover::scan().await else { return Value::Null };
    let ours: Vec<&pb::Service> = found.services.iter().filter(|service| !service.installed_outside).collect();
    let attention = ours.iter().filter(|service| service.status != pb::ServiceStatus::Running as i32).count();
    json!({ "total": ours.len(), "attention": attention })
}

fn security_part(status: &pb::SecurityStatus) -> Value {
    json!({
        "present": status.present,
        "engine": status.engine_running,
        "bouncer": status.bouncer_running,
        "alerts": status.alerts_24h,
        "bans": status.local_bans,
        "blocklist": status.community_blocklist_ips,
    })
}

fn backups_part(policy: &pb::BackupSchedulePolicy) -> Value {
    let (hours, days) = cadence(&policy.schedule);
    json!({
        "on": policy.schedule != "off",
        "every_hours": hours,
        "every_days": days,
        "services": policy.services.len(),
        "retention": policy.retention,
    })
}

/// `every:6h@:15` or `every:1d@04:30` into hours or days
fn cadence(schedule: &str) -> (Option<u32>, Option<u32>) {
    let Some(every) = schedule.strip_prefix("every:") else { return (None, None) };
    let count: String = every.chars().take_while(char::is_ascii_digit).collect();
    let count = count.parse().ok();
    match every.chars().find(|c| !c.is_ascii_digit()) {
        Some('h') => (count, None),
        Some('d') => (None, count),
        _ => (None, None),
    }
}

async fn metrics() -> Value {
    let mut sampler = crate::metrics::Sampler::new();
    tokio::time::sleep(Duration::from_secs(1)).await;
    let sample = sampler.sample();
    let root = sample.mounts.iter().find(|mount| mount.target == "/");
    json!({
        "cpu": sample.cpu_percent,
        "mem_used": sample.mem_used_bytes,
        "mem_total": sample.mem_total_bytes,
        "disk_used": root.map(|mount| mount.used_bytes),
        "disk_total": root.map(|mount| mount.size_bytes),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_push_goes_when_readings_move_or_an_hour_passes() {
        assert!(due("a", 100, &None));
        assert!(!due("a", 100, &Some(("a".into(), 50))));
        assert!(due("b", 100, &Some(("a".into(), 50))));
        assert!(due("a", 50 + REFRESH_SECS, &Some(("a".into(), 50))));
    }

    #[test]
    fn load_figures_alone_do_not_send_again() {
        let one = json!({ "services": { "total": 3 }, "metrics": { "cpu": 10.0 } });
        let two = json!({ "services": { "total": 3 }, "metrics": { "cpu": 80.0 } });
        assert_eq!(steady_part(&one), steady_part(&two));
    }

    #[test]
    fn the_schedule_reads_as_hours_or_days() {
        assert_eq!(cadence("every:6h@:15"), (Some(6), None));
        assert_eq!(cadence("every:1d@04:30"), (None, Some(1)));
        assert_eq!(cadence("off"), (None, None));
    }

    #[test]
    fn vpn_devices_are_counted_per_protocol() {
        let part = vpn_part(Some(vec![("wireguard-vpn", 3), ("amnezia-wg", 0)]));
        assert_eq!(part, json!({ "wireguard-vpn": 3, "amnezia-wg": 0 }));
        assert!(vpn_part(None).is_null(), "a server without the panel sends nothing");
    }

    #[test]
    fn the_event_has_no_words_and_carries_the_summary() {
        let body: Value = serde_json::from_slice(&body("srv", json!({ "services": { "total": 2 } }), 7)).unwrap();
        assert!(body["title"].is_null() && body["loc_key"].is_null(), "the relay sends it quietly");
        assert_eq!(body["data"]["kind"], "gnx.widgets");
        assert_eq!(body["data"]["services"]["total"], 2);
        assert_eq!(body["data"]["at"], 7);
    }
}
