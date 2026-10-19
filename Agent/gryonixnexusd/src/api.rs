//! Connect-RPC serving over the local Unix socket

use std::convert::Infallible;
use std::pin::Pin;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Frame, Incoming};
use hyper::header::CONTENT_TYPE;
use hyper::{Request, Response, StatusCode};
use prost::Message;
use tokio::io::AsyncBufReadExt;
use tokio::sync::mpsc::Sender;

use crate::install::execute as install;
use crate::state::Store;
use crate::util::now_millis;
use crate::vpn_clients;
use crate::ddns;
use crate::mesh;
use crate::notify;
use crate::{
    agent_update, backup, backup_drive, container_backup, container_backup_run, container_removal, container_update, container_schedule, containers, control, discover, dkim, history, lockdown, mailbox,
    metrics, models, mods, pb, restore, security, serial,
    uninstall, update,
};

pub type Resp = Response<BoxBody<Bytes, Infallible>>;

const METRICS_DEFAULT_INTERVAL: u64 = 2;
const METRICS_MAX_INTERVAL: u64 = 60;
const LOGS_DEFAULT_TAIL: u32 = 200;
const LOGS_MAX_TAIL: u32 = 5000;

pub async fn serve(req: Request<Incoming>, store: Arc<Mutex<Store>>) -> Result<Resp, Infallible> {
    Ok(route(req, store).await.unwrap_or_else(|err| {
        connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string())
    }))
}

async fn route(req: Request<Incoming>, store: Arc<Mutex<Store>>) -> anyhow::Result<Resp> {
    let (parts, body) = req.into_parts();
    let path = parts.uri.path().to_string();
    let codec = Codec::from_content_type(parts.headers.get(CONTENT_TYPE).and_then(|v| v.to_str().ok()));
    let bytes = body.collect().await?.to_bytes();

    if let Some(refusal) = session_refusal(&parts, &path, &store)? {
        return Ok(refusal);
    }

    if let Some(resp) = route_control(&path, codec, bytes.clone(), store.clone()).await? {
        return Ok(resp);
    }
    if let Some(resp) = route_containers(&path, codec, bytes.clone(), store.clone()).await? {
        return Ok(resp);
    }
    if let Some(resp) = route_containers_2(&path, codec, bytes.clone(), store.clone()).await? {
        return Ok(resp);
    }
    if let Some(resp) = route_containers_3(&path, codec, bytes.clone(), store.clone()).await? {
        return Ok(resp);
    }
    if let Some(resp) = route_pairing(&path, codec, bytes.clone(), store.clone()).await? {
        return Ok(resp);
    }
    if let Some(resp) = route_vault(&path, codec, bytes.clone(), store.clone()).await? {
        return Ok(resp);
    }
    if let Some(resp) = route_update(&path, codec, bytes.clone()).await? {
        return Ok(resp);
    }
    if let Some(resp) = route_security(&path, codec, bytes.clone()).await? {
        return Ok(resp);
    }
    if let Some(resp) = route_uninstall(&path, codec, bytes.clone(), store.clone()).await? {
        return Ok(resp);
    }
    if let Some(resp) = route_install(&path, codec, bytes.clone(), store.clone()).await? {
        return Ok(resp);
    }
    if let Some(resp) = route_models(&path, codec, bytes.clone(), store.clone()).await? {
        return Ok(resp);
    }
    if let Some(resp) = route_vpn(&path, codec, bytes.clone()).await? {
        return Ok(resp);
    }
    Ok(connect_error(StatusCode::NOT_FOUND, "not_found", "unknown method"))
}

async fn route_control(path: &str, codec: Codec, bytes: Bytes, store: Arc<Mutex<Store>>) -> anyhow::Result<Option<Resp>> {
    match path {
        "/gryonixnexusd.v1.Control/GetState" => ({
            let _req: pb::GetStateRequest = codec.decode(&bytes)?;
            let mut state = lock(&store).snapshot()?;
            state.home_doors = install::home_network_doors()
                .into_iter()
                .map(|door| pb::HomeNetworkDoor { service_id: door.owner, port: door.port as u32 })
                .collect();
            state.wake_on_lan = crate::wake::current();
            state.mesh_address = crate::mesh::own_address().await.unwrap_or_default();
            codec.encode(&state)
        }).map(Some),
        "/gryonixnexusd.v1.Control/Discover" => ({
            let _req: pb::DiscoverRequest = codec.decode(&bytes)?;
            let result = discover::scan().await?;
            // Persist what adoption found so GetState reflects it afterwards.
            lock(&store).record_discovery(&result.services)?;
            codec.encode(&result)
        }).map(Some),
        "/gryonixnexusd.v1.Control/ServiceStatus" => ({
            let req: pb::ServiceStatusRequest = codec.decode(&bytes)?;
            Ok(control::service_status(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Control/ControlService" => ({
            let req: pb::ControlServiceRequest = codec.decode_enveloped(&bytes)?;
            Ok(control::control_service(codec, req, store).await)
        }).map(Some),
        "/gryonixnexusd.v1.Control/MetricsHistory" => ({
            let req: pb::MetricsHistoryRequest = codec.decode(&bytes)?;
            Ok(history::metrics_history(codec, req))
        }).map(Some),
        "/gryonixnexusd.v1.Control/ListSerialDevices" => ({
            let _req: pb::ListSerialDevicesRequest = codec.decode(&bytes)?;
            codec.encode(&serial::list())
        }).map(Some),
        "/gryonixnexusd.v1.Control/HostMetrics" => ({
            let req: pb::HostMetricsRequest = codec.decode_enveloped(&bytes)?;
            Ok(host_metrics_stream(codec, req))
        }).map(Some),
        "/gryonixnexusd.v1.Control/Logs" => ({
            let req: pb::LogsRequest = codec.decode_enveloped(&bytes)?;
            logs_stream(codec, req).await
        }).map(Some),
        "/gryonixnexusd.v1.Containers/ListContainers" => ({
            let _req: pb::ListContainersRequest = codec.decode(&bytes)?;
            let names = lock(&store).container_names()?;
            let inventory = containers::inventory(&names).await?;
            codec.encode(&inventory)
        }).map(Some),
        _ => Ok(None),
    }
}

async fn route_containers(path: &str, codec: Codec, bytes: Bytes, store: Arc<Mutex<Store>>) -> anyhow::Result<Option<Resp>> {
    match path {
        "/gryonixnexusd.v1.Containers/SetContainerGroupName" => ({
            let req: pb::SetContainerGroupNameRequest = codec.decode(&bytes)?;
            let name = match containers::sanitise_name(&req.display_name) {
                Ok(name) => name,
                Err(why) => {
                    return Ok(Some(connect_error(
                        StatusCode::BAD_REQUEST,
                        "invalid_argument",
                        &why,
                    )))
                }
            };
            let existing = lock(&store).container_names()?;
            let inventory = containers::inventory(&existing).await?;
            let Some(group) = containers::resolve(&inventory, &req.key) else {
                return Ok(Some(connect_error(
                    StatusCode::NOT_FOUND,
                    "not_found",
                    "this host reports no container group with that key",
                )));
            };
            let key = group.key.clone();
            lock(&store).set_container_name(&key, &name)?;
            let names = lock(&store).container_names()?;
            let refreshed = containers::inventory(&names).await?;
            codec.encode(&refreshed)
        }).map(Some),
        "/gryonixnexusd.v1.Containers/ControlContainerGroup" => ({
            let req: pb::ControlContainerGroupRequest = codec.decode_enveloped(&bytes)?;
            let names = lock(&store).container_names()?;
            Ok(containers::control_group(codec, req, names).await)
        }).map(Some),
        "/gryonixnexusd.v1.Containers/ContainerGroupLogs" => ({
            let req: pb::ContainerGroupLogsRequest = codec.decode_enveloped(&bytes)?;
            let names = lock(&store).container_names()?;
            match containers::containers_of_group(&req.key, &names).await {
                Err(refusal) => Ok(refusal.response()),
                Ok((label, list)) => Ok(tail_all(codec, list, label, req.tail)),
            }
        }).map(Some),
        "/gryonixnexusd.v1.Containers/InspectContainer" => ({
            let req: pb::InspectContainerRequest = codec.decode(&bytes)?;
            let names = lock(&store).container_names()?;
            Ok(containers::inspect(codec, req, &names).await)
        }).map(Some),
        _ => Ok(None),
    }
}

async fn route_containers_2(path: &str, codec: Codec, bytes: Bytes, store: Arc<Mutex<Store>>) -> anyhow::Result<Option<Resp>> {
    match path {
        "/gryonixnexusd.v1.Containers/GetContainerBackupPlan" => ({
            let req: pb::GetContainerBackupPlanRequest = codec.decode(&bytes)?;
            let names = lock(&store).container_names()?;
            match containers::details_of_group(&req.key, &names).await {
                Err(refusal) => Ok(refusal.response()),
                Ok((group, details)) => {
                    let stored = lock(&store).container_backup_plan(&group.key)?;
                    let plan = container_backup::effective(&group.key, &details, stored);
                    codec.encode(&plan)
                }
            }
        }).map(Some),
        "/gryonixnexusd.v1.Containers/SetContainerBackupPlan" => ({
            let req: pb::SetContainerBackupPlanRequest = codec.decode(&bytes)?;
            let names = lock(&store).container_names()?;
            match containers::details_of_group(&req.key, &names).await {
                Err(refusal) => Ok(refusal.response()),
                Ok((group, details)) => {
                    let sanitised = match req.plan {
                        Some(plan) => match container_backup::sanitise(plan, &group, &details) {
                            Ok(plan) => Some(plan),
                            Err(why) => {
                                return Ok(Some(connect_error(
                                    StatusCode::BAD_REQUEST,
                                    "invalid_argument",
                                    &why,
                                )))
                            }
                        },
                        None => None,
                    };
                    store
                        .lock()
                        .unwrap()
                        .set_container_backup_plan(&group.key, sanitised.as_ref())?;
                    let stored = lock(&store).container_backup_plan(&group.key)?;
                    let plan = container_backup::effective(&group.key, &details, stored);
                    codec.encode(&plan)
                }
            }
        }).map(Some),
        "/gryonixnexusd.v1.Containers/RunContainerGroupBackup" => ({
            let req: pb::RunContainerGroupBackupRequest = codec.decode_enveloped(&bytes)?;
            let names = lock(&store).container_names()?;
            let stored = lock(&store).container_backup_plan(&req.key)?;
            Ok(container_backup_run::run(codec, req, names, stored).await)
        }).map(Some),
        // What removal would delete, before anything is deleted.
        "/gryonixnexusd.v1.Containers/PreviewContainerGroupRemoval" => ({
            let req: pb::PreviewContainerGroupRemovalRequest = codec.decode(&bytes)?;
            let names = lock(&store).container_names()?;
            Ok(container_removal::preview(codec, req, &names).await)
        }).map(Some),
        _ => Ok(None),
    }
}

async fn route_containers_3(path: &str, codec: Codec, bytes: Bytes, store: Arc<Mutex<Store>>) -> anyhow::Result<Option<Resp>> {
    match path {
        "/gryonixnexusd.v1.Containers/RemoveContainerGroup" => ({
            let req: pb::RemoveContainerGroupRequest = codec.decode_enveloped(&bytes)?;
            let names = lock(&store).container_names()?;
            let (kept, key) = (store.clone(), req.key.clone());
            let forget = move || {
                let _ = lock(&kept).forget_container_backup_run(&key);
            };
            Ok(container_removal::remove(codec, req, names, forget).await)
        }).map(Some),
        "/gryonixnexusd.v1.Containers/UpdateContainerGroup" => ({
            let req: pb::UpdateContainerGroupRequest = codec.decode_enveloped(&bytes)?;
            let names = lock(&store).container_names()?;
            let stored = lock(&store).container_backup_plan(&req.key)?;
            Ok(container_update::run(codec, req, names, stored).await)
        }).map(Some),
        "/gryonixnexusd.v1.Containers/GetContainerBackupSchedule" => ({
            let req: pb::GetContainerBackupScheduleRequest = codec.decode(&bytes)?;
            let names = lock(&store).container_names()?;
            match containers::details_of_group(&req.key, &names).await {
                Err(refusal) => Ok(refusal.response()),
                Ok((group, _)) => codec.encode(&container_schedule::schedule_of(&store, &group.key)),
            }
        }).map(Some),
        "/gryonixnexusd.v1.Containers/ListContainerGroupBackups" => ({
            let req: pb::ListContainerGroupBackupsRequest = codec.decode(&bytes)?;
            let names = lock(&store).container_names()?;
            match containers::details_of_group(&req.key, &names).await {
                Err(refusal) => Ok(refusal.response()),
                Ok((group, _)) => match container_backup_run::list(&group.key) {
                    Ok(list) => codec.encode(&list),
                    Err(refusal) => Ok(refusal),
                },
            }
        }).map(Some),
        "/gryonixnexusd.v1.Containers/SetContainerBackupSchedule" => ({
            let req: pb::SetContainerBackupScheduleRequest = codec.decode(&bytes)?;
            let names = lock(&store).container_names()?;
            if !req.schedule.is_empty() && !container_schedule::is_valid(&req.schedule) {
                return Ok(Some(connect_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_argument",
                    "schedule must be daily, weekly or monthly, or empty to switch it off",
                )));
            }
            match containers::details_of_group(&req.key, &names).await {
                Err(refusal) => Ok(refusal.response()),
                Ok((group, _)) => {
                    lock(&store).set_container_backup_schedule(&group.key, &req.schedule)?;
                    codec.encode(&container_schedule::schedule_of(&store, &group.key))
                }
            }
        }).map(Some),
        _ => Ok(None),
    }
}

async fn route_pairing(path: &str, codec: Codec, bytes: Bytes, store: Arc<Mutex<Store>>) -> anyhow::Result<Option<Resp>> {
    match path {
        "/gryonixnexusd.v1.Pairing/Pair" => ({
            let req: pb::PairRequest = codec.decode(&bytes)?;
            let device = {
                let store = lock(&store);
                if !store.pairing_code_valid(&req.code)? {
                    return Ok(Some(connect_error(
                        StatusCode::UNAUTHORIZED,
                        "permission_denied",
                        "invalid or expired pairing code",
                    )));
                }
                let device = store.pair(&req.device_public_key, &req.label, &req.device_uid)?;
                store.consume_pairing_code(&req.code)?;
                device
            };
            let ssh_key_authorized = crate::device_keys::on_pair(&req).await;
            codec.encode(&pb::PairResponse { device: Some(device), ssh_key_authorized })
        }).map(Some),
        "/gryonixnexusd.v1.Pairing/ListDevices" => ({
            let _req: pb::ListDevicesRequest = codec.decode(&bytes)?;
            let devices = lock(&store).list_devices()?;
            codec.encode(&pb::DeviceList { devices })
        }).map(Some),
        "/gryonixnexusd.v1.Pairing/Revoke" => ({
            let req: pb::RevokeRequest = codec.decode(&bytes)?;
            let key = lock(&store).device(&req.device_id)?.map(|d| d.public_key);
            let revoked = lock(&store).revoke(&req.device_id)?;
            let ssh_key_removed = match key {
                Some(key) if revoked => crate::device_keys::on_revoke(&key).await,
                _ => false,
            };
            codec.encode(&pb::RevokeResponse { revoked, ssh_key_removed })
        }).map(Some),
        "/gryonixnexusd.v1.Pairing/CreateTransfer" => ({
            let req: pb::CreateTransferRequest = codec.decode(&bytes)?;
            match crate::device_keys::mint_transfer(req.valid_minutes, crate::util::now_millis() / 1000).await {
                Ok(t) => codec.encode(&pb::CreateTransferResponse {
                    transfer_id: t.id,
                    private_key_seed: t.seed.to_vec(),
                    expires_at: t.expires_at_ms,
                }),
                Err(message) => Ok(connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &message)),
            }
        }).map(Some),
        "/gryonixnexusd.v1.Pairing/GetSessionPolicy" => ({
            let _req: pb::GetSessionPolicyRequest = codec.decode(&bytes)?;
            let policy = lock(&store).session_policy()?;
            codec.encode(&policy)
        }).map(Some),
        "/gryonixnexusd.v1.Pairing/SetSessionPolicy" => ({
            let req: pb::SetSessionPolicyRequest = codec.decode(&bytes)?;
            match lock(&store).set_session_policy(req.auto_logout_months) {
                Ok(policy) => codec.encode(&policy),
                Err(err) => Ok(connect_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_argument",
                    &err.to_string(),
                )),
            }
        }).map(Some),
        "/gryonixnexusd.v1.Vault/GetVault" => ({
            let _req: pb::GetVaultRequest = codec.decode(&bytes)?;
            let snapshot = lock(&store).vault_snapshot()?;
            codec.encode(&snapshot)
        }).map(Some),
        _ => Ok(None),
    }
}

async fn route_vault(path: &str, codec: Codec, bytes: Bytes, store: Arc<Mutex<Store>>) -> anyhow::Result<Option<Resp>> {
    match path {
        "/gryonixnexusd.v1.Vault/PutVaultEntries" => ({
            let req: pb::PutVaultEntriesRequest = codec.decode(&bytes)?;
            let written = lock(&store).put_vault_entries(&req.entries);
            match written {
                Ok(snapshot) => {
                    reconcile_off_the_worker(&snapshot).await;
                    codec.encode(&snapshot)
                }
                Err(err) => Ok(connect_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_argument",
                    &err.to_string(),
                )),
            }
        }).map(Some),
        "/gryonixnexusd.v1.Vault/DeleteVaultEntry" => ({
            let req: pb::DeleteVaultEntryRequest = codec.decode(&bytes)?;
            let snapshot = lock(&store).delete_vault_entry(&req.id, &req.device_uid, req.deleted_at)?;
            reconcile_off_the_worker(&snapshot).await;
            codec.encode(&snapshot)
        }).map(Some),
        "/gryonixnexusd.v1.Backup/ListBackups" => ({
            let req: pb::ListBackupsRequest = codec.decode(&bytes)?;
            Ok(backup::list_backups(codec, req))
        }).map(Some),
        "/gryonixnexusd.v1.Backup/ListAllBackups" => ({
            let _: pb::ListAllBackupsRequest = codec.decode(&bytes)?;
            Ok(backup::list_all_backups(codec))
        }).map(Some),
        "/gryonixnexusd.v1.Backup/EstimateBackup" => ({
            let req: pb::EstimateBackupRequest = codec.decode(&bytes)?;
            Ok(backup::estimate_backup(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Backup/DeleteBackup" => ({
            let req: pb::DeleteBackupRequest = codec.decode(&bytes)?;
            Ok(backup::delete_backup(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Backup/RunBackup" => ({
            let req: pb::RunBackupRequest = codec.decode_enveloped(&bytes)?;
            Ok(backup::run_backup(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Backup/GetBackupSchedule" => ({
            let req: pb::GetBackupScheduleRequest = codec.decode(&bytes)?;
            Ok(backup::get_backup_schedule(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Backup/SetBackupSchedule" => ({
            let req: pb::SetBackupScheduleRequest = codec.decode(&bytes)?;
            Ok(backup::set_backup_schedule(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Backup/SetBackupDestination" => ({
            let req: pb::SetBackupDestinationRequest = codec.decode(&bytes)?;
            Ok(backup::set_backup_destination(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Backup/TestBackupDestination" => ({
            let req: pb::TestBackupDestinationRequest = codec.decode(&bytes)?;
            Ok(backup::test_backup_destination(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Backup/SetBackupDrives" => ({
            let req: pb::SetBackupDrivesRequest = codec.decode(&bytes)?;
            Ok(backup_drive::set_backup_drives(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Backup/FetchDriveBackup" => ({
            let req: pb::FetchDriveBackupRequest = codec.decode(&bytes)?;
            Ok(backup_drive::fetch_drive_backup(codec, req).await)
        }).map(Some),
        _ => Ok(None),
    }
}

async fn route_update(path: &str, codec: Codec, bytes: Bytes) -> anyhow::Result<Option<Resp>> {
    match path {
        "/gryonixnexusd.v1.Update/CheckUpdates" => ({
            let req: pb::CheckUpdatesRequest = codec.decode(&bytes)?;
            Ok(update::check_updates(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Update/GetUpdatePolicy" => ({
            let req: pb::GetUpdatePolicyRequest = codec.decode(&bytes)?;
            Ok(update::get_update_policy(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Update/SetUpdateSchedule" => ({
            let req: pb::SetUpdateScheduleRequest = codec.decode(&bytes)?;
            Ok(update::set_update_schedule(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Update/RunUpdate" => ({
            let req: pb::RunUpdateRequest = codec.decode_enveloped(&bytes)?;
            Ok(update::run_update(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.AgentUpdate/GetAgentUpdateStatus" => ({
            let req: pb::GetAgentUpdateStatusRequest = codec.decode(&bytes)?;
            Ok(agent_update::get_agent_update_status(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.AgentUpdate/SetAgentAutoUpdate" => ({
            let req: pb::SetAgentAutoUpdateRequest = codec.decode(&bytes)?;
            Ok(crate::agent_update::set_agent_auto_update(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.AgentUpdate/RemoveAgent" => ({
            let _req: pb::RemoveAgentRequest = codec.decode(&bytes)?;
            Ok(crate::agent_removal::remove(codec).await)
        }).map(Some),
        "/gryonixnexusd.v1.AgentUpdate/ApplyAgentUpdate" => ({
            let req: pb::ApplyAgentUpdateRequest = codec.decode_enveloped(&bytes)?;
            Ok(agent_update::apply_agent_update(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Lockdown/GetLockdown" => ({
            let req: pb::GetLockdownRequest = codec.decode(&bytes)?;
            Ok(lockdown::get_lockdown(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Lockdown/SetLockdown" => ({
            let req: pb::SetLockdownRequest = codec.decode(&bytes)?;
            Ok(lockdown::set_lockdown(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Security/GetSecurityStatus" => ({
            let req: pb::GetSecurityStatusRequest = codec.decode(&bytes)?;
            Ok(security::get_security_status(codec, req).await)
        }).map(Some),
        _ => Ok(None),
    }
}

async fn route_security(path: &str, codec: Codec, bytes: Bytes) -> anyhow::Result<Option<Resp>> {
    match path {
        "/gryonixnexusd.v1.Security/GetSshPasswordState" => ({
            let req: pb::GetSshPasswordStateRequest = codec.decode(&bytes)?;
            Ok(security::get_ssh_password_state(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Security/ControlSecurity" => ({
            let req: pb::ControlSecurityRequest = codec.decode_enveloped(&bytes)?;
            Ok(security::control_security(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Security/GetSecurityDecisions" => ({
            let req: pb::GetSecurityDecisionsRequest = codec.decode(&bytes)?;
            Ok(security::get_security_decisions(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Security/SetSecurityDecision" => ({
            let req: pb::SetSecurityDecisionRequest = codec.decode(&bytes)?;
            Ok(security::set_security_decision(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Security/GetSecurityAllowlist" => ({
            let req: pb::GetSecurityAllowlistRequest = codec.decode(&bytes)?;
            Ok(security::get_security_allowlist(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Security/GetSecurityAutoRules" => ({
            let req: pb::GetSecurityAutoRulesRequest = codec.decode(&bytes)?;
            Ok(security::get_security_auto_rules(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Security/SetSecurityAutoRules" => ({
            let req: pb::SetSecurityAutoRulesRequest = codec.decode(&bytes)?;
            Ok(security::set_security_auto_rules(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Security/SetSecurityAllowlist" => ({
            let req: pb::SetSecurityAllowlistRequest = codec.decode(&bytes)?;
            Ok(security::set_security_allowlist(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Security/SetSshPasswordLogin" => ({
            let req: pb::SetSshPasswordLoginRequest = codec.decode(&bytes)?;
            Ok(security::set_ssh_password_login(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Security/ListSshUsers" => ({
            let req: pb::ListSshUsersRequest = codec.decode(&bytes)?;
            Ok(security::list_ssh_users(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Security/SetSshKeyOnlyUsers" => ({
            let req: pb::SetSshKeyOnlyUsersRequest = codec.decode(&bytes)?;
            Ok(security::set_ssh_key_only_users(codec, req).await)
        }).map(Some),
        _ => Ok(None),
    }
}

async fn route_uninstall(path: &str, codec: Codec, bytes: Bytes, store: Arc<Mutex<Store>>) -> anyhow::Result<Option<Resp>> {
    match path {
        "/gryonixnexusd.v1.Uninstall/RemoveService" => ({
            let req: pb::RemoveServiceRequest = codec.decode_enveloped(&bytes)?;
            Ok(uninstall::remove_service(codec, req, store).await)
        }).map(Some),
        "/gryonixnexusd.v1.Restore/RunRestore" => ({
            let req: pb::RunRestoreRequest = codec.decode_enveloped(&bytes)?;
            Ok(restore::run_restore(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Move/PrepareMoveSend" => ({
            let req: pb::PrepareMoveSendRequest = codec.decode(&bytes)?;
            Ok(crate::move_transfer::prepare_send(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Move/PrepareMoveReceive" => ({
            let req: pb::PrepareMoveReceiveRequest = codec.decode(&bytes)?;
            Ok(crate::move_transfer::prepare_receive(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Move/SendMoveData" => ({
            let req: pb::SendMoveDataRequest = codec.decode_enveloped(&bytes)?;
            Ok(crate::move_run::send_data(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Move/AcceptMoveData" => ({
            let req: pb::AcceptMoveDataRequest = codec.decode_enveloped(&bytes)?;
            Ok(crate::move_run::accept_data(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Move/DiscardMoveTransfer" => ({
            let req: pb::DiscardMoveTransferRequest = codec.decode(&bytes)?;
            Ok(crate::move_transfer::discard(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Move/SetServiceUpstream" => ({
            let req: pb::SetServiceUpstreamRequest = codec.decode(&bytes)?;
            Ok(crate::move_upstream::set_upstream(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Move/ProbeServiceUpstream" => ({
            let req: pb::ProbeServiceUpstreamRequest = codec.decode(&bytes)?;
            Ok(crate::move_upstream::probe_upstream(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Install/InstallService" => ({
            let req: pb::InstallServiceRequest = codec.decode_enveloped(&bytes)?;
            Ok(install::run_install(codec, req, store).await)
        }).map(Some),
        _ => Ok(None),
    }
}

async fn route_install(path: &str, codec: Codec, bytes: Bytes, store: Arc<Mutex<Store>>) -> anyhow::Result<Option<Resp>> {
    match path {
        "/gryonixnexusd.v1.Install/WatchInstall" => ({
            let req: pb::WatchInstallRequest = codec.decode_enveloped(&bytes)?;
            Ok(install::run_watch_install(codec, req, store).await)
        }).map(Some),
        "/gryonixnexusd.v1.Install/StartInstallPlan" => ({
            let req: pb::StartInstallPlanRequest = codec.decode(&bytes)?;
            Ok(crate::install::plan::run_start(codec, req, store).await)
        }).map(Some),
        "/gryonixnexusd.v1.Install/GetInstallPlan" => ({
            let req: pb::GetInstallPlanRequest = codec.decode(&bytes)?;
            Ok(crate::install::plan::run_get(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Install/RefreshCertificates" => ({
            let req: pb::RefreshCertificatesRequest = codec.decode(&bytes)?;
            Ok(install::run_refresh_certificates(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Install/ProvisionHost" => ({
            let req: pb::ProvisionHostRequest = codec.decode(&bytes)?;
            Ok(install::run_provision_host(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Jobs/WatchJob" => ({
            let req: pb::WatchJobRequest = codec.decode_enveloped(&bytes)?;
            Ok(crate::jobs::run_watch_job(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Jobs/ListJobs" => ({
            let req: pb::ListJobsRequest = codec.decode(&bytes)?;
            Ok(crate::jobs::run_list_jobs(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Jobs/CancelJob" => ({
            let req: pb::CancelJobRequest = codec.decode(&bytes)?;
            Ok(crate::jobs::run_cancel_job(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Mesh/ListMeshUsers" => ({
            let req: pb::ListMeshUsersRequest = codec.decode(&bytes)?;
            Ok(mesh::list_users(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Mesh/CreateMeshUser" => ({
            let req: pb::CreateMeshUserRequest = codec.decode(&bytes)?;
            Ok(mesh::create_user(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Mesh/CreateMeshAuthKey" => ({
            let req: pb::CreateMeshAuthKeyRequest = codec.decode(&bytes)?;
            Ok(mesh::create_auth_key(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Mesh/ListMeshNodes" => ({
            let req: pb::ListMeshNodesRequest = codec.decode(&bytes)?;
            Ok(mesh::list_nodes(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Mesh/DeleteMeshNode" => ({
            let req: pb::DeleteMeshNodeRequest = codec.decode(&bytes)?;
            Ok(mesh::delete_node(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Mesh/PublishMeshNames" => ({
            let req: pb::PublishMeshNamesRequest = codec.decode(&bytes)?;
            Ok(mesh::publish_names(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Models/ListModels" => ({
            let req: pb::ListModelsRequest = codec.decode(&bytes)?;
            Ok(models::list(codec, req).await)
        }).map(Some),
        _ => Ok(None),
    }
}

async fn route_models(path: &str, codec: Codec, bytes: Bytes, store: Arc<Mutex<Store>>) -> anyhow::Result<Option<Resp>> {
    match path {
        "/gryonixnexusd.v1.Models/PullModel" => ({
            // Enveloped, like every other streaming verb on this router.
            let req: pb::PullModelRequest = codec.decode_enveloped(&bytes)?;
            Ok(models::pull(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Models/DeleteModel" => ({
            let req: pb::DeleteModelRequest = codec.decode(&bytes)?;
            Ok(models::delete(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Mods/SearchMods" => ({
            let req: pb::SearchModsRequest = codec.decode(&bytes)?;
            Ok(mods::search(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Mods/ModVersions" => ({
            let req: pb::ModVersionsRequest = codec.decode(&bytes)?;
            Ok(mods::versions(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Mods/ListModFiles" => ({
            let req: pb::ListModFilesRequest = codec.decode(&bytes)?;
            Ok(mods::list_files(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Mods/UploadModFile" => ({
            let req: pb::UploadModFileRequest = codec.decode(&bytes)?;
            Ok(mods::upload(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Mods/DeleteModFile" => ({
            let req: pb::DeleteModFileRequest = codec.decode(&bytes)?;
            Ok(mods::delete(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Restore/ListPreRestoreCopies" => ({
            let req: pb::ListPreRestoreCopiesRequest = codec.decode(&bytes)?;
            Ok(crate::pre_restore::list(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Restore/DeletePreRestoreCopy" => ({
            let req: pb::DeletePreRestoreCopyRequest = codec.decode(&bytes)?;
            Ok(crate::pre_restore::delete(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Vaultwarden/GetVaultwardenTwoFactor" => (Ok(crate::vaultwarden_2fa::get(codec).await)).map(Some),
        "/gryonixnexusd.v1.Dns/SetDynamicDNS" => ({
            let req: pb::SetDynamicDnsRequest = codec.decode(&bytes)?;
            Ok(ddns::set(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Dns/GetDynamicDNS" => ({
            let req: pb::GetDynamicDnsRequest = codec.decode(&bytes)?;
            Ok(ddns::get(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Storage/RunStorageTask" => ({
            let req: pb::StorageTaskRequest = codec.decode(&bytes)?;
            Ok(crate::storage_task::run(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Notify/GetNotifySettings" => (Ok(notify::get(codec, store).await)).map(Some),
        "/gryonixnexusd.v1.Notify/SetNotifySettings" => ({
            let req: pb::SetNotifySettingsRequest = codec.decode(&bytes)?;
            Ok(notify::set(codec, store, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Notify/RegisterNotifyDevice" => ({
            let req: pb::RegisterNotifyDeviceRequest = codec.decode(&bytes)?;
            Ok(notify::register_device(codec, store, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Notify/UnregisterNotifyDevice" => ({
            let req: pb::UnregisterNotifyDeviceRequest = codec.decode(&bytes)?;
            Ok(notify::unregister_device(codec, store, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Notify/SendTestNotification" => (Ok(notify::send_test(codec, store).await)).map(Some),
        "/gryonixnexusd.v1.Notify/WatchTunnelActivity" => ({
            let req: pb::WatchTunnelActivityRequest = codec.decode(&bytes)?;
            Ok(notify::watch_tunnel(codec, store, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Notify/WatchLiveActivity" => ({
            let req: pb::WatchLiveActivityRequest = codec.decode(&bytes)?;
            Ok(notify::watch_live(codec, store, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Notify/TestLiveActivity" => ({
            let req: pb::TestLiveActivityRequest = codec.decode(&bytes)?;
            Ok(notify::test_live(codec, store, req).await)
        }).map(Some),
        _ => Ok(None),
    }
}

async fn route_vpn(path: &str, codec: Codec, bytes: Bytes) -> anyhow::Result<Option<Resp>> {
    match path {
        "/gryonixnexusd.v1.Vpn/ListVpnClients" => ({
            let req: pb::ListVpnClientsRequest = codec.decode(&bytes)?;
            Ok(vpn_clients::list_clients(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Vpn/AddVpnClient" => ({
            let req: pb::AddVpnClientRequest = codec.decode(&bytes)?;
            Ok(vpn_clients::add_client(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Vpn/DeleteVpnClient" => ({
            let req: pb::DeleteVpnClientRequest = codec.decode(&bytes)?;
            Ok(vpn_clients::delete_client(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Vpn/GetVpnClientConfig" => ({
            let req: pb::GetVpnClientConfigRequest = codec.decode(&bytes)?;
            Ok(vpn_clients::client_config(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Vpn/SetVpnClientDns" => ({
            let req: pb::SetVpnClientDnsRequest = codec.decode(&bytes)?;
            Ok(vpn_clients::set_client_dns(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Vpn/GetVpnDns" => ({
            let req: pb::GetVpnDnsRequest = codec.decode(&bytes)?;
            Ok(vpn_clients::default_dns(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Vpn/SetVpnDns" => ({
            let req: pb::VpnDns = codec.decode(&bytes)?;
            Ok(vpn_clients::set_default_dns(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Vpn/GetVpnDnsPriority" => ({
            let req: pb::GetVpnDnsPriorityRequest = codec.decode(&bytes)?;
            Ok(vpn_clients::dns_priority(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Vpn/SetVpnDnsPriority" => ({
            let req: pb::VpnDnsPriority = codec.decode(&bytes)?;
            Ok(vpn_clients::set_dns_priority(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Vpn/ExportVpnState" => ({
            let req: pb::ExportVpnStateRequest = codec.decode(&bytes)?;
            Ok(crate::vpn_state::export(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Vpn/ImportVpnState" => ({
            let req: pb::ImportVpnStateRequest = codec.decode(&bytes)?;
            Ok(crate::vpn_state::import(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Mail/ListMailboxes" => ({
            let req: pb::ListMailboxesRequest = codec.decode(&bytes)?;
            Ok(mailbox::list_mailboxes(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Mail/CreateMailbox" => ({
            let req: pb::CreateMailboxRequest = codec.decode(&bytes)?;
            Ok(mailbox::create_mailbox(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Mail/DeleteMailbox" => ({
            let req: pb::DeleteMailboxRequest = codec.decode(&bytes)?;
            Ok(mailbox::delete_mailbox(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Mail/SetMailboxPassword" => ({
            let req: pb::SetMailboxPasswordRequest = codec.decode(&bytes)?;
            Ok(mailbox::set_mailbox_password(codec, req).await)
        }).map(Some),
        "/gryonixnexusd.v1.Dkim/GetDkimRecords" => ({
            let req: pb::GetDkimRecordsRequest = codec.decode(&bytes)?;
            Ok(dkim::get_dkim_records(codec, req).await)
        }).map(Some),
        _ => Ok(None),
    }
}

fn host_metrics_stream(codec: Codec, req: pb::HostMetricsRequest) -> Resp {
    let interval = match req.interval_seconds as u64 {
        0 => METRICS_DEFAULT_INTERVAL,
        n => n.clamp(1, METRICS_MAX_INTERVAL),
    };
    let json = matches!(codec, Codec::Json);
    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(8);

    tokio::spawn(async move {
        let mut sampler = metrics::Sampler::new();
        tokio::time::sleep(Duration::from_millis(300)).await;
        loop {
            let sample = sampler.sample();
            let payload = if json {
                serde_json::to_vec(&sample).unwrap_or_default()
            } else {
                sample.encode_to_vec()
            };
            if tx.send(envelope(0x00, &payload)).await.is_err() {
                break; // client gone
            }
            tokio::time::sleep(Duration::from_secs(interval)).await;
        }
    });

    stream_response(json, rx)
}

pub fn stream_response(json: bool, rx: tokio::sync::mpsc::Receiver<Bytes>) -> Resp {
    let content_type = if json {
        "application/connect+json"
    } else {
        "application/connect+proto"
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, content_type)
        .body(ChannelBody { rx, trailer_sent: false }.boxed())
        .expect("streaming response builds")
}

async fn logs_stream(codec: Codec, req: pb::LogsRequest) -> anyhow::Result<Resp> {
    let containers = discover::containers_of_service(&req.service_id).await?;
    Ok(tail_all(codec, containers, req.service_id, req.tail))
}

/// Follow a resolved set of containers, whatever resolved them
pub(crate) fn tail_all(
    codec: Codec,
    containers: Vec<String>,
    label: String,
    requested_tail: u32,
) -> Resp {
    let tail = match requested_tail {
        0 => LOGS_DEFAULT_TAIL,
        n => n.clamp(1, LOGS_MAX_TAIL),
    };
    let json = matches!(codec, Codec::Json);
    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(64);

    for container in containers {
        let tx = tx.clone();
        let label = label.clone();
        tokio::spawn(async move { tail_container(container, label, tail, json, tx).await });
    }
    drop(tx);

    stream_response(json, rx)
}

async fn tail_container(container: String, service_id: String, tail: u32, json: bool, tx: Sender<Bytes>) {
    let mut child = match tokio::process::Command::new("docker")
        .args(["logs", "-f", "--tail", &tail.to_string(), &container])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
    {
        Ok(child) => child,
        Err(err) => {
            tracing::warn!(%container, ?err, "docker logs failed to start");
            return;
        }
    };

    let mut out = child.stdout.take().map(|s| tokio::io::BufReader::new(s).lines());
    let mut err = child.stderr.take().map(|s| tokio::io::BufReader::new(s).lines());

    loop {
        tokio::select! {
            line = async { out.as_mut().unwrap().next_line().await }, if out.is_some() => {
                match line {
                    Ok(Some(text)) => {
                        if send_log(&tx, &service_id, &container, "stdout", text, json).await.is_err() {
                            break;
                        }
                    }
                    _ => out = None, // EOF or read error on this pipe
                }
            }
            line = async { err.as_mut().unwrap().next_line().await }, if err.is_some() => {
                match line {
                    Ok(Some(text)) => {
                        if send_log(&tx, &service_id, &container, "stderr", text, json).await.is_err() {
                            break;
                        }
                    }
                    _ => err = None,
                }
            }
            else => break, // both pipes drained
        }
    }
}

async fn send_log(
    tx: &Sender<Bytes>,
    service_id: &str,
    container: &str,
    stream: &str,
    text: String,
    json: bool,
) -> Result<(), ()> {
    let line = pb::LogLine {
        service_id: service_id.to_string(),
        at: now_millis(),
        stream: stream.to_string(),
        text,
        container: container.to_string(),
    };
    let payload = if json {
        serde_json::to_vec(&line).unwrap_or_default()
    } else {
        line.encode_to_vec()
    };
    tx.send(envelope(0x00, &payload)).await.map_err(|_| ())
}

pub fn envelope(flags: u8, payload: &[u8]) -> Bytes {
    let mut buf = Vec::with_capacity(5 + payload.len());
    buf.push(flags);
    buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    buf.extend_from_slice(payload);
    Bytes::from(buf)
}

struct ChannelBody {
    rx: tokio::sync::mpsc::Receiver<Bytes>,
    trailer_sent: bool,
}

fn success_trailer() -> Bytes {
    envelope(END_OF_STREAM_FLAG, b"{}")
}

impl Body for ChannelBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(bytes)) => {
                if bytes.first() == Some(&END_OF_STREAM_FLAG) {
                    self.trailer_sent = true;
                }
                Poll::Ready(Some(Ok(Frame::data(bytes))))
            }
            Poll::Ready(None) if !self.trailer_sent => {
                self.trailer_sent = true;
                Poll::Ready(Some(Ok(Frame::data(success_trailer()))))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

pub const END_OF_STREAM_FLAG: u8 = 0x02;

/// The end-of-stream envelope carrying a Connect error
pub fn error_trailer(code: &str, message: &str) -> Bytes {
    let body = serde_json::json!({ "error": { "code": code, "message": message } }).to_string();
    envelope(END_OF_STREAM_FLAG, body.as_bytes())
}

#[derive(Clone, Copy)]
pub enum Codec {
    Json,
    Proto,
}

impl Codec {
    fn from_content_type(ct: Option<&str>) -> Self {
        match ct {
            Some(v) if v.contains("json") => Codec::Json,
            _ => Codec::Proto,
        }
    }

    fn decode<T>(&self, bytes: &[u8]) -> anyhow::Result<T>
    where
        T: prost::Message + Default + serde::de::DeserializeOwned,
    {
        match self {
            Codec::Json if bytes.is_empty() => Ok(T::default()),
            Codec::Json => Ok(serde_json::from_slice(bytes)?),
            Codec::Proto => Ok(T::decode(bytes)?),
        }
    }

    fn decode_enveloped<T>(&self, bytes: &[u8]) -> anyhow::Result<T>
    where
        T: prost::Message + Default + serde::de::DeserializeOwned,
    {
        self.decode(strip_envelope(bytes))
    }

    pub fn encode_payload<T>(&self, msg: &T) -> Vec<u8>
    where
        T: prost::Message + serde::Serialize,
    {
        match self {
            Codec::Json => serde_json::to_vec(msg).unwrap_or_default(),
            Codec::Proto => msg.encode_to_vec(),
        }
    }

    /// Decode a payload this codec encoded — the inverse of `encode_payload`
    pub fn decode_payload<T>(&self, bytes: &[u8]) -> Option<T>
    where
        T: prost::Message + Default + serde::de::DeserializeOwned,
    {
        match self {
            Codec::Json => serde_json::from_slice(bytes).ok(),
            Codec::Proto => T::decode(bytes).ok(),
        }
    }

    pub fn encode<T>(&self, msg: &T) -> anyhow::Result<Resp>
    where
        T: prost::Message + serde::Serialize,
    {
        let (body, ct) = match self {
            Codec::Json => (serde_json::to_vec(msg)?, "application/json"),
            Codec::Proto => (msg.encode_to_vec(), "application/proto"),
        };
        Ok(Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, ct)
            .body(Full::new(Bytes::from(body)).boxed())?)
    }
}

fn strip_envelope(bytes: &[u8]) -> &[u8] {
    if bytes.len() < 5 {
        return &[];
    }
    let len = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize;
    let end = (5 + len).min(bytes.len());
    &bytes[5..end]
}

/// The header every client puts its installation id in
const DEVICE_HEADER: &str = "x-gryonix-device";

fn session_refusal(
    parts: &hyper::http::request::Parts,
    path: &str,
    store: &Arc<Mutex<Store>>,
) -> anyhow::Result<Option<Resp>> {
    if path == "/gryonixnexusd.v1.Pairing/Pair" {
        return Ok(None);
    }
    let uid = parts
        .headers
        .get(DEVICE_HEADER)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .trim()
        .to_string();

    let (policy, session) = {
        let store = lock(store);
        let session = store.device_session(&uid)?;
        (store.session_policy()?, session)
    };
    if policy.auto_logout_months == 0 {
        return Ok(None);
    }
    let refusal = match session {
        crate::state::DeviceSession::Live => return Ok(None),
        crate::state::DeviceSession::Unidentified => (
            "device_unidentified",
            "this server signs devices out on a schedule, and this client did not say which device it is — update the app",
        ),
        crate::state::DeviceSession::Unknown => (
            "device_not_paired",
            "this device is not paired with this server",
        ),
        crate::state::DeviceSession::Expired => (
            "session_expired",
            "this device's session has run out — sign in again to keep using this server",
        ),
    };
    Ok(Some(connect_error(
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
        &format!("{}: {}", refusal.0, refusal.1),
    )))
}

async fn reconcile_off_the_worker(snapshot: &pb::VaultSnapshot) {
    let snapshot = snapshot.clone();
    let _ = tokio::task::spawn_blocking(move || reconcile_service_secrets(&snapshot)).await;
}

fn reconcile_service_secrets(snapshot: &pb::VaultSnapshot) {
    if let Err(err) = crate::install::llm_keys::reconcile(&snapshot.entries) {
        eprintln!("vault: rendering the model provider keys failed: {err:#}");
    }
}

fn lock(store: &Arc<Mutex<Store>>) -> std::sync::MutexGuard<'_, Store> {
    store.lock().unwrap_or_else(|err| err.into_inner())
}

pub fn connect_error(status: StatusCode, code: &str, message: &str) -> Resp {
    let body = serde_json::json!({ "code": code, "message": message }).to_string();
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body)).boxed())
        .expect("static error response builds")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_frames_flag_and_big_endian_length() {
        let framed = envelope(0x00, b"hello");
        assert_eq!(framed[0], 0x00);
        assert_eq!(&framed[1..5], &[0, 0, 0, 5]); // length 5, big-endian
        assert_eq!(&framed[5..], b"hello");
    }

    #[test]
    fn strip_envelope_roundtrips_the_payload() {
        let framed = envelope(0x00, b"payload");
        assert_eq!(strip_envelope(&framed), b"payload");
    }

    // ─────────────── who is calling, and is the door still open ───────────────

    fn parts_for(path: &str, device: Option<&str>) -> hyper::http::request::Parts {
        let mut builder = Request::builder().uri(path);
        if let Some(device) = device {
            builder = builder.header(DEVICE_HEADER, device);
        }
        builder.body(()).expect("request builds").into_parts().0
    }

    fn store_with_device() -> Arc<Mutex<Store>> {
        let store = Store::in_memory().expect("in-memory store");
        store.pair("ssh-ed25519 AAAA", "iPhone", "uid-a").expect("pair");
        Arc::new(Mutex::new(store))
    }

    async fn refusal_message(resp: Resp) -> String {
        let bytes = resp.into_body().collect().await.expect("body").to_bytes();
        String::from_utf8_lossy(&bytes).to_string()
    }

    const ANY_VERB: &str = "/gryonixnexusd.v1.Control/GetState";

    /// The default
    #[test]
    fn with_no_window_set_an_anonymous_caller_is_served_exactly_as_before() {
        let store = store_with_device();
        let parts = parts_for(ANY_VERB, None);
        assert!(session_refusal(&parts, ANY_VERB, &store).unwrap().is_none());
    }

    #[tokio::test]
    async fn with_a_window_set_a_caller_that_will_not_name_itself_is_refused() {
        let store = store_with_device();
        store.lock().unwrap().set_session_policy(3).unwrap();
        let parts = parts_for(ANY_VERB, None);
        let refusal = session_refusal(&parts, ANY_VERB, &store).unwrap().expect("refused");
        assert_eq!(refusal.status(), StatusCode::UNAUTHORIZED);
        let body = refusal_message(refusal).await;
        assert!(body.contains("device_unidentified"), "got: {body}");
        assert!(body.contains("unauthenticated"), "got: {body}");
    }

    #[tokio::test]
    async fn an_id_nobody_paired_under_is_refused_too() {
        let store = store_with_device();
        store.lock().unwrap().set_session_policy(3).unwrap();
        let parts = parts_for(ANY_VERB, Some("uid-somebody-else"));
        let refusal = session_refusal(&parts, ANY_VERB, &store).unwrap().expect("refused");
        let body = refusal_message(refusal).await;
        assert!(body.contains("device_not_paired"), "got: {body}");
    }

    #[tokio::test]
    async fn a_device_past_its_window_is_told_which_kind_of_no_this_is() {
        let store = store_with_device();
        store.lock().unwrap().set_session_policy(1).unwrap();
        store
            .lock()
            .unwrap()
            .set_expiry_for_test("uid-a", 1)
            .unwrap();
        let parts = parts_for(ANY_VERB, Some("uid-a"));
        let refusal = session_refusal(&parts, ANY_VERB, &store).unwrap().expect("refused");
        let body = refusal_message(refusal).await;
        assert!(body.contains("session_expired"), "got: {body}");
    }

    #[test]
    fn a_paired_device_inside_its_window_is_let_through() {
        let store = store_with_device();
        store.lock().unwrap().set_session_policy(12).unwrap();
        let parts = parts_for(ANY_VERB, Some("uid-a"));
        assert!(session_refusal(&parts, ANY_VERB, &store).unwrap().is_none());
    }

    /// The way back in
    #[test]
    fn pairing_stays_open_to_a_device_whose_session_has_run_out() {
        let store = store_with_device();
        store.lock().unwrap().set_session_policy(1).unwrap();
        store.lock().unwrap().set_expiry_for_test("uid-a", 1).unwrap();
        let path = "/gryonixnexusd.v1.Pairing/Pair";
        let parts = parts_for(path, Some("uid-a"));
        assert!(session_refusal(&parts, path, &store).unwrap().is_none());
    }

    #[test]
    fn strip_envelope_tolerates_short_and_truncated_input() {
        assert_eq!(strip_envelope(b""), b"");
        assert_eq!(strip_envelope(&[0x00, 0x00]), b"");
        let truncated = [0x00, 0, 0, 0, 99, b'a', b'b', b'c'];
        assert_eq!(strip_envelope(&truncated), b"abc");
    }

    #[test]
    fn decode_enveloped_reads_the_inner_request() {
        let req = pb::HostMetricsRequest { interval_seconds: 7 };
        let framed = envelope(0x00, &req.encode_to_vec());
        let decoded: pb::HostMetricsRequest = Codec::Proto.decode_enveloped(&framed).unwrap();
        assert_eq!(decoded.interval_seconds, 7);
    }

    async fn drain_body(rx: tokio::sync::mpsc::Receiver<Bytes>) -> Vec<Bytes> {
        use http_body_util::BodyExt;
        let mut body = ChannelBody { rx, trailer_sent: false };
        let mut frames = Vec::new();
        while let Some(frame) = body.frame().await {
            frames.push(frame.unwrap().into_data().unwrap());
        }
        frames
    }

    #[tokio::test]
    async fn a_stream_that_ends_well_closes_with_an_empty_end_of_stream_envelope() {
        let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(8);
        tx.send(envelope(0x00, b"event")).await.unwrap();
        drop(tx); // the verb finished and dropped its sender

        let frames = drain_body(rx).await;
        assert_eq!(frames.len(), 2, "the data frame plus one trailer");
        assert_eq!(frames[0][0], 0x00);
        let trailer = &frames[1];
        assert_eq!(trailer[0], END_OF_STREAM_FLAG);
        assert_eq!(strip_envelope(trailer), b"{}", "success is the empty error object");
    }

    #[tokio::test]
    async fn a_stream_that_sent_its_own_error_trailer_does_not_get_a_second_one() {
        let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(8);
        tx.send(envelope(0x00, b"event")).await.unwrap();
        tx.send(error_trailer("internal", "it broke")).await.unwrap();
        drop(tx);

        let frames = drain_body(rx).await;
        assert_eq!(frames.len(), 2, "the data frame plus the verb's own trailer, nothing appended");
        let trailer = &frames[1];
        assert_eq!(trailer[0], END_OF_STREAM_FLAG);
        let body: serde_json::Value = serde_json::from_slice(strip_envelope(trailer)).unwrap();
        assert_eq!(body["error"]["code"], "internal");
    }

    #[tokio::test]
    async fn even_a_stream_with_no_events_at_all_carries_the_trailer() {
        let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(8);
        drop(tx);

        let frames = drain_body(rx).await;
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0][0], END_OF_STREAM_FLAG);
        assert_eq!(strip_envelope(&frames[0]), b"{}");
    }
}
