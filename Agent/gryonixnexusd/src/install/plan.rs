//! A list of services the agent installs one by one on its own.
//! The plan is a job: one card, one Stop, any device can follow it.

use crate::api::{connect_error, Codec, Resp};
use crate::jobs;
use crate::pb;
use crate::state::Store;
use hyper::StatusCode;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

/// Plans kept in memory for GetInstallPlan
const KEEP_PLANS: usize = 5;

/// The longest plan the agent accepts
const MAX_SERVICES: usize = 64;

/// How often a service's lines are copied into the plan
const MIRROR_EVERY: std::time::Duration = std::time::Duration::from_millis(700);

fn plans() -> &'static Mutex<Vec<pb::InstallPlan>> {
    static PLANS: OnceLock<Mutex<Vec<pb::InstallPlan>>> = OnceLock::new();
    PLANS.get_or_init(Default::default)
}

/// Services a plan is installing now, and the plan's job
fn quiet() -> &'static Mutex<HashMap<String, String>> {
    static QUIET: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
    QUIET.get_or_init(Default::default)
}

/// The plan job that shows this service's progress, if any
pub fn card_of(service_id: &str) -> Option<String> {
    quiet().lock().unwrap().get(service_id).cloned()
}

fn update(plan_id: &str, change: impl FnOnce(&mut pb::InstallPlan)) {
    if let Some(plan) = plans().lock().unwrap().iter_mut().find(|p| p.plan_id == plan_id) {
        change(plan);
    }
}

fn set_item(plan_id: &str, index: usize, change: impl FnOnce(&mut pb::InstallPlanItem)) {
    update(plan_id, |plan| {
        if let Some(item) = plan.items.get_mut(index) {
            change(item);
        }
    });
}

/// The plan whose list holds this service run
pub fn part_of(job_id: &str) -> Option<String> {
    let all = plans().lock().unwrap();
    all.iter().find(|p| p.items.iter().any(|i| i.job_id == job_id)).map(|p| p.plan_id.clone())
}

/// Why this plan job runs, when it is one
pub fn purpose_of(plan_id: &str) -> Option<i32> {
    plans().lock().unwrap().iter().find(|p| p.plan_id == plan_id).map(|p| p.purpose)
}

/// The job kind a plan of this purpose runs as
pub fn kind_for(purpose: i32) -> pb::JobKind {
    match pb::InstallPlanPurpose::try_from(purpose) {
        Ok(pb::InstallPlanPurpose::Repair) => pb::JobKind::Repair,
        Ok(pb::InstallPlanPurpose::Reinstall) => pb::JobKind::Reinstall,
        _ => pb::JobKind::Install,
    }
}

pub fn get(plan_id: &str) -> pb::InstallPlan {
    let all = plans().lock().unwrap();
    let found = if plan_id.is_empty() { all.last() } else { all.iter().find(|p| p.plan_id == plan_id) };
    found.cloned().unwrap_or_default()
}

/// The card's title: the first services, then how many more
pub fn subject(services: &[String]) -> String {
    let shown: Vec<&str> = services.iter().take(2).map(String::as_str).collect();
    match services.len().saturating_sub(shown.len()) {
        0 => shown.join(", "),
        more => format!("{} +{more}", shown.join(", ")),
    }
}

/// `Install/StartInstallPlan`
pub async fn run_start(codec: Codec, req: pb::StartInstallPlanRequest, store: Arc<Mutex<Store>>) -> Resp {
    if req.services.is_empty() || req.services.len() > MAX_SERVICES {
        return connect_error(StatusCode::BAD_REQUEST, "invalid_argument", "an install plan needs 1 to 64 services");
    }
    if let Some(unknown) = req.services.iter().find(|s| super::execute::resolve(&s.service_id).is_err()) {
        return connect_error(StatusCode::BAD_REQUEST, "invalid_argument", &format!("unknown service '{}'", unknown.service_id));
    }
    let ids: Vec<String> = req.services.iter().map(|s| s.service_id.clone()).collect();
    let mut all = plans().lock().unwrap();
    if all.iter().any(|p| !p.finished) {
        return connect_error(StatusCode::CONFLICT, "already_exists", "an install plan is already running on this host");
    }
    let Some(journal) = jobs::Journal::open(kind_for(req.purpose), &subject(&ids)) else {
        return connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", "the job journal is unavailable");
    };
    let mut plan = new_plan(journal.job_id(), &ids);
    plan.purpose = req.purpose;
    keep(&mut all, plan.clone());
    drop(all);
    tokio::spawn(run(journal, req.services, store));
    codec.encode(&plan).unwrap_or_else(|err| connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string()))
}

/// `Install/GetInstallPlan`
pub async fn run_get(codec: Codec, req: pb::GetInstallPlanRequest) -> Resp {
    codec.encode(&get(&req.plan_id)).unwrap_or_else(|err| connect_error(StatusCode::INTERNAL_SERVER_ERROR, "internal", &err.to_string()))
}

fn new_plan(plan_id: &str, services: &[String]) -> pb::InstallPlan {
    pb::InstallPlan {
        plan_id: plan_id.to_string(),
        items: services
            .iter()
            .map(|id| pb::InstallPlanItem {
                service_id: id.clone(),
                state: pb::InstallPlanItemState::Pending as i32,
                ..Default::default()
            })
            .collect(),
        started: crate::notify::now(),
        ..Default::default()
    }
}

#[cfg(test)]
fn remember(plan: pb::InstallPlan) {
    keep(&mut plans().lock().unwrap(), plan);
}

fn keep(all: &mut Vec<pb::InstallPlan>, plan: pb::InstallPlan) {
    all.push(plan);
    let excess = all.len().saturating_sub(KEEP_PLANS);
    all.drain(..excess);
}

async fn run(journal: jobs::Journal, services: Vec<pb::InstallServiceRequest>, store: Arc<Mutex<Store>>) {
    let plan_id = journal.job_id().to_string();
    let stop = jobs::cancellable(&Some(journal.clone()));
    let total = services.len();
    let mut failed = Vec::new();
    for (index, request) in services.into_iter().enumerate() {
        if stop.as_ref().is_some_and(|s| s.asked()) {
            return stopped(&journal, &plan_id, index);
        }
        let service = request.service_id.clone();
        journal.append(pb::JobPhase::Progress, "agent", &format!("GRYONIXNEXUS_STEP {}/{total}\n{service}", index + 1));
        set_item(&plan_id, index, |item| item.state = pb::InstallPlanItemState::Running as i32);
        quiet().lock().unwrap().insert(service.clone(), plan_id.clone());
        let outcome = install_mirrored(&journal, &plan_id, index, request, store.clone()).await;
        quiet().lock().unwrap().remove(&service);
        set_item(&plan_id, index, |item| record(item, &outcome));
        if let Err(why) = outcome {
            journal.append(pb::JobPhase::Progress, "agent", &format!("{service}: {why}"));
            failed.push(service);
        }
    }
    finish(&journal, &plan_id, &failed);
}

/// Installs one service, copying its lines into the plan
async fn install_mirrored(
    journal: &jobs::Journal,
    plan_id: &str,
    index: usize,
    request: pb::InstallServiceRequest,
    store: Arc<Mutex<Store>>,
) -> Result<(), String> {
    let child = Arc::new(Mutex::new(None::<String>));
    let named = child.clone();
    let install = super::execute::install_awaited(request, store, move |job| {
        set_item(plan_id, index, |item| item.job_id = job.to_string());
        *named.lock().unwrap() = Some(job.to_string());
    });
    tokio::pin!(install);
    let mut copied = 0u64;
    let outcome = loop {
        tokio::select! {
            outcome = &mut install => break outcome,
            () = tokio::time::sleep(MIRROR_EVERY) => copied = copy_lines(journal, &child, copied),
        }
    };
    copy_lines(journal, &child, copied);
    outcome
}

/// Appends the service's new lines; returns the next sequence
fn copy_lines(journal: &jobs::Journal, child: &Mutex<Option<String>>, from: u64) -> u64 {
    let Some(job_id) = child.lock().unwrap().clone() else { return from };
    let Some((events, _, _)) = super::journal::events_after(&job_id, from) else { return from };
    let mut next = from;
    for event in events {
        next = event.sequence + 1;
        if event.phase == pb::ServiceOperationPhase::Progress as i32 && !event.text.is_empty() {
            journal.append_quiet(pb::JobPhase::Progress, &event.stream, &event.text);
        }
    }
    next
}

fn record(item: &mut pb::InstallPlanItem, outcome: &Result<(), String>) {
    match outcome {
        Ok(()) => item.state = pb::InstallPlanItemState::Done as i32,
        Err(why) => {
            item.state = pb::InstallPlanItemState::Failed as i32;
            item.failure = why.clone();
        }
    }
}

fn stopped(journal: &jobs::Journal, plan_id: &str, from: usize) {
    update(plan_id, |plan| {
        plan.items.iter_mut().skip(from).for_each(|item| item.state = pb::InstallPlanItemState::Skipped as i32);
        plan.finished = true;
        plan.cancelled = true;
    });
    journal.cancelled("stopped before the remaining services");
}

fn finish(journal: &jobs::Journal, plan_id: &str, failed: &[String]) {
    update(plan_id, |plan| plan.finished = true);
    journal.append(pb::JobPhase::Completed, "agent", "");
    let failure = (!failed.is_empty()).then(|| format!("not installed: {}", failed.join(", ")));
    journal.finish(failure.as_deref());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_card_names_two_services_and_counts_the_rest() {
        let ids = |list: &[&str]| list.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(subject(&ids(&["vaultwarden"])), "vaultwarden");
        assert_eq!(subject(&ids(&["vaultwarden", "immich", "nextcloud", "jellyfin"])), "vaultwarden, immich +2");
    }

    #[test]
    fn an_item_records_its_outcome() {
        let mut item = pb::InstallPlanItem::default();
        record(&mut item, &Err("ports in use".into()));
        assert_eq!((item.state, item.failure.as_str()), (pb::InstallPlanItemState::Failed as i32, "ports in use"));
        record(&mut item, &Ok(()));
        assert_eq!(item.state, pb::InstallPlanItemState::Done as i32);
    }

    #[test]
    fn the_newest_plan_answers_an_empty_id() {
        remember(new_plan("plan-a", &["vaultwarden".into()]));
        remember(new_plan("plan-b", &["immich".into(), "jellyfin".into()]));
        assert_eq!(get("").plan_id, "plan-b");
        assert_eq!(get("plan-a").items.len(), 1);
        assert_eq!(get("missing").plan_id, "");
        set_item("plan-b", 1, |item| item.job_id = "job-9".into());
        assert_eq!(get("plan-b").items[1].job_id, "job-9");
        assert_eq!(part_of("job-9").as_deref(), Some("plan-b"));
        assert_eq!(part_of("job-0"), None);
    }

    #[test]
    fn repair_and_reinstall_plans_run_as_their_own_kinds() {
        assert_eq!(kind_for(pb::InstallPlanPurpose::Repair as i32), pb::JobKind::Repair);
        assert_eq!(kind_for(pb::InstallPlanPurpose::Reinstall as i32), pb::JobKind::Reinstall);
        assert_eq!(kind_for(pb::InstallPlanPurpose::Setup as i32), pb::JobKind::Install);
        assert_eq!(kind_for(pb::InstallPlanPurpose::Add as i32), pb::JobKind::Install);
    }
}
