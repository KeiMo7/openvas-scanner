// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use fslock::LockFile;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::config::SchedulingMode;
use scannerlib::{
    models::{self, FeedType, Scan},
    nasl::{builtin::nasl_std_executor, syntax::Loader},
    openvas::{self, cmd},
    osp,
    scanner::{OpenvasdScanner, ScanResultKind, Scanner},
    utils::scanner_types::{self, ScannerType},
};

use crate::database::sqlite::scan_storage::ScanStorage;
use crate::scans::{
    scheduler_store::{self, Event, StoredTaskState},
    target_scheduler::{
        self, BatchConfig, DependencyReadiness, QueueSnapshot, ResolvedTargets,
        TargetResolutionError,
    },
};
use tokio::{
    sync::mpsc::{self, Sender},
    time::MissedTickBehavior,
};

use crate::{
    config::Config,
    crypt::Crypt,
    database::{
        dao::{Fetch, RetryExec},
        sqlite::{DataBase, results::DBResults, scans::ScanDB, state_change::ScanStateController},
    },
    vts::orchestrator::{self, FeedStatusChange},
};

const LOCK_FILE: &str = "feed-update.lock";

#[derive(Default, Debug)]
struct IsInProgress {
    need_approval_nasl: bool,
    need_approval_advisories: bool,
    approved_nasl: bool,
    approved_advisories: bool,
}

impl IsInProgress {
    fn set_based_on_message(&mut self, msg: &orchestrator::FeedStatusChange) {
        match msg {
            // A new request always needs a new approval. Without resetting `approved_*` a
            // previous sync that failed (and therefore never sent `Synced`) would leave the
            // approval set forever, so the request would never be approved again and no scan
            // could be started anymore.
            FeedStatusChange::Need(FeedType::Advisories) => {
                self.need_approval_advisories = true;
                self.approved_advisories = false;
            }
            FeedStatusChange::Need(FeedType::NASL) => {
                self.need_approval_nasl = true;
                self.approved_nasl = false;
            }
            FeedStatusChange::Synced(FeedType::Advisories) => {
                self.need_approval_advisories = false;
                self.approved_advisories = false;
            }
            FeedStatusChange::Synced(FeedType::NASL) => {
                self.need_approval_nasl = false;
                self.approved_nasl = false;
            }
            _ => {
                // ignore products
            }
        }
    }

    fn approve(&mut self) -> Vec<FeedType> {
        let mut result = Vec::with_capacity(2);
        if self.need_approve(&FeedType::NASL) {
            self.approved_nasl = true;
            result.push(FeedType::NASL);
        }
        if self.need_approve(&FeedType::Advisories) {
            self.approved_advisories = true;
            result.push(FeedType::Advisories);
        };
        result
    }

    fn scans_allowed(&self) -> bool {
        !self.need_approval_nasl
            && !self.approved_nasl
            && !self.need_approval_advisories
            && !self.approved_advisories
    }

    fn is_feed_sync_in_progress(&self) -> bool {
        !self.scans_allowed()
    }

    fn need_approve(&self, ft: &FeedType) -> bool {
        match ft {
            FeedType::Products => false,
            FeedType::Advisories => self.need_approval_advisories && !self.approved_advisories,
            FeedType::NASL => self.need_approval_nasl && !self.approved_nasl,
        }
    }

    fn contains_need(&self) -> bool {
        (self.need_approval_nasl && !self.approved_nasl)
            || (self.need_approval_advisories && !self.approved_advisories)
    }
}

struct ScanScheduler<Scanner, Cryptor> {
    pool: DataBase,
    cryptor: Arc<Cryptor>,
    scanner: Arc<Scanner>,
    max_concurrent_scan: usize,
    // we store the need and allow requests in the case of a feed sync
    //
    // On need we know that we actually need to send the allows because we waited for the scans to
    // finish. One allow we just wait for synced.
    // We use the fact that we don't handle products as a differentiation between need and allow
    // otherwise we would need to store two separate lists.
    feed_sync_in_progress: Arc<RwLock<IsInProgress>>,
    scan_state: ScanStateController,
    lock_file_dir: String,
    scheduling_mode: SchedulingMode,
    starvation_threshold: u32,
    batch_config: BatchConfig,
}

#[derive(Debug)]
pub enum Message {
    Start(String),
    // On Stop we also delete
    Stop(String),
}

#[derive(Debug)]
enum StartOutcome {
    Started,
    Skipped,
    Deferred(String),
    Failed(String),
}

fn scan_dependencies(scan: &models::Scan) -> Vec<String> {
    scan.scan_preferences
        .iter()
        .filter(|preference| {
            preference.id == "depends_on" || preference.id == "dependencies"
        })
        .flat_map(|preference| {
            serde_json::from_str::<Vec<String>>(&preference.value).unwrap_or_else(|_| {
                preference
                    .value
                    .split(',')
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(ToString::to_string)
                    .collect()
            })
        })
        .collect()
}

#[derive(Debug, thiserror::Error)]
enum LockFileError {
    #[error("Unable to open feed update lock file {path}: {source}")]
    Open {
        path: String,
        source: std::io::Error,
    },
    #[error("Unable to check feed update lock file {path}: {source}")]
    TryLock {
        path: String,
        source: std::io::Error,
    },
    #[error("Unable to unlock feed update lock file {path}: {source}")]
    Unlock {
        path: String,
        source: std::io::Error,
    },
}

impl<SC, C> ScanScheduler<SC, C>
where
    SC: Scanner + Send + Sync + 'static,
    C: Crypt + Send + Sync + 'static,
{
    /// Should be called on restart if the application crashed while there were running scans.
    ///
    /// This is to safe guard against ghost scans that will never finish.
    async fn running_to_failed(&self) -> anyhow::Result<()> {
        let running = self
            .scan_state
            .fetch_scans_in_state("running", None)
            .await?;
        let affected = self
            .scan_state
            .change_state_all("running", "failed")
            .await?;

        for id in running {
            if let Err(error) = scheduler_store::finish_task(
                &self.pool,
                id,
                "failed",
                Some("openvasd restarted while the scan was running"),
                false,
            )
            .await
            {
                tracing::warn!(id, %error, "Unable to update persisted scheduler state.");
            }
        }

        if affected > 0 {
            tracing::warn!(
                scans_failed = affected,
                "Set scans to failed from previous runs."
            );
        }
        Ok(())
    }

    async fn scan_to_requested(&self, id: i64) -> anyhow::Result<()> {
        let scan = ScanDB::new(&self.pool, (self.cryptor.as_ref(), id))
            .fetch()
            .await?;
        let dependencies = scan_dependencies(&scan);
        let (group_id, target_ranges, total_batches) = match self.scheduling_mode {
            SchedulingMode::Fifo => ("fifo".to_string(), scan.target.hosts.clone(), 1),
            SchedulingMode::TargetAware => {
                let resolved = self.resolve_targets(scan.target.hosts.clone()).await;
                match resolved {
                    Ok(resolved) => (
                        resolved.group_id,
                        resolved.target_ranges,
                        resolved.batches.len().max(1),
                    ),
                    Err(error) => {
                        self.scan_state
                            .change_state(id, "stored", "failed")
                            .await?;
                        self.scan_state
                            .change_state(id, "stopped", "failed")
                            .await?;
                        let reason = format!("target resolution failed: {error}");
                        tracing::warn!(id, %error, "Target resolution failed; scan was not queued.");
                        let _ = scheduler_store::finish_task(
                            &self.pool,
                            id,
                            "failed",
                            Some(&reason),
                            false,
                        )
                        .await;
                        let _ = scheduler_store::record_event(
                            &self.pool,
                            Event {
                                round: 0,
                                task_id: Some(id),
                                scan_id: Some(&scan.scan_id),
                                group_id: "unresolved",
                                decision: "target_resolution_failed",
                                reason: &reason,
                                wait_rounds: 0,
                                queue_duration_ms: None,
                                execution_duration_ms: None,
                                forced: false,
                                starvation_detected: false,
                                batch_index: None,
                            },
                            None,
                        )
                        .await;
                        return Ok(());
                    }
                }
            }
        };

        scheduler_store::enqueue_task(
            &self.pool,
            id,
            &group_id,
            &target_ranges,
            &dependencies,
            self.batch_config.strategy,
            self.batch_config.batch_size,
            total_batches,
        )
        .await?;
        self.scan_state
            .change_state(id, "stored", "requested")
            .await?;
        self.scan_state
            .change_state(id, "stopped", "requested")
            .await?;

        let _ = scheduler_store::record_event(
            &self.pool,
            Event {
                round: 0,
                task_id: Some(id),
                scan_id: Some(&scan.scan_id),
                group_id: &group_id,
                decision: "queued",
                reason: if self.scheduling_mode == SchedulingMode::Fifo {
                    "queued in FIFO order"
                } else {
                    "queued in target-aware group"
                },
                wait_rounds: 0,
                queue_duration_ms: None,
                execution_duration_ms: None,
                forced: false,
                starvation_detected: false,
                batch_index: None,
            },
            None,
        )
        .await;

        Ok(())
    }

    async fn scan_running_to_failed(&self, id: i64, reason: &str) -> anyhow::Result<()> {
        let changed = self
            .scan_state
            .change_state(id, "running", "failed")
            .await?;

        if changed {
            tracing::warn!(id, reason, "Set scan from running to failed.");
            if let Err(error) = scheduler_store::finish_task(
                &self.pool,
                id,
                "failed",
                Some(reason),
                false,
            )
            .await
            {
                tracing::warn!(id, %error, "Unable to persist failed scheduler state.");
            }
        }
        Ok(())
    }

    async fn scan_insert_results(
        &self,
        id: i64,
        results: Vec<models::Result>,
    ) -> anyhow::Result<()> {
        // TODO: maybe better to use i64 in the impl?
        let id: &str = &id.to_string();
        DBResults::new(&self.pool, (id, &results as &[_]))
            .retry_exec()
            .await?;
        Ok(())
    }
}

fn is_file_locked(path: String) -> anyhow::Result<bool> {
    let mut file = LockFile::open(&path).map_err(|source| LockFileError::Open {
        path: path.clone(),
        source,
    })?;

    if file.try_lock().map_err(|source| LockFileError::TryLock {
        path: path.clone(),
        source,
    })? {
        file.unlock()
            .map_err(|source| LockFileError::Unlock { path, source })?;
        Ok(false)
    } else {
        // locked by another process
        Ok(true)
    }
}

impl<SC, C> ScanScheduler<SC, C>
where
    SC: Scanner + Send + Sync + 'static,
    C: Crypt + Send + Sync + 'static,
{
    async fn resolve_targets(
        &self,
        hosts: Vec<String>,
    ) -> Result<ResolvedTargets, TargetResolutionError> {
        let batch_config = self.batch_config;
        tokio::task::spawn_blocking(move || target_scheduler::resolve_targets(&hosts, batch_config))
            .await
            .unwrap_or_else(|error| {
                Err(TargetResolutionError::InvalidRange {
                    target: "target list".to_string(),
                    reason: error.to_string(),
                })
            })
    }

    async fn scan_start(&self, _id: i64, scan: Scan) -> Result<(), scannerlib::scanner::Error> {
        self.scanner.start_scan(scan).await
    }

    fn is_retryable_start_error(error: &scannerlib::scanner::Error) -> bool {
        matches!(
            error,
            scannerlib::scanner::Error::InsufficientResources(_)
                | scannerlib::scanner::Error::Connection(_)
        ) || matches!(
            error,
            scannerlib::scanner::Error::Unexpected(reason)
                if reason.contains("Socket") || reason.contains("socket")
        )
    }

    async fn fetch_requested(&self) -> anyhow::Result<Vec<i64>> {
        let limit: Option<i64> = if self.max_concurrent_scan > 0 {
            let running = self.scan_state.count_scans_in_state("running").await?;
            Some(if running > self.max_concurrent_scan {
                0
            } else {
                (self.max_concurrent_scan - running) as i64
            })
        } else {
            None
        };
        let ids = self
            .scan_state
            .fetch_scans_in_state("requested", limit)
            .await?;

        Ok(ids)
    }

    async fn is_feed_sync_in_progress(&self) -> bool {
        self.feed_sync_in_progress
            .read()
            .await
            .is_feed_sync_in_progress()
    }

    async fn batch_hosts(
        &self,
        state: Option<&StoredTaskState>,
        scan: &models::Scan,
    ) -> Result<Option<Vec<String>>, TargetResolutionError> {
        if self.scheduling_mode == SchedulingMode::Fifo {
            return Ok(None);
        }
        let Some(state) = state else {
            return Ok(None);
        };
        let resolved = self.resolve_targets(scan.target.hosts.clone()).await?;
        if resolved.batches.is_empty() {
            return Err(TargetResolutionError::Empty);
        }
        let index = state.current_batch.min(resolved.batches.len() - 1);
        Ok(Some(resolved.batches[index].clone()))
    }

    async fn set_to_running(
        &self,
        id: i64,
        batch_hosts: Option<Vec<String>>,
    ) -> anyhow::Result<StartOutcome> {
        let mut scan = ScanDB::new(&self.pool, (self.cryptor.as_ref(), id))
            .fetch()
            .await?;
        if let Some(hosts) = batch_hosts {
            scan.target.hosts = hosts;
        }
        let running = self
            .scan_state
            .change_state(id, "requested", "running")
            .await?;
        if !running {
            return Ok(StartOutcome::Skipped);
        }

        tracing::info!(id, running, "Started scan");

        match self.scan_start(id, scan).await {
            Ok(()) => Ok(StartOutcome::Started),
            Err(error) if Self::is_retryable_start_error(&error) => {
                self.scan_state.change_state(id, "running", "requested").await?;
                scheduler_store::requeue_after_start_failure(&self.pool, id).await?;
                let reason = format!("scanner pool unavailable: {error}");
                tracing::warn!(id, %error, "Scanner pool unavailable; scan remains queued.");
                Ok(StartOutcome::Deferred(reason))
            }
            Err(error) => {
                let reason = format!("unable to start scan: {error}");
                tracing::warn!(id, %error, "Unable to start scan");
                self.scan_running_to_failed(id, &reason).await?;
                Ok(StartOutcome::Failed(reason))
            }
        }
    }

    async fn mark_not_executed(&self, id: i64, reason: &str) -> anyhow::Result<bool> {
        let changed = self
            .scan_state
            .change_state(id, "requested", "not_executed")
            .await?;
        if changed {
            scheduler_store::finish_task(
                &self.pool,
                id,
                "not_executed",
                Some(reason),
                false,
            )
            .await?;
            tracing::warn!(id, reason, "Scan marked as not executed.");
        }
        Ok(changed)
    }

    async fn mark_failed_dependencies(
        &self,
        round: u64,
        snapshot: Option<&QueueSnapshot>,
    ) -> anyhow::Result<bool> {
        let mut changed = false;
        loop {
            let pending = scheduler_store::pending_tasks(&self.pool).await?;
            let failed = pending
                .iter()
                .filter_map(|task| match &task.dependencies {
                    DependencyReadiness::Failed(dependencies) => {
                        Some((task.id, task.scan_id.clone(), dependencies.clone()))
                    }
                    _ => None,
                })
                .collect::<Vec<_>>();
            if failed.is_empty() {
                break;
            }
            for (id, scan_id, dependencies) in failed {
                let reason = format!(
                    "dependency did not succeed; task was not executed: {}",
                    dependencies.join(",")
                );
                if self.mark_not_executed(id, &reason).await? {
                    changed = true;
                    let _ = scheduler_store::record_event(
                        &self.pool,
                        Event {
                            round,
                            task_id: Some(id),
                            scan_id: Some(&scan_id),
                            group_id: "dependency",
                            decision: "not_executed",
                            reason: &reason,
                            wait_rounds: 0,
                            queue_duration_ms: None,
                            execution_duration_ms: None,
                            forced: false,
                            starvation_detected: false,
                            batch_index: None,
                        },
                        snapshot,
                    )
                    .await;
                }
            }
        }
        Ok(changed)
    }

    async fn requested_to_running_fifo(&self, round: u64) -> anyhow::Result<()> {
        self.mark_failed_dependencies(round, None).await?;
        let pending = scheduler_store::pending_tasks(&self.pool).await?;
        let readiness = pending
            .iter()
            .map(|task| (task.id, task.dependencies.clone()))
            .collect::<std::collections::HashMap<_, _>>();
        let ids = self.fetch_requested().await?;
        for id in ids {
            if matches!(
                readiness.get(&id),
                Some(DependencyReadiness::Waiting(_)) | Some(DependencyReadiness::Failed(_))
            ) {
                tracing::debug!(
                    id,
                    "Skipping FIFO scan because its dependencies are not ready."
                );
                continue;
            }
            if !self.scanner.can_start_scan().await {
                tracing::debug!(
                    id,
                    "Scanner pool has no capacity; leaving scan in FIFO queue."
                );
                break;
            }
            let outcome = self.set_to_running(id, None).await?;
            let selected = if matches!(outcome, StartOutcome::Started) {
                scheduler_store::selected(&self.pool, id, false, false)
                    .await
                    .ok()
            } else {
                None
            };
            let (decision, reason) = match &outcome {
                StartOutcome::Started => ("started", "selected by FIFO order".to_string()),
                StartOutcome::Skipped => (
                    "skipped",
                    "state changed before the scan was started".to_string(),
                ),
                StartOutcome::Deferred(reason) => {
                    tracing::debug!(id, %reason, "FIFO scan remains queued.");
                    ("deferred", reason.clone())
                }
                StartOutcome::Failed(reason) => ("failed", reason.clone()),
            };
            let _ = scheduler_store::record_event(
                &self.pool,
                Event {
                    round,
                    task_id: Some(id),
                    scan_id: None,
                    group_id: "fifo",
                    decision,
                    reason: &reason,
                    wait_rounds: 0,
                    queue_duration_ms: selected.as_ref().and_then(|state| state.queue_duration_ms),
                    execution_duration_ms: selected
                        .as_ref()
                        .map(|state| state.execution_duration_ms),
                    forced: false,
                    starvation_detected: false,
                    batch_index: None,
                },
                None,
            )
            .await;
            if matches!(outcome, StartOutcome::Deferred(_)) {
                break;
            }
        }
        Ok(())
    }

    async fn requested_to_running_target_aware(&self, round: u64) -> anyhow::Result<()> {
        let initial_snapshot = scheduler_store::build_snapshot(
            &self.pool,
            self.scheduling_mode,
            self.max_concurrent_scan,
            round,
        )
        .await?;
        self.mark_failed_dependencies(round, Some(&initial_snapshot))
            .await?;

        let pending = scheduler_store::pending_tasks(&self.pool).await?;
        let running_scans = self.scan_state.count_scans_in_state("running").await?;
        let available_slots = if self.max_concurrent_scan == 0 {
            pending.len()
        } else {
            self.max_concurrent_scan
                .saturating_sub(running_scans)
                .min(pending.len())
        };
        let running_groups = scheduler_store::running_groups(&self.pool).await?;
        let groups = scheduler_store::group_states(&self.pool).await?;
        let plan = target_scheduler::plan(
            &pending,
            &groups,
            &running_groups,
            available_slots,
            self.starvation_threshold,
        );
        scheduler_store::save_group_states(&self.pool, &plan.groups).await?;
        let snapshot = scheduler_store::build_snapshot(
            &self.pool,
            self.scheduling_mode,
            self.max_concurrent_scan,
            round,
        )
        .await?;
        scheduler_store::store_snapshot(&self.pool, &snapshot).await?;

        for skip in &plan.skips {
            tracing::info!(
                round,
                task_id = skip.task_id,
                scan_id = %skip.scan_id,
                group_id = %skip.group_id,
                wait_rounds = skip.wait_rounds,
                starvation_detected = skip.starvation_detected,
                reason = %skip.reason,
                "Scheduler skipped queued task."
            );
            let _ = scheduler_store::record_event(
                &self.pool,
                Event {
                    round,
                    task_id: Some(skip.task_id),
                    scan_id: Some(&skip.scan_id),
                    group_id: &skip.group_id,
                    decision: "skipped",
                    reason: &skip.reason,
                    wait_rounds: skip.wait_rounds,
                    queue_duration_ms: None,
                    execution_duration_ms: None,
                    forced: false,
                    starvation_detected: skip.starvation_detected,
                    batch_index: None,
                },
                Some(&snapshot),
            )
            .await;
        }

        for selection in &plan.selections {
            if !self.scanner.can_start_scan().await {
                let reason = "scanner pool is unavailable; task remains queued";
                tracing::info!(
                    round,
                    task_id = selection.task_id,
                    group_id = %selection.group_id,
                    reason,
                    "Scheduler skipped queued task."
                );
                let _ = scheduler_store::record_event(
                    &self.pool,
                    Event {
                        round,
                        task_id: Some(selection.task_id),
                        scan_id: Some(&selection.scan_id),
                        group_id: &selection.group_id,
                        decision: "deferred",
                        reason,
                        wait_rounds: selection.wait_rounds,
                        queue_duration_ms: None,
                        execution_duration_ms: None,
                        forced: selection.forced,
                        starvation_detected: selection.starvation_detected,
                        batch_index: None,
                    },
                    Some(&snapshot),
                )
                .await;
                break;
            }

            let state = scheduler_store::task_state(&self.pool, selection.task_id).await?;
            let scan = ScanDB::new(&self.pool, (self.cryptor.as_ref(), selection.task_id))
                .fetch()
                .await?;
            let batch_hosts = match self.batch_hosts(state.as_ref(), &scan).await {
                Ok(hosts) => hosts,
                Err(error) => {
                    let reason = format!("target resolution failed: {error}");
                    self.scan_running_to_failed(selection.task_id, &reason)
                        .await?;
                    let _ = scheduler_store::record_event(
                        &self.pool,
                        Event {
                            round,
                            task_id: Some(selection.task_id),
                            scan_id: Some(&selection.scan_id),
                            group_id: &selection.group_id,
                            decision: "failed",
                            reason: &reason,
                            wait_rounds: selection.wait_rounds,
                            queue_duration_ms: None,
                            execution_duration_ms: None,
                            forced: selection.forced,
                            starvation_detected: selection.starvation_detected,
                            batch_index: state.as_ref().map(|state| state.current_batch),
                        },
                        Some(&snapshot),
                    )
                    .await;
                    continue;
                }
            };
            let batch_index = state.as_ref().map(|state| state.current_batch);
            let selected = scheduler_store::selected(
                &self.pool,
                selection.task_id,
                selection.forced,
                selection.starvation_detected,
            )
            .await?;
            let outcome = self
                .set_to_running(selection.task_id, batch_hosts)
                .await?;
            let (decision, reason) = match &outcome {
                StartOutcome::Started => ("started", selection.reason.clone()),
                StartOutcome::Skipped => {
                    (
                        "skipped",
                        "state changed before the selected batch was started".to_string(),
                    )
                }
                StartOutcome::Deferred(reason) => ("deferred", reason.clone()),
                StartOutcome::Failed(reason) => ("failed", reason.clone()),
            };
            tracing::info!(
                round,
                task_id = selection.task_id,
                scan_id = %selection.scan_id,
                group_id = %selection.group_id,
                forced = selection.forced,
                starvation_detected = selection.starvation_detected,
                wait_rounds = selection.wait_rounds,
                reason = %reason,
                decision,
                "Scheduler decision."
            );
            let _ = scheduler_store::record_event(
                &self.pool,
                Event {
                    round,
                    task_id: Some(selection.task_id),
                    scan_id: Some(&selection.scan_id),
                    group_id: &selection.group_id,
                    decision,
                    reason: &reason,
                    wait_rounds: selection.wait_rounds,
                    queue_duration_ms: selected.queue_duration_ms,
                    execution_duration_ms: Some(selected.execution_duration_ms),
                    forced: selection.forced,
                    starvation_detected: selection.starvation_detected,
                    batch_index,
                },
                Some(&snapshot),
            )
            .await;
            if matches!(outcome, StartOutcome::Deferred(_)) {
                break;
            }
        }

        let final_snapshot = scheduler_store::build_snapshot(
            &self.pool,
            self.scheduling_mode,
            self.max_concurrent_scan,
            round,
        )
        .await?;
        scheduler_store::store_snapshot(&self.pool, &final_snapshot).await?;
        Ok(())
    }

    /// Checks for scans that are requested and may start them.
    async fn requested_to_running(&self) -> anyhow::Result<()> {
        if self.is_feed_sync_in_progress().await {
            tracing::trace!("Skipping to set new scans to running because of feed sync.");
            return Ok(());
        }

        let round = scheduler_store::next_round(&self.pool).await?;
        match self.scheduling_mode {
            SchedulingMode::Fifo => self.requested_to_running_fifo(round).await?,
            SchedulingMode::TargetAware => {
                self.requested_to_running_target_aware(round).await?
            }
        }
        Ok(())
    }

    async fn scan_import_results(
        &self,
        internal_id: i64,
        scan_id: String,
        allow_requeue: bool,
    ) -> anyhow::Result<()> {
        let mut results = match self.scanner.fetch_results(scan_id.clone()).await {
            Ok(x) => x,
            Err(scannerlib::scanner::Error::ScanNotFound(scan_id)) => {
                if !allow_requeue {
                    tracing::debug!(
                        internal_id,
                        scan_id,
                        "Scanner no longer knows the stopped scan; persisted results are kept."
                    );
                    return Ok(());
                }
                let reason = format!("Tried to get results of an unknown scan ({scan_id})");
                return self.scan_running_to_failed(internal_id, &reason).await;
            }
            e => e?,
        };

        let kind = self.scanner.scan_result_status_kind();

        self.scan_insert_results(internal_id, results.results)
            .await?;
        let previous_status = self.scan_state.scan_get_status(internal_id).await?;
        let status = match &kind {
            ScanResultKind::StatusOverride => results.status,
            // TODO: refactor on StatusAddition to do that within SQL directly instead of get mut
            ScanResultKind::StatusAddition => {
                results.status.update_with(&previous_status);
                results.status
            }
        };

        let task = scheduler_store::task_state(&self.pool, internal_id).await?;
        let intermediate_batch = allow_requeue
            && self.scheduling_mode == SchedulingMode::TargetAware
            && status.status == models::Phase::Succeeded
            && task
                .as_ref()
                .is_some_and(|task| task.completed_batches + 1 < task.total_batches);

        if intermediate_batch || !allow_requeue {
            // Preserve host progress but keep the scan in `requested` so the next
            // batch can be scheduled without marking the whole task successful.
            let mut progress_only = status.clone();
            progress_only.status = models::Phase::Requested;
            self.scan_state
                .scan_update_status(internal_id, &progress_only)
                .await?;
            if !allow_requeue {
                return Ok(());
            }
            let _ = self.scanner_delete_scan(internal_id, scan_id.clone()).await;
            self.scan_state
                .change_state(internal_id, "running", "requested")
                .await?;
            let now = target_scheduler::now_millis();
            let state = scheduler_store::batch_finished(&self.pool, internal_id, now).await?;
            let round = scheduler_store::current_round(&self.pool).await?;
            let reason = format!(
                "batch {} of {} completed; scanner slot released for the next batch",
                state
                    .as_ref()
                    .map(|state| state.completed_batches)
                    .unwrap_or_default(),
                state
                    .as_ref()
                    .map(|state| state.total_batches)
                    .unwrap_or_default()
            );
            tracing::info!(
                internal_id,
                scan_id,
                completed_batches = state.as_ref().map(|state| state.completed_batches),
                total_batches = state.as_ref().map(|state| state.total_batches),
                "Scan batch finished; task returned to the queue."
            );
            let _ = scheduler_store::record_event(
                &self.pool,
                Event {
                    round,
                    task_id: Some(internal_id),
                    scan_id: Some(&scan_id),
                    group_id: state
                        .as_ref()
                        .map(|state| state.group_id.as_str())
                        .unwrap_or("unknown"),
                    decision: "batch_completed",
                    reason: &reason,
                    wait_rounds: 0,
                    queue_duration_ms: state.as_ref().and_then(|state| state.queue_duration_ms),
                    execution_duration_ms: state.as_ref().map(|state| state.execution_duration_ms),
                    forced: state.as_ref().is_some_and(|state| state.forced),
                    starvation_detected: state
                        .as_ref()
                        .is_some_and(|state| state.starvation_detected),
                    batch_index: state.as_ref().map(|state| state.completed_batches - 1),
                },
                None,
            )
            .await;
            return Ok(());
        }

        self.scan_state
            .scan_update_status(internal_id, &status)
            .await?;
        if status.is_done() {
            tracing::info!(internal_id, scan_id, status=%status.status, "Scan is finished.");
            if let Err(error) = self
                .scanner_delete_scan(internal_id, scan_id.clone())
                .await
            {
                tracing::debug!(internal_id, %error, "It may be that the scanner self deleted the scan on finish.");
            }
            let final_batch = status.status == models::Phase::Succeeded
                && task.as_ref().is_some_and(|task| {
                    task.total_batches > 1 && task.completed_batches + 1 >= task.total_batches
                });
            if final_batch {
                let now = target_scheduler::now_millis();
                let state =
                    scheduler_store::batch_finished(&self.pool, internal_id, now).await?;
                let round = scheduler_store::current_round(&self.pool).await?;
                let reason = "final batch completed; all target addresses were scanned";
                let _ = scheduler_store::record_event(
                    &self.pool,
                    Event {
                        round,
                        task_id: Some(internal_id),
                        scan_id: Some(&scan_id),
                        group_id: state
                            .as_ref()
                            .map(|state| state.group_id.as_str())
                            .unwrap_or("unknown"),
                        decision: "batch_completed",
                        reason,
                        wait_rounds: 0,
                        queue_duration_ms: state
                            .as_ref()
                            .and_then(|state| state.queue_duration_ms),
                        execution_duration_ms: state
                            .as_ref()
                            .map(|state| state.execution_duration_ms),
                        forced: state.as_ref().is_some_and(|state| state.forced),
                        starvation_detected: state
                            .as_ref()
                            .is_some_and(|state| state.starvation_detected),
                        batch_index: state.as_ref().map(|state| state.completed_batches - 1),
                    },
                    None,
                )
                .await;
            } else if let Err(error) = scheduler_store::finish_task(
                &self.pool,
                internal_id,
                status.status.as_ref(),
                Some("scan reached a terminal phase"),
                false,
            )
            .await
            {
                tracing::warn!(internal_id, %error, "Unable to persist terminal scheduler state.");
            }
        }
        Ok(())
    }

    async fn import_results(&self) -> anyhow::Result<()> {
        let scans = self
            .scan_state
            .fetch_scans_in_state("running", None)
            .await?;

        for id in scans {
            let scan_id = ScanDB::new(&self.pool, id).fetch().await?;
            if let Err(error) = self.scan_import_results(id, scan_id, true).await {
                // we don't return error here as other imports may succeed
                tracing::warn!(id, %error, "Unable to import results of scan.");
            }
        }

        Ok(())
    }

    async fn scanner_delete_scan(&self, internal_id: i64, scan_id: String) -> anyhow::Result<()> {
        tracing::debug!(internal_id, scan_id, "deleting scan from scanner");
        self.scanner.delete_scan(scan_id).await?;
        Ok(())
    }

    async fn scan_stop(&self, id: i64) -> anyhow::Result<()> {
        let scan_id: String = ScanDB::new(&self.pool, id).fetch().await?;

        let current_status = self.scan_state.scan_get_status(id).await?;
        if current_status.is_stopped() {
            tracing::debug!(id, "Scan already stopped");
            return Ok(());
        }

        if current_status.status == models::Phase::Requested {
            self.scan_state
                .change_state(id, "requested", "stopped")
                .await?;
            scheduler_store::finish_task(
                &self.pool,
                id,
                "stopped",
                Some("cancelled while waiting in the queue"),
                true,
            )
            .await?;
            tracing::info!(id, "Cancelled queued scan; no scanner resources were used.");
            return Ok(());
        }

        if current_status.status == models::Phase::Running {
            if let Err(error) = self
                .scan_import_results(id, scan_id.clone(), false)
                .await
            {
                tracing::warn!(id, %error, "Unable to import partial results before stopping scan.");
            }
            if let Err(error) = self.scanner.stop_scan(scan_id.clone()).await {
                tracing::debug!(id, %error, "Scanner scan was already gone while stopping.");
            }
        }
        let changed = self
            .scan_state
            .change_state(id, "running", "stopped")
            .await?;
        scheduler_store::finish_task(
            &self.pool,
            id,
            "stopped",
            Some("cancelled by client; partial results were retained"),
            true,
        )
        .await?;
        tracing::debug!(changed, id, "Changed scan from running to stopped");

        Ok(())
    }

    async fn on_user_action(&self, message: &Message) -> anyhow::Result<()> {
        match message {
            Message::Start(id) => self.scan_to_requested(id.parse()?).await?,
            Message::Stop(id) => self.scan_stop(id.parse()?).await?,
        };
        Ok(())
    }

    async fn on_feed_action(
        &self,
        message: &orchestrator::FeedStatusChange,
    ) -> anyhow::Result<Option<Vec<orchestrator::Allow>>> {
        let msg = message.clone();
        self.feed_sync_in_progress
            .write()
            .await
            .set_based_on_message(&msg);
        let result = match message {
            FeedStatusChange::Need(_) => {
                let count_running: i64 = self.get_running_count().await;
                let is_file_locked = {
                    let mut lockfile = PathBuf::from(self.lock_file_dir.clone());
                    lockfile.push(LOCK_FILE);
                    is_file_locked(lockfile.to_string_lossy().to_string())?
                };
                if self.scan_type() == ScannerType::Openvas && !is_file_locked {
                    Some(self.feed_sync_in_progress.write().await.approve())
                } else if (self.scan_type() == ScannerType::Openvas && is_file_locked)
                    || count_running > 0
                {
                    None
                } else {
                    Some(self.feed_sync_in_progress.write().await.approve())
                }
            }
            FeedStatusChange::Synced(ft) => {
                let scans_allowed = self.feed_sync_in_progress.read().await.scans_allowed();
                tracing::info!(allowing_new_scans=scans_allowed, feed=?ft, "Synchronized");
                None
            }
        };

        Ok(result)
    }

    async fn get_running_count(&self) -> i64 {
        match ScanDB::new(&self.pool, models::Phase::Running)
            .fetch()
            .await
        {
            Ok(x) => x,
            Err(error) => {
                tracing::warn!(
                    %error,
                    "Unable to count running scans, still preventing start of new scans"
                );
                1
            }
        }
    }

    async fn contains_need(&self) -> bool {
        self.feed_sync_in_progress.read().await.contains_need()
    }

    async fn need_to_allow(&self) -> Vec<orchestrator::Allow> {
        self.feed_sync_in_progress.write().await.approve()
    }

    async fn on_schedule(&self) -> anyhow::Result<Vec<orchestrator::Allow>> {
        if self.contains_need().await {
            let count_running = self.get_running_count().await;
            let filelocked = {
                let mut lockfile = PathBuf::from(self.lock_file_dir.clone());
                lockfile.push(LOCK_FILE);
                is_file_locked(lockfile.to_string_lossy().to_string())?
            };
            if count_running == 0 || (self.scan_type() == ScannerType::Openvas && !filelocked) {
                return Ok(self.need_to_allow().await);
            }
        }
        self.requested_to_running().await?;
        self.import_results().await?;

        Ok(vec![])
    }

    fn scan_type(&self) -> ScannerType {
        self.scanner.scanner_type()
    }
}

async fn run_scheduler<S, E>(
    check_interval: std::time::Duration,
    scheduler: ScanScheduler<S, E>,
    feed: orchestrator::Communicator,
) -> anyhow::Result<mpsc::Sender<Message>>
where
    S: Scanner + Send + Sync + 'static,
    E: Crypt + Send + Sync + 'static,
{
    // happens when openvasd was killed when scans did still run
    if let Err(error) = scheduler.running_to_failed().await {
        tracing::warn!(%error, "Unable to set not stopped runs from a previous session to failed.")
    }
    let mut interval = tokio::time::interval(check_interval);
    // The default on missed ticks is bursted. Which means when a tick was missed instead of
    // ticking in the interval after the new time it is immediately triggering missed ticks
    // resulting in immediately calling scheduler.on_schedule. What we would rather do on a missed
    // tick is waiting for that interval until we check again.
    interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let (sender, mut recv) = mpsc::channel(10);
    tokio::spawn(async move {
        let send_allow = async |msgs: Vec<orchestrator::Allow>| {
            for msg in msgs {
                tracing::debug!(feed_type=?msg, "Sending feed sync allow.");
                feed.approve(msg).await?;
            }
            Ok::<(), orchestrator::CommunicationIssues>(())
        };
        loop {
            tokio::select! {
                Some(msg) = feed.receive_state_changes() => {
                    match scheduler.on_feed_action(&msg).await {
                        Ok(Some(msg)) => {
                            if let Err(error) = send_allow(msg).await {
                                tracing::warn!(%error, "Unable to send allow message to orchestrator");
                                break;
                            }
                        }
                        Ok(None) => {},
                        Err(error) =>  tracing::warn!(?msg, %error, "Unable to react on feed message"),

                    }


                }
                Some(msg) = recv.recv() => {
                    if let Err(error) = scheduler.on_user_action(&msg).await {
                        tracing::warn!(?msg, %error, "Unable to react on message");
                    }

                }

                _ = interval.tick() => {
                    match scheduler.on_schedule().await {
                        Err(error) => tracing::warn!(%error, "Unable to schedule"),
                        Ok(msgs) => {
                            if let Err(error) = send_allow(msgs).await {
                                tracing::warn!(%error, "Unable to send allow message to orchestrator");
                                break;
                            }
                        }

                    }
                }


                else => {
                    tracing::debug!("Channel closed, good bye");
                    break;
                }
            }
        }
    });

    Ok(sender)
}

pub(super) async fn init_with_scanner<E, S>(
    pool: DataBase,
    crypter: Arc<E>,
    config: &Config,
    scanner: S,
    feed: orchestrator::Communicator,
) -> anyhow::Result<Sender<Message>>
where
    S: Scanner + Send + Sync + 'static,
    E: Crypt + Send + Sync + 'static,
{
    let change_scan_status = ScanStateController::init(pool.clone()).await?;
    let scheduler = ScanScheduler {
        pool,
        cryptor: crypter,
        max_concurrent_scan: config
            .scheduler
            .max_running_scans
            .or(config.scheduler.max_queued_scans)
            .unwrap_or(0),
        scanner: Arc::new(scanner),
        feed_sync_in_progress: Arc::new(RwLock::new(IsInProgress::default())),
        scan_state: change_scan_status,
        lock_file_dir: config.feed.lock_file_dir().to_string_lossy().to_string(),
        scheduling_mode: config.scheduler.mode,
        starvation_threshold: config.scheduler.starvation_threshold,
        batch_config: BatchConfig {
            strategy: config.scheduler.batch_strategy,
            batch_size: config.scheduler.batch_size,
            v4_prefix: config.scheduler.group_prefix_v4,
            v6_prefix: config.scheduler.group_prefix_v6,
        },
    };

    run_scheduler(config.scheduler.check_interval, scheduler, feed).await
}

fn openvas_scanner(config: &Config, sudo: bool, redis_url: String) -> openvas::OpenvasScanner {
    openvas::OpenvasScanner::new(
        config.scheduler.min_free_mem,
        None, // cpu_option are not available currently
        sudo,
        redis_url,
        config.scanner.preferences.clone(),
    )
}

pub async fn init<E>(
    pool: DataBase,
    crypter: Arc<E>,
    config: &Config,
    feed_status: orchestrator::Communicator,
) -> anyhow::Result<Sender<Message>>
where
    E: Crypt + Send + Sync + 'static,
{
    match config.scanner.scanner_type {
        scanner_types::ScannerType::Ospd => {
            //TODO: when in notus don't start scheduler at all
            if !config.scanner.ospd.socket.exists()
                && config.mode != crate::config::Mode::ServiceNotus
            {
                tracing::warn!(
                    "OSPD socket {} does not exist. Some commands will not work until the socket is created!",
                    config.scanner.ospd.socket.display()
                );
            }
            let scanner = osp::OspScanner::new(
                config.scanner.ospd.socket.clone(),
                config.scanner.ospd.read_timeout,
            );
            init_with_scanner(pool, crypter, config, scanner, feed_status).await
        }
        scanner_types::ScannerType::Openvas => {
            let redis_url = cmd::get_redis_socket().await;
            let scanner = openvas_scanner(config, cmd::check_sudo(), redis_url);

            init_with_scanner(pool, crypter, config, scanner, feed_status).await
        }
        scanner_types::ScannerType::Openvasd => {
            let loader = Loader::from_feed_path(&config.feed.path);
            let executor = nasl_std_executor();
            let notus = config
                .notus
                .url
                .clone()
                .map(scannerlib::nasl::utils::ctx::NotusCtx::Address);
            let storage = ScanStorage::new(
                pool.clone(),
                config.feed.path.clone(),
                config.feed.signature_check,
            );
            let scanner = OpenvasdScanner::new(storage, loader, executor, notus);
            init_with_scanner(pool, crypter, config, scanner, feed_status).await
        }
        _ => panic!("Invalid Scanner type"),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::{
        collections::HashMap,
        sync::Mutex,
    };

    use scannerlib::{
        models::{self, Status},
        scanner::{self, ScanResults, TestScannerBuilder, preferences::preference::ScanPrefValue},
    };
    use sqlx::query_scalar;

    use super::*;
    use crate::{
        config::BatchStrategy,
        crypt::Crypter,
        database::{dao::Execute, sqlite::DbGuard},
        scans::tests::{create_pool, prepare_scans},
    };

    async fn setup_test_env() -> anyhow::Result<(
        ScanScheduler<scanner::TestScanner, Crypter>,
        Vec<i64>,
        DbGuard,
    )> {
        setup_test_env_with_scanner(TestScannerBuilder::default()).await
    }

    async fn setup_test_env_with_scanner(
        builder: TestScannerBuilder,
    ) -> anyhow::Result<(
        ScanScheduler<scanner::TestScanner, Crypter>,
        Vec<i64>,
        DbGuard,
    )> {
        setup_test_env_with_scanner_and_feed_messages(builder, Default::default()).await
    }

    async fn setup_test_env_with_scanner_and_feed_messages(
        builder: TestScannerBuilder,
        feed_changes: IsInProgress,
    ) -> anyhow::Result<(
        ScanScheduler<scanner::TestScanner, Crypter>,
        Vec<i64>,
        DbGuard,
    )> {
        let (config, pool, guard) = create_pool().await?;
        let scanner = Arc::new(builder.build());
        let cryptor = Arc::new(Crypter::from_config(&config, &pool).await?);

        let change_scan_status = ScanStateController::init(pool.clone()).await?;
        let under_test = ScanScheduler {
            pool: pool.clone(),
            scanner,
            cryptor,
            max_concurrent_scan: 4,
            feed_sync_in_progress: Arc::new(RwLock::new(feed_changes)),
            scan_state: change_scan_status,
            lock_file_dir: String::new(),
            scheduling_mode: SchedulingMode::Fifo,
            starvation_threshold: 5,
            batch_config: BatchConfig::default(),
        };
        let known_scans = prepare_scans(pool.clone(), &config).await;
        Ok((under_test, known_scans, guard))
    }

    async fn insert_test_scan(
        pool: &DataBase,
        config: &Config,
        scan_id: &str,
        hosts: Vec<String>,
        depends_on: Vec<String>,
    ) -> anyhow::Result<i64> {
        let crypter = Crypter::from_config(config, pool).await?;
        let dependencies = serde_json::to_string(&depends_on)?;
        let scan = models::Scan {
            scan_id: scan_id.to_string(),
            target: models::Target {
                hosts,
                ..Default::default()
            },
            scan_preferences: (!depends_on.is_empty())
                .then_some(models::ScanPreference {
                    id: "depends_on".to_string(),
                    value: dependencies,
                })
                .into_iter()
                .collect(),
            vts: vec![],
        };
        ScanDB::new(pool, (&crypter, "test-client", &scan))
            .exec()
            .await?;
        Ok(query_scalar("SELECT id FROM client_scan_map WHERE scan_id = ?")
            .bind(scan_id)
            .fetch_one(pool)
            .await?)
    }

    async fn setup_target_aware(
        builder: TestScannerBuilder,
        batch_size: usize,
    ) -> anyhow::Result<(ScanScheduler<scanner::TestScanner, Crypter>, Config, DataBase, DbGuard)>
    {
        let (mut config, pool, guard) = create_pool().await?;
        config.scheduler.mode = SchedulingMode::TargetAware;
        config.scheduler.batch_size = batch_size;
        let crypter = Arc::new(Crypter::from_config(&config, &pool).await?);
        let under_test = ScanScheduler {
            pool: pool.clone(),
            scanner: Arc::new(builder.build()),
            cryptor: crypter,
            max_concurrent_scan: 4,
            feed_sync_in_progress: Arc::new(RwLock::new(IsInProgress::default())),
            scan_state: ScanStateController::init(pool.clone()).await?,
            lock_file_dir: String::new(),
            scheduling_mode: SchedulingMode::TargetAware,
            starvation_threshold: 5,
            batch_config: BatchConfig {
                strategy: BatchStrategy::Count,
                batch_size,
                v4_prefix: 24,
                v6_prefix: 64,
            },
        };
        Ok((under_test, config, pool, guard))
    }

    #[test]
    fn openvas_scanner_uses_configured_preferences() {
        let mut config = Config::default();
        config.scanner.preferences = HashMap::from([
            ("safe_checks".to_string(), ScanPrefValue::Bool(false.into())),
            ("plugins_timeout".to_string(), ScanPrefValue::Int(11)),
        ]);

        let scanner = openvas_scanner(&config, false, "redis://localhost".to_string());

        assert_eq!(scanner.scan_preferences(), &config.scanner.preferences);
    }

    #[tokio::test]
    async fn start_scan() -> anyhow::Result<()> {
        let (under_test, known_scans, _guard) = setup_test_env().await?;

        for id in known_scans.iter() {
            under_test
                .on_user_action(&Message::Start(id.to_string()))
                .await?;
        }
        let status: Vec<String> = query_scalar("SELECT status FROM scans")
            .fetch_all(&under_test.pool)
            .await?;
        assert_eq!(status.len(), known_scans.len());
        assert_eq!(
            status.iter().filter(|s| s as &str == "requested").count(),
            status.len()
        );

        Ok(())
    }

    #[tokio::test]
    async fn run_scans() -> anyhow::Result<()> {
        let (under_test, known_scans, _guard) = setup_test_env().await?;

        for id in known_scans.iter() {
            under_test
                .on_user_action(&Message::Start(id.to_string()))
                .await?;
        }
        under_test.on_schedule().await?;
        let status: Vec<String> = query_scalar("SELECT status FROM scans")
            .fetch_all(&under_test.pool)
            .await?;
        assert!(known_scans.len() > under_test.max_concurrent_scan);
        assert_eq!(status.len(), known_scans.len());
        assert_eq!(
            status.iter().filter(|s| s as &str == "running").count(),
            under_test.max_concurrent_scan
        );
        let start_times: Vec<i64> =
            query_scalar("SELECT start_time FROM scans WHERE status = 'running'")
                .fetch_all(&under_test.pool)
                .await?;
        assert_eq!(
            start_times.iter().filter(|x| x > &&0).count(),
            start_times.len()
        );

        Ok(())
    }

    pub(crate) fn scanner_succeeded() -> TestScannerBuilder {
        TestScannerBuilder::new().with_fetch(|id| {
            let results = vec![
                models::Result {
                    id: 0,
                    r_type: models::ResultType::Alarm,
                    ip_address: None,
                    hostname: None,
                    oid: None,
                    port: None,
                    protocol: None,
                    message: None,
                    detail: None,
                },
                models::Result {
                    id: 1,
                    r_type: models::ResultType::Log,
                    ip_address: Some("127.0.0.1".to_string()),
                    hostname: Some("localhost".to_string()),
                    oid: Some("1".to_string()),
                    port: Some(22),
                    protocol: Some(models::Protocol::UDP),
                    message: Some("hooary".to_string()),
                    detail: Some(models::Detail {
                        name: "detail_name".to_string(),
                        value: "detail_value".to_string(),
                        source: models::Source {
                            s_type: "dunno".to_string(),
                            name: "something".to_string(),
                            description: "found something in don't know".to_string(),
                        },
                    }),
                },
            ];

            Ok(ScanResults {
                id: id.to_string(),
                status: Status {
                    status: models::Phase::Succeeded,
                    ..Default::default()
                },
                results,
            })
        })
    }

    #[tokio::test]
    // maybe create a function of that so that it can be used within scans testing
    async fn reflect_status_phase_of_scan() -> anyhow::Result<()> {
        let (under_test, known_scans, _guard) =
            setup_test_env_with_scanner(scanner_succeeded()).await?;

        for id in known_scans.iter() {
            under_test
                .on_user_action(&Message::Start(id.to_string()))
                .await?;
        }
        under_test.on_schedule().await?;
        let status: Vec<String> = query_scalar("SELECT status FROM scans")
            .fetch_all(&under_test.pool)
            .await?;
        assert!(known_scans.len() > under_test.max_concurrent_scan);
        assert_eq!(status.len(), known_scans.len());
        assert_eq!(
            status.iter().filter(|s| s as &str == "succeeded").count(),
            under_test.max_concurrent_scan
        );

        let end_times: Vec<i64> =
            query_scalar("SELECT end_time FROM scans WHERE status = 'succeeded'")
                .fetch_all(&under_test.pool)
                .await?;
        assert_eq!(
            end_times.iter().filter(|x| x > &&0).count(),
            end_times.len()
        );
        let result_count: i64 = query_scalar("SELECT count(*) FROM results")
            .fetch_one(&under_test.pool)
            .await?;
        assert_eq!(result_count, (under_test.max_concurrent_scan * 2) as i64);

        Ok(())
    }

    #[tokio::test]
    async fn run_scans_failure() -> anyhow::Result<()> {
        let (under_test, known_scans, _guard) = setup_test_env_with_scanner(
            TestScannerBuilder::new()
                .with_start(|_| Err(scanner::Error::Unexpected("nada".to_string()))),
        )
        .await?;

        for id in known_scans.iter() {
            under_test
                .on_user_action(&Message::Start(id.to_string()))
                .await?;
        }
        under_test.on_schedule().await?;
        let status: Vec<String> = query_scalar("SELECT status FROM scans")
            .fetch_all(&under_test.pool)
            .await?;
        assert!(known_scans.len() > under_test.max_concurrent_scan);
        assert_eq!(status.len(), known_scans.len());
        assert_eq!(
            status.iter().filter(|s| s as &str == "failed").count(),
            under_test.max_concurrent_scan
        );

        let end_times: Vec<i64> =
            query_scalar("SELECT end_time FROM scans WHERE status = 'failed'")
                .fetch_all(&under_test.pool)
                .await?;
        assert_eq!(
            end_times.iter().filter(|x| x > &&0).count(),
            end_times.len()
        );

        Ok(())
    }

    #[tokio::test]
    async fn scanner_connection_failure_keeps_scans_queued() -> anyhow::Result<()> {
        let (under_test, known_scans, _guard) = setup_test_env_with_scanner(
            TestScannerBuilder::new()
                .with_start(|_| Err(scanner::Error::Connection("pool down".to_string()))),
        )
        .await?;

        for id in known_scans.iter() {
            under_test
                .on_user_action(&Message::Start(id.to_string()))
                .await?;
        }
        under_test.on_schedule().await?;
        let status: Vec<String> = query_scalar("SELECT status FROM scans")
            .fetch_all(&under_test.pool)
            .await?;
        assert_eq!(
            status.iter().filter(|s| s as &str == "requested").count(),
            status.len()
        );
        Ok(())
    }

    #[tokio::test]
    async fn do_not_start_when_scanner_cannot_start_scan() -> anyhow::Result<()> {
        let (under_test, known_scans, _guard) =
            setup_test_env_with_scanner(TestScannerBuilder::new().with_can_start(|| false)).await?;

        for id in known_scans.iter() {
            under_test
                .on_user_action(&Message::Start(id.to_string()))
                .await?;
        }
        let status: Vec<String> = query_scalar("SELECT status FROM scans")
            .fetch_all(&under_test.pool)
            .await?;
        assert_eq!(status.len(), known_scans.len());
        assert_eq!(
            status.iter().filter(|s| s as &str == "requested").count(),
            status.len()
        );

        Ok(())
    }

    #[tokio::test]
    async fn do_not_start_on_feed_sync() -> anyhow::Result<()> {
        let iip = IsInProgress {
            need_approval_nasl: true,
            ..Default::default()
        };
        let (under_test, known_scans, _guard) =
            setup_test_env_with_scanner_and_feed_messages(TestScannerBuilder::new(), iip).await?;

        for id in known_scans.iter() {
            under_test
                .on_user_action(&Message::Start(id.to_string()))
                .await?;
        }
        let status: Vec<String> = query_scalar("SELECT status FROM scans")
            .fetch_all(&under_test.pool)
            .await?;
        assert_eq!(status.len(), known_scans.len());
        assert_eq!(
            status.iter().filter(|s| s as &str == "requested").count(),
            status.len()
        );

        Ok(())
    }

    #[test]
    fn need_after_failed_sync_is_approved_again() {
        let mut iip = IsInProgress::default();
        iip.set_based_on_message(&FeedStatusChange::Need(FeedType::NASL));
        assert_eq!(iip.approve(), vec![FeedType::NASL]);
        assert!(!iip.scans_allowed());

        // The feed update failed, therefore no `Synced` message was sent. The next feed check
        // requests approval again.
        iip.set_based_on_message(&FeedStatusChange::Need(FeedType::NASL));
        assert!(iip.contains_need());
        assert_eq!(iip.approve(), vec![FeedType::NASL]);

        iip.set_based_on_message(&FeedStatusChange::Synced(FeedType::NASL));
        assert!(iip.scans_allowed());
    }

    #[tokio::test]
    async fn target_aware_serializes_same_network() -> anyhow::Result<()> {
        let starts = Arc::new(Mutex::new(Vec::new()));
        let recorded_starts = starts.clone();
        let builder = TestScannerBuilder::new()
            .with_start(move |scan| {
                recorded_starts.lock().unwrap().push(scan);
                Ok(())
            })
            .with_fetch(|id| {
                Ok(ScanResults {
                    id: id.to_string(),
                    status: Status {
                        status: models::Phase::Running,
                        ..Default::default()
                    },
                    results: vec![],
                })
            });
        let (under_test, config, pool, _guard) = setup_target_aware(builder, 256).await?;

        let mut ids = Vec::new();
        for index in 1..=5 {
            ids.push(
                insert_test_scan(
                    &pool,
                    &config,
                    &format!("same-{index}"),
                    vec![format!("10.0.0.{index}")],
                    vec![],
                )
                .await?,
            );
            ids.push(
                insert_test_scan(
                    &pool,
                    &config,
                    &format!("other-{index}"),
                    vec![format!("10.0.1.{index}")],
                    vec![],
                )
                .await?,
            );
        }
        for id in &ids {
            under_test
                .on_user_action(&Message::Start(id.to_string()))
                .await?;
        }

        under_test.on_schedule().await?;
        under_test.on_schedule().await?;

        let running: i64 = query_scalar("SELECT count(*) FROM scans WHERE status = 'running'")
            .fetch_one(&pool)
            .await?;
        assert_eq!(running, 2, "only one task per target group may run");
        let starts = starts.lock().unwrap();
        assert_eq!(starts.len(), 2);
        let groups = starts
            .iter()
            .map(|scan| {
                scan.target.hosts[0]
                    .rsplit_once('.')
                    .map(|(prefix, _)| prefix.to_string())
                    .unwrap()
            })
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(groups.len(), 2);
        Ok(())
    }

    #[tokio::test]
    async fn scheduling_records_contain_queue_and_execution_times() -> anyhow::Result<()> {
        let starts = Arc::new(Mutex::new(Vec::new()));
        let recorded_starts = starts.clone();
        let builder = TestScannerBuilder::new()
            .with_start(move |scan| {
                recorded_starts.lock().unwrap().push(scan);
                Ok(())
            })
            .with_fetch(|id| {
                Ok(ScanResults {
                    id: id.to_string(),
                    status: Status {
                        status: models::Phase::Succeeded,
                        ..Default::default()
                    },
                    results: vec![],
                })
            });
        let (under_test, config, pool, _guard) = setup_target_aware(builder, 256).await?;

        let mut ids = Vec::new();
        for index in 1..=10 {
            ids.push(
                insert_test_scan(
                    &pool,
                    &config,
                    &format!("record-{index}"),
                    vec![format!("10.0.{}.{}", index % 2, index)],
                    vec![],
                )
                .await?,
            );
        }
        for id in &ids {
            under_test
                .on_user_action(&Message::Start(id.to_string()))
                .await?;
        }
        for _ in 0..10 {
            under_test.on_schedule().await?;
        }

        let succeeded: i64 = query_scalar("SELECT count(*) FROM scans WHERE status = 'succeeded'")
            .fetch_one(&pool)
            .await?;
        assert_eq!(succeeded, 10);
        assert_eq!(starts.lock().unwrap().len(), 10);

        let records = scheduler_store::schedule_records(&pool).await?;
        assert_eq!(records.len(), 10);
        for record in records {
            assert!(record.started_at.is_some(), "{record:?}");
            assert!(record.finished_at.is_some(), "{record:?}");
            assert!(record.queue_duration_ms.is_some(), "{record:?}");
            assert!(record.execution_duration_ms.is_some(), "{record:?}");
        }
        Ok(())
    }

    #[tokio::test]
    async fn large_target_releases_resources_between_batches() -> anyhow::Result<()> {
        let starts = Arc::new(Mutex::new(Vec::new()));
        let recorded_starts = starts.clone();
        let builder = TestScannerBuilder::new()
            .with_start(move |scan| {
                recorded_starts.lock().unwrap().push(scan);
                Ok(())
            })
            .with_fetch(|id| {
                Ok(ScanResults {
                    id: id.to_string(),
                    status: Status {
                        status: models::Phase::Succeeded,
                        ..Default::default()
                    },
                    results: vec![],
                })
            });
        let (under_test, config, pool, _guard) = setup_target_aware(builder, 2).await?;
        let id = insert_test_scan(
            &pool,
            &config,
            "batched",
            vec!["10.0.0.1-5".to_string()],
            vec![],
        )
        .await?;
        under_test
            .on_user_action(&Message::Start(id.to_string()))
            .await?;

        for _ in 0..8 {
            under_test.on_schedule().await?;
        }

        let batches = starts
            .lock()
            .unwrap()
            .iter()
            .map(|scan| scan.target.hosts.len())
            .collect::<Vec<_>>();
        assert_eq!(batches, vec![2, 2, 1]);
        let status: String = query_scalar("SELECT status FROM scans WHERE id = ?")
            .bind(id)
            .fetch_one(&pool)
            .await?;
        assert_eq!(status, "succeeded");
        let record = scheduler_store::schedule_records(&pool)
            .await?
            .into_iter()
            .find(|record| record.task_id == id)
            .unwrap();
        assert_eq!(record.total_batches, 3);
        assert_eq!(record.completed_batches, 3);
        Ok(())
    }

    #[tokio::test]
    async fn cancelling_running_batch_keeps_partial_results() -> anyhow::Result<()> {
        let (under_test, config, pool, _guard) =
            setup_target_aware(scanner_succeeded(), 2).await?;
        let id = insert_test_scan(
            &pool,
            &config,
            "cancelled",
            vec!["10.0.0.1-5".to_string()],
            vec![],
        )
        .await?;
        under_test
            .on_user_action(&Message::Start(id.to_string()))
            .await?;
        under_test.requested_to_running().await?;

        under_test
            .on_user_action(&Message::Stop(id.to_string()))
            .await?;

        let status: String = query_scalar("SELECT status FROM scans WHERE id = ?")
            .bind(id)
            .fetch_one(&pool)
            .await?;
        assert_eq!(status, "stopped");
        let results: i64 = query_scalar("SELECT count(*) FROM results WHERE scan_id = ?")
            .bind(id)
            .fetch_one(&pool)
            .await?;
        assert!(results > 0, "partial results must be retained");
        let record = scheduler_store::schedule_records(&pool)
            .await?
            .into_iter()
            .find(|record| record.task_id == id)
            .unwrap();
        assert!(record.cancelled);
        Ok(())
    }

    #[tokio::test]
    async fn failed_dependency_marks_downstream_not_executed() -> anyhow::Result<()> {
        let builder = TestScannerBuilder::new()
            .with_start(|_| Err(scanner::Error::Unexpected("scanner failed".to_string())));
        let (under_test, config, pool, _guard) = setup_target_aware(builder, 256).await?;
        let dependency = insert_test_scan(
            &pool,
            &config,
            "dependency",
            vec!["10.0.0.1".to_string()],
            vec![],
        )
        .await?;
        let downstream = insert_test_scan(
            &pool,
            &config,
            "downstream",
            vec!["10.0.0.2".to_string()],
            vec!["dependency".to_string()],
        )
        .await?;
        for id in [dependency, downstream] {
            under_test
                .on_user_action(&Message::Start(id.to_string()))
                .await?;
        }

        under_test.on_schedule().await?;
        under_test.on_schedule().await?;

        let dependency_status: String = query_scalar("SELECT status FROM scans WHERE id = ?")
            .bind(dependency)
            .fetch_one(&pool)
            .await?;
        let downstream_status: String = query_scalar("SELECT status FROM scans WHERE id = ?")
            .bind(downstream)
            .fetch_one(&pool)
            .await?;
        assert_eq!(dependency_status, "failed");
        assert_eq!(downstream_status, "not_executed");
        Ok(())
    }

    #[tokio::test]
    async fn target_resolution_failure_does_not_block_other_scans() -> anyhow::Result<()> {
        let (under_test, config, pool, _guard) =
            setup_target_aware(TestScannerBuilder::new(), 256).await?;
        let invalid = insert_test_scan(
            &pool,
            &config,
            "invalid-target",
            vec!["invalid host name !!!".to_string()],
            vec![],
        )
        .await?;
        let valid = insert_test_scan(
            &pool,
            &config,
            "valid-target",
            vec!["10.0.0.1".to_string()],
            vec![],
        )
        .await?;
        for id in [invalid, valid] {
            under_test
                .on_user_action(&Message::Start(id.to_string()))
                .await?;
        }

        under_test.on_schedule().await?;

        let invalid_status: String = query_scalar("SELECT status FROM scans WHERE id = ?")
            .bind(invalid)
            .fetch_one(&pool)
            .await?;
        let valid_status: String = query_scalar("SELECT status FROM scans WHERE id = ?")
            .bind(valid)
            .fetch_one(&pool)
            .await?;
        assert_eq!(invalid_status, "failed");
        assert_eq!(valid_status, "running");
        Ok(())
    }
}
