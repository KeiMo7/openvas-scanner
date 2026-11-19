// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::collections::HashSet;

use serde_json::Value;
use sqlx::{Row, SqlitePool, query, query_scalar};

use super::target_scheduler::{
    self, DependencyReadiness, GroupRuntime, GroupSnapshot, PendingTask, QueueSnapshot,
    QueueTaskSnapshot, TaskScheduleRecord,
};
use crate::config::{BatchStrategy, SchedulingMode};

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct StoredTaskState {
    pub id: i64,
    pub scan_id: String,
    pub group_id: String,
    pub target_ranges: Vec<String>,
    pub enqueued_at: i64,
    pub started_at: Option<i64>,
    pub finished_at: Option<i64>,
    pub last_started_at: Option<i64>,
    pub queue_duration_ms: Option<i64>,
    pub execution_duration_ms: i64,
    pub depends_on: Vec<String>,
    pub current_batch: usize,
    pub completed_batches: usize,
    pub total_batches: usize,
    pub batch_strategy: BatchStrategy,
    pub batch_size: usize,
    pub cancelled: bool,
    pub status: String,
    pub reason: Option<String>,
    pub forced: bool,
    pub starvation_detected: bool,
}

fn json_strings(value: &str) -> Vec<String> {
    serde_json::from_str::<Vec<String>>(value).unwrap_or_default()
}

fn strategy(value: &str) -> BatchStrategy {
    serde_json::from_value(Value::String(value.to_string())).unwrap_or_default()
}

fn strategy_name(value: BatchStrategy) -> &'static str {
    match value {
        BatchStrategy::Count => "count",
        BatchStrategy::AddressSegment => "address_segment",
    }
}

fn row_to_state(row: sqlx::sqlite::SqliteRow) -> StoredTaskState {
    StoredTaskState {
        id: row.get("id"),
        scan_id: row.get("scan_id"),
        group_id: row.get("group_id"),
        target_ranges: json_strings(row.get::<String, _>("target_ranges").as_str()),
        enqueued_at: row.get("enqueued_at"),
        started_at: row.get("started_at"),
        finished_at: row.get("finished_at"),
        last_started_at: row.get("last_started_at"),
        queue_duration_ms: row.get("queue_duration_ms"),
        execution_duration_ms: row.get("execution_duration_ms"),
        depends_on: json_strings(row.get::<String, _>("depends_on").as_str()),
        current_batch: row.get::<i64, _>("current_batch") as usize,
        completed_batches: row.get::<i64, _>("completed_batches") as usize,
        total_batches: row.get::<i64, _>("total_batches") as usize,
        batch_strategy: strategy(row.get::<String, _>("batch_strategy").as_str()),
        batch_size: row.get::<i64, _>("batch_size") as usize,
        cancelled: row.get::<i64, _>("cancelled") != 0,
        status: row.get("status"),
        reason: row.get("reason"),
        forced: row.get::<i64, _>("forced") != 0,
        starvation_detected: row.get::<i64, _>("starvation_detected") != 0,
    }
}

pub async fn enqueue_task(
    pool: &SqlitePool,
    id: i64,
    group_id: &str,
    target_ranges: &[String],
    depends_on: &[String],
    batch_strategy: BatchStrategy,
    batch_size: usize,
    total_batches: usize,
) -> Result<(), sqlx::Error> {
    let now = target_scheduler::now_millis();
    query(
        r#"
        INSERT INTO scheduler_task_state (
            id, group_id, target_ranges, enqueued_at, depends_on,
            current_batch, completed_batches, total_batches,
            batch_strategy, batch_size, cancelled, status, reason,
            forced, starvation_detected
        )
        VALUES (?, ?, ?, ?, ?, 0, 0, ?, ?, ?, 0, 'queued', NULL, 0, 0)
        ON CONFLICT(id) DO UPDATE SET
            group_id = excluded.group_id,
            target_ranges = excluded.target_ranges,
            enqueued_at = excluded.enqueued_at,
            started_at = NULL,
            finished_at = NULL,
            last_started_at = NULL,
            queue_duration_ms = NULL,
            execution_duration_ms = 0,
            depends_on = excluded.depends_on,
            current_batch = 0,
            completed_batches = 0,
            total_batches = excluded.total_batches,
            batch_strategy = excluded.batch_strategy,
            batch_size = excluded.batch_size,
            cancelled = 0,
            status = 'queued',
            reason = NULL,
            forced = 0,
            starvation_detected = 0
        "#,
    )
    .bind(id)
    .bind(group_id)
    .bind(serde_json::to_string(target_ranges).unwrap_or_else(|_| "[]".to_string()))
    .bind(now)
    .bind(serde_json::to_string(depends_on).unwrap_or_else(|_| "[]".to_string()))
    .bind(total_batches.max(1) as i64)
    .bind(strategy_name(batch_strategy))
    .bind(batch_size.max(1) as i64)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn task_state(
    pool: &SqlitePool,
    id: i64,
) -> Result<Option<StoredTaskState>, sqlx::Error> {
    let row = query(
        r#"
        SELECT s.id, csm.scan_id, s.group_id, s.target_ranges, s.enqueued_at,
               s.started_at, s.finished_at, s.last_started_at, s.queue_duration_ms,
               s.execution_duration_ms, s.depends_on, s.current_batch,
               s.completed_batches, s.total_batches, s.batch_strategy, s.batch_size,
               s.cancelled, s.status, s.reason, s.forced, s.starvation_detected
        FROM scheduler_task_state s
        JOIN client_scan_map csm ON csm.id = s.id
        WHERE s.id = ?
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(row_to_state))
}

pub async fn queued_task_states(
    pool: &SqlitePool,
) -> Result<Vec<StoredTaskState>, sqlx::Error> {
    let rows = query(
        r#"
        SELECT s.id, csm.scan_id, s.group_id, s.target_ranges, s.enqueued_at,
               s.started_at, s.finished_at, s.last_started_at, s.queue_duration_ms,
               s.execution_duration_ms, s.depends_on, s.current_batch,
               s.completed_batches, s.total_batches, s.batch_strategy, s.batch_size,
               s.cancelled, s.status, s.reason, s.forced, s.starvation_detected
        FROM scheduler_task_state s
        JOIN client_scan_map csm ON csm.id = s.id
        JOIN scans sc ON sc.id = s.id
        WHERE sc.status = 'requested' AND s.cancelled = 0
        ORDER BY s.enqueued_at, s.id
        "#,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(row_to_state).collect())
}

pub async fn running_task_states(
    pool: &SqlitePool,
) -> Result<Vec<StoredTaskState>, sqlx::Error> {
    let rows = query(
        r#"
        SELECT s.id, csm.scan_id, s.group_id, s.target_ranges, s.enqueued_at,
               s.started_at, s.finished_at, s.last_started_at, s.queue_duration_ms,
               s.execution_duration_ms, s.depends_on, s.current_batch,
               s.completed_batches, s.total_batches, s.batch_strategy, s.batch_size,
               s.cancelled, s.status, s.reason, s.forced, s.starvation_detected
        FROM scheduler_task_state s
        JOIN client_scan_map csm ON csm.id = s.id
        JOIN scans sc ON sc.id = s.id
        WHERE sc.status = 'running' AND s.cancelled = 0
        ORDER BY s.enqueued_at, s.id
        "#,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(row_to_state).collect())
}

async fn dependency_readiness(
    pool: &SqlitePool,
    id: i64,
    current_scan_id: &str,
    depends_on: &[String],
) -> Result<DependencyReadiness, sqlx::Error> {
    if depends_on.is_empty() {
        return Ok(DependencyReadiness::Ready);
    }

    let client_id: Option<String> =
        query_scalar("SELECT client_id FROM client_scan_map WHERE id = ?")
            .bind(id)
            .fetch_optional(pool)
            .await?;
    let Some(client_id) = client_id else {
        return Ok(DependencyReadiness::Failed(depends_on.to_vec()));
    };

    let mut waiting = Vec::new();
    let mut failed = Vec::new();
    for dependency in depends_on {
        if dependency == current_scan_id {
            failed.push(dependency.clone());
            continue;
        }
        let status: Option<String> = query_scalar(
            r#"
            SELECT sc.status
            FROM client_scan_map csm
            LEFT JOIN scans sc ON sc.id = csm.id
            WHERE csm.client_id = ? AND csm.scan_id = ?
            "#,
        )
        .bind(&client_id)
        .bind(dependency)
        .fetch_optional(pool)
        .await?;
        match status.as_deref() {
            Some("succeeded") => {}
            Some("failed" | "stopped" | "not_executed") | None => failed.push(dependency.clone()),
            Some(_) => waiting.push(dependency.clone()),
        }
    }

    if !failed.is_empty() {
        Ok(DependencyReadiness::Failed(failed))
    } else if !waiting.is_empty() {
        Ok(DependencyReadiness::Waiting(waiting))
    } else {
        Ok(DependencyReadiness::Ready)
    }
}

pub async fn pending_tasks(pool: &SqlitePool) -> Result<Vec<PendingTask>, sqlx::Error> {
    let states = queued_task_states(pool).await?;
    let mut tasks = Vec::with_capacity(states.len());
    for state in states {
        let dependencies =
            dependency_readiness(pool, state.id, &state.scan_id, &state.depends_on).await?;
        tasks.push(PendingTask {
            id: state.id,
            scan_id: state.scan_id,
            group_id: state.group_id,
            target_ranges: state.target_ranges,
            enqueued_at: state.enqueued_at,
            dependencies,
            current_batch: state.current_batch,
            total_batches: state.total_batches,
        });
    }
    Ok(tasks)
}

pub async fn group_states(pool: &SqlitePool) -> Result<Vec<GroupRuntime>, sqlx::Error> {
    let rows = query(
        r#"
        SELECT group_id, target_ranges, enqueued_at, wait_rounds, skipped_rounds,
               forced, current_load, last_skip_reason, starvation_detected
        FROM scheduler_group_state
        "#,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| GroupRuntime {
            group_id: row.get("group_id"),
            target_ranges: json_strings(row.get::<String, _>("target_ranges").as_str()),
            enqueued_at: row.get("enqueued_at"),
            wait_rounds: row.get::<i64, _>("wait_rounds") as u32,
            skipped_rounds: row.get::<i64, _>("skipped_rounds") as u32,
            forced: row.get::<i64, _>("forced") != 0,
            current_load: row.get::<i64, _>("current_load") as usize,
            last_skip_reason: row.get("last_skip_reason"),
            starvation_detected: row.get::<i64, _>("starvation_detected") != 0,
        })
        .collect())
}

pub async fn save_group_states(
    pool: &SqlitePool,
    groups: &[GroupRuntime],
) -> Result<(), sqlx::Error> {
    let now = target_scheduler::now_millis();
    for group in groups {
        query(
            r#"
            INSERT INTO scheduler_group_state (
                group_id, target_ranges, enqueued_at, wait_rounds, skipped_rounds,
                forced, current_load, last_skip_reason, starvation_detected,
                updated_at, last_scheduled_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(group_id) DO UPDATE SET
                target_ranges = excluded.target_ranges,
                enqueued_at = excluded.enqueued_at,
                wait_rounds = excluded.wait_rounds,
                skipped_rounds = excluded.skipped_rounds,
                forced = excluded.forced,
                current_load = excluded.current_load,
                last_skip_reason = excluded.last_skip_reason,
                starvation_detected = excluded.starvation_detected,
                updated_at = excluded.updated_at,
                last_scheduled_at = COALESCE(excluded.last_scheduled_at, scheduler_group_state.last_scheduled_at)
            "#,
        )
        .bind(&group.group_id)
        .bind(serde_json::to_string(&group.target_ranges).unwrap_or_else(|_| "[]".to_string()))
        .bind(group.enqueued_at)
        .bind(group.wait_rounds as i64)
        .bind(group.skipped_rounds as i64)
        .bind(i64::from(group.forced))
        .bind(group.current_load as i64)
        .bind(&group.last_skip_reason)
        .bind(i64::from(group.starvation_detected))
        .bind(now)
        .bind((group.wait_rounds == 0 && group.current_load > 0).then_some(now))
        .execute(pool)
        .await?;
    }
    Ok(())
}

pub async fn running_groups(pool: &SqlitePool) -> Result<HashSet<String>, sqlx::Error> {
    let groups = query_scalar::<_, String>(
        r#"
        SELECT DISTINCT s.group_id
        FROM scheduler_task_state s
        JOIN scans sc ON sc.id = s.id
        WHERE sc.status = 'running' AND s.cancelled = 0
        "#,
    )
    .fetch_all(pool)
    .await?;
    Ok(groups.into_iter().collect())
}

pub async fn selected(
    pool: &SqlitePool,
    id: i64,
    forced: bool,
    starvation_detected: bool,
) -> Result<StoredTaskState, sqlx::Error> {
    let now = target_scheduler::now_millis();
    query(
        r#"
        UPDATE scheduler_task_state
        SET status = 'running',
            started_at = COALESCE(started_at, ?),
            last_started_at = ?,
            queue_duration_ms = COALESCE(queue_duration_ms, ? - enqueued_at),
            forced = ?,
            starvation_detected = ?
        WHERE id = ?
        "#,
    )
    .bind(now)
    .bind(now)
    .bind(now)
    .bind(i64::from(forced))
    .bind(i64::from(starvation_detected))
    .bind(id)
    .execute(pool)
    .await?;
    task_state(pool, id)
        .await?
        .ok_or(sqlx::Error::RowNotFound)
}

pub async fn requeue_after_start_failure(pool: &SqlitePool, id: i64) -> Result<(), sqlx::Error> {
    query(
        r#"
        UPDATE scheduler_task_state
        SET status = 'queued', last_started_at = NULL
        WHERE id = ?
        "#,
    )
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn batch_finished(
    pool: &SqlitePool,
    id: i64,
    now: i64,
) -> Result<Option<StoredTaskState>, sqlx::Error> {
    let Some(state) = task_state(pool, id).await? else {
        return Ok(None);
    };
    let execution_delta = now.saturating_sub(state.last_started_at.unwrap_or(now));
    let completed = state.completed_batches.saturating_add(1);
    let next_batch = state.current_batch.saturating_add(1);
    if completed < state.total_batches {
        query(
            r#"
            UPDATE scheduler_task_state
            SET completed_batches = ?,
                current_batch = ?,
                execution_duration_ms = execution_duration_ms + ?,
                last_started_at = NULL,
                status = 'queued',
                reason = 'batch completed; waiting for the next batch'
            WHERE id = ?
            "#,
        )
        .bind(completed as i64)
        .bind(next_batch as i64)
        .bind(execution_delta.max(0))
        .bind(id)
        .execute(pool)
        .await?;
    } else {
        query(
            r#"
            UPDATE scheduler_task_state
            SET completed_batches = ?,
                current_batch = ?,
                execution_duration_ms = execution_duration_ms + ?,
                finished_at = ?,
                last_started_at = NULL,
                status = 'succeeded',
                reason = 'all batches completed'
            WHERE id = ?
            "#,
        )
        .bind(completed as i64)
        .bind(next_batch as i64)
        .bind(execution_delta.max(0))
        .bind(now)
        .bind(id)
        .execute(pool)
        .await?;
    }
    task_state(pool, id).await
}

pub async fn finish_task(
    pool: &SqlitePool,
    id: i64,
    status: &str,
    reason: Option<&str>,
    cancelled: bool,
) -> Result<(), sqlx::Error> {
    let now = target_scheduler::now_millis();
    query(
        r#"
        UPDATE scheduler_task_state
        SET status = ?,
            reason = ?,
            cancelled = ?,
            finished_at = COALESCE(finished_at, ?),
            execution_duration_ms = execution_duration_ms
                + CASE WHEN last_started_at IS NULL THEN 0 ELSE MAX(0, ? - last_started_at) END,
            last_started_at = NULL
        WHERE id = ?
        "#,
    )
    .bind(status)
    .bind(reason)
    .bind(i64::from(cancelled))
    .bind(now)
    .bind(now)
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn next_round(pool: &SqlitePool) -> Result<u64, sqlx::Error> {
    let round: i64 = query_scalar(
        "UPDATE scheduler_round SET round = round + 1 WHERE id = 1 RETURNING round",
    )
    .fetch_one(pool)
    .await?;
    Ok(round as u64)
}

pub async fn current_round(pool: &SqlitePool) -> Result<u64, sqlx::Error> {
    let round: i64 = query_scalar("SELECT round FROM scheduler_round WHERE id = 1")
        .fetch_one(pool)
        .await?;
    Ok(round as u64)
}

#[derive(Debug, Clone)]
pub struct Event<'a> {
    pub round: u64,
    pub task_id: Option<i64>,
    pub scan_id: Option<&'a str>,
    pub group_id: &'a str,
    pub decision: &'a str,
    pub reason: &'a str,
    pub wait_rounds: u32,
    pub queue_duration_ms: Option<i64>,
    pub execution_duration_ms: Option<i64>,
    pub forced: bool,
    pub starvation_detected: bool,
    pub batch_index: Option<usize>,
}

pub async fn record_event(
    pool: &SqlitePool,
    event: Event<'_>,
    snapshot: Option<&QueueSnapshot>,
) -> Result<(), sqlx::Error> {
    let payload = snapshot
        .map(serde_json::to_string)
        .transpose()
        .unwrap_or_default();
    query(
        r#"
        INSERT INTO scheduler_events (
            captured_at, round, task_id, scan_id, group_id, decision, reason,
            wait_rounds, queue_duration_ms, execution_duration_ms, forced,
            starvation_detected, batch_index, snapshot_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(target_scheduler::now_millis())
    .bind(event.round as i64)
    .bind(event.task_id)
    .bind(event.scan_id)
    .bind(event.group_id)
    .bind(event.decision)
    .bind(event.reason)
    .bind(event.wait_rounds as i64)
    .bind(event.queue_duration_ms)
    .bind(event.execution_duration_ms)
    .bind(i64::from(event.forced))
    .bind(i64::from(event.starvation_detected))
    .bind(event.batch_index.map(|index| index as i64))
    .bind(payload)
    .execute(pool)
    .await?;
    Ok(())
}

/// Builds the queue snapshot from persisted queue/groups state.
pub async fn build_snapshot(
    pool: &SqlitePool,
    mode: SchedulingMode,
    max_running_scans: usize,
    round: u64,
) -> Result<QueueSnapshot, sqlx::Error> {
    let now = target_scheduler::now_millis();
    let queued = queued_task_states(pool).await?;
    let running = running_task_states(pool).await?;
    let mut groups = group_states(pool).await?;
    let known_groups = groups
        .iter()
        .map(|group| group.group_id.clone())
        .collect::<HashSet<_>>();

    for state in &queued {
        if !known_groups.contains(&state.group_id) {
            groups.push(GroupRuntime {
                group_id: state.group_id.clone(),
                target_ranges: state.target_ranges.clone(),
                enqueued_at: state.enqueued_at,
                ..Default::default()
            });
        }
    }

    let mut snapshots = Vec::with_capacity(groups.len());
    for group in groups {
        let queued_tasks = queued
            .iter()
            .filter(|task| task.group_id == group.group_id)
            .map(|task| QueueTaskSnapshot {
                task_id: task.id,
                scan_id: task.scan_id.clone(),
                group_id: task.group_id.clone(),
                target_ranges: task.target_ranges.clone(),
                enqueued_at: task.enqueued_at,
                waited_ms: now.saturating_sub(task.enqueued_at),
                current_batch: task.current_batch,
                total_batches: task.total_batches,
            })
            .collect::<Vec<_>>();
        let load = running
            .iter()
            .filter(|task| task.group_id == group.group_id)
            .count();
        let enqueued_at = queued_tasks
            .iter()
            .map(|task| task.enqueued_at)
            .min()
            .unwrap_or(group.enqueued_at);
        snapshots.push(GroupSnapshot {
            group_id: group.group_id,
            target_ranges: group.target_ranges,
            enqueued_at,
            waited_ms: now.saturating_sub(enqueued_at),
            current_load: load,
            wait_rounds: group.wait_rounds,
            skipped_rounds: group.skipped_rounds,
            starvation_detected: group.starvation_detected,
            last_skip_reason: group.last_skip_reason,
            queued_tasks,
        });
    }
    snapshots.retain(|group| group.current_load > 0 || !group.queued_tasks.is_empty());
    snapshots.sort_by(|left, right| left.group_id.cmp(&right.group_id));

    Ok(QueueSnapshot {
        captured_at: now,
        round,
        mode,
        max_running_scans,
        running_scans: running.len(),
        groups: snapshots,
    })
}

pub async fn store_snapshot(
    pool: &SqlitePool,
    snapshot: &QueueSnapshot,
) -> Result<(), sqlx::Error> {
    let payload = serde_json::to_string(snapshot).unwrap_or_else(|_| "{}".to_string());
    query(
        "INSERT INTO scheduler_snapshots (captured_at, round, payload) VALUES (?, ?, ?)",
    )
    .bind(snapshot.captured_at)
    .bind(snapshot.round as i64)
    .bind(payload)
    .execute(pool)
    .await?;
    query(
        r#"
        DELETE FROM scheduler_snapshots
        WHERE id NOT IN (
            SELECT id FROM scheduler_snapshots ORDER BY id DESC LIMIT 100
        )
        "#,
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn latest_snapshot(
    pool: &SqlitePool,
) -> Result<Option<QueueSnapshot>, sqlx::Error> {
    let payload: Option<String> = query_scalar(
        "SELECT payload FROM scheduler_snapshots ORDER BY id DESC LIMIT 1",
    )
    .fetch_optional(pool)
    .await?;
    Ok(payload.and_then(|payload| serde_json::from_str(&payload).ok()))
}

pub async fn snapshot_history(
    pool: &SqlitePool,
    limit: usize,
) -> Result<Vec<QueueSnapshot>, sqlx::Error> {
    let payloads = query_scalar::<_, String>(
        "SELECT payload FROM scheduler_snapshots ORDER BY id DESC LIMIT ?",
    )
    .bind(limit.max(1) as i64)
    .fetch_all(pool)
    .await?;
    Ok(payloads
        .into_iter()
        .filter_map(|payload| serde_json::from_str(&payload).ok())
        .collect())
}

pub async fn schedule_records(
    pool: &SqlitePool,
) -> Result<Vec<TaskScheduleRecord>, sqlx::Error> {
    let rows = query(
        r#"
        SELECT s.id, csm.scan_id, s.group_id, s.target_ranges, s.enqueued_at,
               s.started_at, s.finished_at, s.queue_duration_ms,
               s.execution_duration_ms, s.current_batch, s.completed_batches,
               s.total_batches, s.forced, s.starvation_detected, s.cancelled,
               s.status, s.reason
        FROM scheduler_task_state s
        JOIN client_scan_map csm ON csm.id = s.id
        ORDER BY s.enqueued_at, s.id
        "#,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| TaskScheduleRecord {
            task_id: row.get("id"),
            scan_id: row.get("scan_id"),
            group_id: row.get("group_id"),
            target_ranges: json_strings(row.get::<String, _>("target_ranges").as_str()),
            enqueued_at: row.get("enqueued_at"),
            started_at: row.get("started_at"),
            finished_at: row.get("finished_at"),
            queue_duration_ms: row.get("queue_duration_ms"),
            execution_duration_ms: row.get::<Option<i64>, _>("execution_duration_ms"),
            current_batch: row.get::<i64, _>("current_batch") as usize,
            completed_batches: row.get::<i64, _>("completed_batches") as usize,
            total_batches: row.get::<i64, _>("total_batches") as usize,
            forced: row.get::<i64, _>("forced") != 0,
            starvation_detected: row.get::<i64, _>("starvation_detected") != 0,
            cancelled: row.get::<i64, _>("cancelled") != 0,
            status: row.get("status"),
            reason: row.get("reason"),
        })
        .collect())
}
