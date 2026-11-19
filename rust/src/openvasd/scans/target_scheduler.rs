// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! Target-aware task planning for `openvasd`.
//!
//! This module deliberately contains no scanner calls. It turns scans into
//! target groups and batches, selects the next groups, and records why a group
//! was selected or skipped. The scheduler loop remains responsible for the
//! actual state transitions and scanner interaction.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use crate::config::{BatchStrategy, SchedulingMode};

const DEFAULT_V4_PREFIX: u8 = 24;
const DEFAULT_V6_PREFIX: u8 = 64;
const MAX_EXPANDED_ADDRESSES: u64 = 1_000_000;

#[derive(Debug, thiserror::Error)]
pub enum TargetResolutionError {
    #[error("target list is empty")]
    Empty,
    #[error("unable to resolve target {target:?}: {reason}")]
    Unresolvable { target: String, reason: String },
    #[error("invalid target range {target:?}: {reason}")]
    InvalidRange { target: String, reason: String },
    #[error(
        "target {target:?} expands to {addresses} addresses, exceeding the limit of {limit}"
    )]
    TooLarge {
        target: String,
        addresses: u64,
        limit: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResolvedTargets {
    pub group_id: String,
    pub target_ranges: Vec<String>,
    pub address_count: u64,
    pub batches: Vec<Vec<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchConfig {
    pub strategy: BatchStrategy,
    pub batch_size: usize,
    pub v4_prefix: u8,
    pub v6_prefix: u8,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            strategy: BatchStrategy::Count,
            batch_size: 256,
            v4_prefix: DEFAULT_V4_PREFIX,
            v6_prefix: DEFAULT_V6_PREFIX,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AddressRange {
    V4 { start: u32, end: u32 },
    V6 { start: u128, end: u128 },
}

impl AddressRange {
    fn len(&self) -> u64 {
        match self {
            Self::V4 { start, end } => u64::from(*end - *start) + 1,
            Self::V6 { start, end } => {
                let len = *end - *start;
                if len == u128::MAX {
                    MAX_EXPANDED_ADDRESSES + 1
                } else {
                    len.saturating_add(1).min(u128::from(u64::MAX)) as u64
                }
            }
        }
    }

    fn addresses(&self) -> Vec<IpAddr> {
        match self {
            Self::V4 { start, end } => (*start..=*end)
                .map(|x| IpAddr::V4(Ipv4Addr::from(x)))
                .collect(),
            Self::V6 { start, end } => (*start..=*end)
                .map(|x| IpAddr::V6(Ipv6Addr::from(x)))
                .collect(),
        }
    }
}

fn parse_v4_range(target: &str) -> Option<AddressRange> {
    if let Some((network, prefix)) = target.split_once('/') {
        let ip = network.parse::<Ipv4Addr>().ok()?;
        let prefix = prefix.parse::<u8>().ok()?;
        if prefix > 32 {
            return None;
        }
        let mask = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        };
        let start = u32::from(ip) & mask;
        let end = start | !mask;
        return Some(AddressRange::V4 { start, end });
    }

    if let Ok(ip) = target.parse::<Ipv4Addr>() {
        let ip = u32::from(ip);
        return Some(AddressRange::V4 {
            start: ip,
            end: ip,
        });
    }

    let (start, end) = target.split_once('-')?;
    let start = start.parse::<Ipv4Addr>().ok()?;
    let start_num = u32::from(start);
    let end_num = if let Ok(end) = end.parse::<Ipv4Addr>() {
        u32::from(end)
    } else if !end.contains('.') {
        let last = end.parse::<u8>().ok()?;
        (start_num & 0xffff_ff00) | u32::from(last)
    } else {
        let parts = end.split('.').collect::<Vec<_>>();
        let start_parts = start.octets();
        let mut octets = start_parts;
        if parts.is_empty() || parts.len() > 4 {
            return None;
        }
        let offset = 4 - parts.len();
        for (i, part) in parts.iter().enumerate() {
            octets[offset + i] = part.parse::<u8>().ok()?;
        }
        u32::from(Ipv4Addr::from(octets))
    };
    (end_num >= start_num).then_some(AddressRange::V4 {
        start: start_num,
        end: end_num,
    })
}

fn parse_v6_range(target: &str) -> Option<AddressRange> {
    if let Some((network, prefix)) = target.split_once('/') {
        let ip = network.parse::<Ipv6Addr>().ok()?;
        let prefix = prefix.parse::<u8>().ok()?;
        if prefix > 128 {
            return None;
        }
        let mask = if prefix == 0 {
            0
        } else {
            u128::MAX << (128 - prefix)
        };
        let start = u128::from(ip) & mask;
        let end = start | !mask;
        return Some(AddressRange::V6 { start, end });
    }

    if let Ok(ip) = target.parse::<Ipv6Addr>() {
        let ip = u128::from(ip);
        return Some(AddressRange::V6 {
            start: ip,
            end: ip,
        });
    }

    let (start, end) = target.split_once('-')?;
    let start = start.parse::<Ipv6Addr>().ok()?;
    let start_num = u128::from(start);
    let end_num = if let Ok(end) = end.parse::<Ipv6Addr>() {
        u128::from(end)
    } else if !end.contains(':') {
        let last = u16::from_str_radix(end, 16).ok()?;
        (start_num & !u128::from(u16::MAX)) | u128::from(last)
    } else {
        let prefix = start
            .segments()
            .iter()
            .take(7)
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(":");
        format!("{prefix}:{end}").parse::<Ipv6Addr>().ok().map(u128::from)?
    };
    (end_num >= start_num).then_some(AddressRange::V6 {
        start: start_num,
        end: end_num,
    })
}

fn parse_target(target: &str) -> Result<Vec<AddressRange>, TargetResolutionError> {
    if let Some(range) = parse_v4_range(target).or_else(|| parse_v6_range(target)) {
        return Ok(vec![range]);
    }

    let addresses = (target, 0)
        .to_socket_addrs()
        .map_err(|reason| TargetResolutionError::Unresolvable {
            target: target.to_string(),
            reason: reason.to_string(),
        })?
        .map(|address| address.ip())
        .collect::<BTreeSet<_>>();

    if addresses.is_empty() {
        return Err(TargetResolutionError::Unresolvable {
            target: target.to_string(),
            reason: "hostname did not resolve to an address".to_string(),
        });
    }
    Ok(addresses
        .into_iter()
        .map(|address| match address {
            IpAddr::V4(ip) => {
                let ip = u32::from(ip);
                AddressRange::V4 {
                    start: ip,
                    end: ip,
                }
            }
            IpAddr::V6(ip) => {
                let ip = u128::from(ip);
                AddressRange::V6 {
                    start: ip,
                    end: ip,
                }
            }
        })
        .collect())
}

fn v4_network(ip: Ipv4Addr, prefix: u8) -> String {
    let prefix = prefix.min(32);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    format!("{}/{}", Ipv4Addr::from(u32::from(ip) & mask), prefix)
}

fn v6_network(ip: Ipv6Addr, prefix: u8) -> String {
    let prefix = prefix.min(128);
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    format!("{}/{}", Ipv6Addr::from(u128::from(ip) & mask), prefix)
}

fn network_id(ip: IpAddr, v4_prefix: u8, v6_prefix: u8) -> String {
    match ip {
        IpAddr::V4(ip) => v4_network(ip, v4_prefix),
        IpAddr::V6(ip) => v6_network(ip, v6_prefix),
    }
}

/// Resolves supported target expressions and builds the configured batches.
///
/// Supported expressions are single IPv4/IPv6 addresses, CIDRs, abbreviated
/// IPv4/IPv6 ranges (for example `192.168.0.1-15`), and DNS names that resolve
/// to exactly one address.
pub fn resolve_targets(
    hosts: &[String],
    config: BatchConfig,
) -> Result<ResolvedTargets, TargetResolutionError> {
    if hosts.is_empty() {
        return Err(TargetResolutionError::Empty);
    }

    let mut ranges = Vec::with_capacity(hosts.len());
    let mut total = 0u64;
    for host in hosts {
        for range in parse_target(host)? {
            total = total.saturating_add(range.len());
            if total > MAX_EXPANDED_ADDRESSES {
                return Err(TargetResolutionError::TooLarge {
                    target: host.clone(),
                    addresses: total,
                    limit: MAX_EXPANDED_ADDRESSES,
                });
            }
            ranges.push(range);
        }
    }

    let mut addresses = ranges
        .iter()
        .flat_map(AddressRange::addresses)
        .collect::<Vec<_>>();
    addresses.sort_unstable();
    addresses.dedup();
    let address_count = addresses.len() as u64;
    let group_id = addresses
        .first()
        .map(|ip| network_id(*ip, config.v4_prefix, config.v6_prefix))
        .unwrap_or_else(|| "unknown".to_string());

    let batches = match config.strategy {
        BatchStrategy::Count => addresses
            .chunks(config.batch_size.max(1))
            .map(|batch| batch.iter().map(ToString::to_string).collect())
            .collect(),
        BatchStrategy::AddressSegment => {
            let mut segments: BTreeMap<String, Vec<String>> = BTreeMap::new();
            for address in addresses {
                segments
                    .entry(network_id(address, config.v4_prefix, config.v6_prefix))
                    .or_default()
                    .push(address.to_string());
            }
            segments
                .into_values()
                .flat_map(|segment| {
                    segment
                        .chunks(config.batch_size.max(1))
                        .map(|batch| batch.to_vec())
                        .collect::<Vec<_>>()
                })
                .collect()
        }
    };

    Ok(ResolvedTargets {
        group_id,
        target_ranges: hosts.to_vec(),
        address_count,
        batches,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DependencyReadiness {
    Ready,
    Waiting(Vec<String>),
    Failed(Vec<String>),
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct PendingTask {
    pub id: i64,
    pub scan_id: String,
    pub group_id: String,
    pub target_ranges: Vec<String>,
    pub enqueued_at: i64,
    pub dependencies: DependencyReadiness,
    pub current_batch: usize,
    pub total_batches: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct GroupRuntime {
    pub group_id: String,
    pub target_ranges: Vec<String>,
    pub enqueued_at: i64,
    pub wait_rounds: u32,
    pub skipped_rounds: u32,
    pub forced: bool,
    pub current_load: usize,
    pub last_skip_reason: Option<String>,
    pub starvation_detected: bool,
}

#[derive(Debug, Clone)]
pub struct Selection {
    pub task_id: i64,
    pub scan_id: String,
    pub group_id: String,
    pub reason: String,
    pub forced: bool,
    pub wait_rounds: u32,
    pub starvation_detected: bool,
}

#[derive(Debug, Clone)]
pub struct SkipDecision {
    pub task_id: i64,
    pub scan_id: String,
    pub group_id: String,
    pub reason: String,
    pub wait_rounds: u32,
    pub starvation_detected: bool,
}

#[derive(Debug, Clone)]
pub struct Plan {
    pub selections: Vec<Selection>,
    pub skips: Vec<SkipDecision>,
    pub groups: Vec<GroupRuntime>,
}

fn task_block_reason(task: &PendingTask) -> Option<String> {
    match &task.dependencies {
        DependencyReadiness::Ready => None,
        DependencyReadiness::Waiting(dependencies) => Some(format!(
            "waiting for dependencies to succeed: {}",
            dependencies.join(",")
        )),
        DependencyReadiness::Failed(dependencies) => Some(format!(
            "dependency failed; task must not be executed: {}",
            dependencies.join(",")
        )),
    }
}

/// Selects tasks by target group.
///
/// A group is serialized by selecting at most one task from it per call. Groups
/// are normally ordered by their oldest queued task. Once a group reaches the
/// starvation threshold it is selected before normally ordered groups, which
/// guarantees that a steady stream of older work cannot starve it.
pub fn plan(
    pending: &[PendingTask],
    previous_groups: &[GroupRuntime],
    running_groups: &HashSet<String>,
    available_slots: usize,
    starvation_threshold: u32,
) -> Plan {
    let mut groups = previous_groups
        .iter()
        .map(|group| (group.group_id.clone(), group.clone()))
        .collect::<HashMap<_, _>>();
    let mut by_group: BTreeMap<String, Vec<&PendingTask>> = BTreeMap::new();

    for task in pending {
        by_group
            .entry(task.group_id.clone())
            .or_default()
            .push(task);
    }
    for tasks in by_group.values_mut() {
        tasks.sort_by_key(|task| (task.enqueued_at, task.id));
    }

    let mut eligible = Vec::new();
    let mut skips = Vec::new();
    for (group_id, tasks) in &by_group {
        let oldest = tasks.first().expect("group is not empty");
        let group = groups.entry(group_id.clone()).or_insert_with(|| GroupRuntime {
            group_id: group_id.clone(),
            target_ranges: oldest.target_ranges.clone(),
            enqueued_at: oldest.enqueued_at,
            ..Default::default()
        });
        group.enqueued_at = oldest.enqueued_at;
        group.target_ranges = tasks
            .iter()
            .flat_map(|task| task.target_ranges.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        group.current_load = usize::from(running_groups.contains(group_id));

        if running_groups.contains(group_id) {
            let reason = "same-target group already has a running batch; groups are serialized"
                .to_string();
            group.last_skip_reason = Some(reason.clone());
            group.wait_rounds = 0;
            group.skipped_rounds = 0;
            group.forced = false;
            group.starvation_detected = false;
            group.current_load = 1;
            continue;
        }

        let ready = tasks
            .iter()
            .filter(|task| task.dependencies == DependencyReadiness::Ready)
            .copied()
            .collect::<Vec<_>>();
        if ready.is_empty() {
            let reason = task_block_reason(oldest)
                .unwrap_or_else(|| "no runnable task in group".to_string());
            group.last_skip_reason = Some(reason.clone());
            continue;
        }
        eligible.push((group_id.clone(), ready));
    }

    let mut selected_groups = HashSet::new();
    let mut selections = Vec::new();
    for _ in 0..available_slots {
        let forced = eligible
            .iter()
            .filter(|(group_id, _)| !selected_groups.contains(group_id))
            .filter_map(|(group_id, tasks)| {
                let group = groups.get(group_id)?;
                (starvation_threshold > 0
                    && group.wait_rounds.saturating_add(1) >= starvation_threshold)
                    .then_some((group_id.clone(), tasks[0].id, group.wait_rounds))
            })
            .max_by_key(|(_, id, wait_rounds)| (*wait_rounds, std::cmp::Reverse(*id)));

        let choice = forced.or_else(|| {
            eligible
                .iter()
                .filter(|(group_id, _)| !selected_groups.contains(group_id))
                .filter_map(|(group_id, tasks)| {
                    let group = groups.get(group_id)?;
                    Some((group_id.clone(), tasks[0].id, group.wait_rounds))
                })
                .min_by_key(|(group_id, id, _)| {
                    let group = groups.get(group_id).expect("group exists");
                    (group.enqueued_at, *id)
                })
        });

        let Some((group_id, task_id, wait_rounds_before)) = choice else {
            break;
        };
        selected_groups.insert(group_id.clone());
        let task = eligible
            .iter()
            .find(|(id, _)| id == &group_id)
            .and_then(|(_, tasks)| tasks.iter().find(|task| task.id == task_id))
            .expect("selected task exists");
        let group = groups.get_mut(&group_id).expect("group exists");
        let forced = starvation_threshold > 0
            && wait_rounds_before.saturating_add(1) >= starvation_threshold;
        let reason = if forced {
            format!(
                "fairness override: group was not scheduled for {} rounds (threshold {})",
                wait_rounds_before.saturating_add(1),
                starvation_threshold
            )
        } else {
            format!(
                "oldest eligible target group; queued task waited {} rounds",
                wait_rounds_before
            )
        };
        group.wait_rounds = 0;
        group.skipped_rounds = 0;
        group.forced = false;
        group.starvation_detected = false;
        group.current_load = 1;
        group.last_skip_reason = None;
        selections.push(Selection {
            task_id: task.id,
            scan_id: task.scan_id.clone(),
            group_id: group_id.clone(),
            reason,
            forced,
            wait_rounds: wait_rounds_before,
            starvation_detected: forced,
        });
    }

    for (group_id, tasks) in &by_group {
        let group = groups.get_mut(group_id).expect("group exists");
        if selected_groups.contains(group_id) {
            let selected_ids = selections
                .iter()
                .filter(|selection| &selection.group_id == group_id)
                .map(|selection| selection.task_id)
                .collect::<HashSet<_>>();
            group.enqueued_at = tasks
                .iter()
                .filter(|task| !selected_ids.contains(&task.id))
                .map(|task| task.enqueued_at)
                .min()
                .unwrap_or(group.enqueued_at);
            for task in tasks {
                if !selected_ids.contains(&task.id) {
                    let reason =
                        "another task from the same target group was selected; groups are serialized"
                            .to_string();
                    skips.push(SkipDecision {
                        task_id: task.id,
                        scan_id: task.scan_id.clone(),
                        group_id: group_id.clone(),
                        reason,
                        wait_rounds: group.wait_rounds,
                        starvation_detected: group.starvation_detected,
                    });
                }
            }
            continue;
        }

        if running_groups.contains(group_id) {
            let reason =
                "same-target group already has a running batch; groups are serialized".to_string();
            group.last_skip_reason = Some(reason.clone());
            for task in tasks {
                skips.push(SkipDecision {
                    task_id: task.id,
                    scan_id: task.scan_id.clone(),
                    group_id: group_id.clone(),
                    reason: reason.clone(),
                    wait_rounds: group.wait_rounds,
                    starvation_detected: group.starvation_detected,
                });
            }
            continue;
        }

        group.wait_rounds = group.wait_rounds.saturating_add(1);
        group.skipped_rounds = group.skipped_rounds.saturating_add(1);
        group.starvation_detected =
            starvation_threshold > 0 && group.wait_rounds >= starvation_threshold;
        group.forced = group.starvation_detected;
        let reason = if available_slots == 0 || selections.len() >= available_slots {
            "not selected because all scanner slots were assigned to groups with older work"
                .to_string()
        } else if tasks
            .iter()
            .all(|task| task.dependencies != DependencyReadiness::Ready)
        {
            task_block_reason(tasks[0])
                .unwrap_or_else(|| "no runnable task in group".to_string())
        } else {
            "not selected because another group had an older queued task".to_string()
        };
        group.last_skip_reason = Some(reason.clone());
        for task in tasks {
            if !selections.iter().any(|selection| selection.task_id == task.id) {
                skips.push(SkipDecision {
                    task_id: task.id,
                    scan_id: task.scan_id.clone(),
                    group_id: group_id.clone(),
                    reason: reason.clone(),
                    wait_rounds: group.wait_rounds,
                    starvation_detected: group.starvation_detected,
                });
            }
        }
    }

    let mut groups = groups.into_values().collect::<Vec<_>>();
    groups.sort_by(|left, right| left.group_id.cmp(&right.group_id));
    Plan {
        selections,
        skips,
        groups,
    }
}

pub fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or_default()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QueueTaskSnapshot {
    pub task_id: i64,
    pub scan_id: String,
    pub group_id: String,
    pub target_ranges: Vec<String>,
    pub enqueued_at: i64,
    pub waited_ms: i64,
    pub current_batch: usize,
    pub total_batches: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupSnapshot {
    pub group_id: String,
    pub target_ranges: Vec<String>,
    pub enqueued_at: i64,
    pub waited_ms: i64,
    pub current_load: usize,
    pub wait_rounds: u32,
    pub skipped_rounds: u32,
    pub starvation_detected: bool,
    pub last_skip_reason: Option<String>,
    pub queued_tasks: Vec<QueueTaskSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QueueSnapshot {
    pub captured_at: i64,
    pub round: u64,
    pub mode: SchedulingMode,
    pub max_running_scans: usize,
    pub running_scans: usize,
    pub groups: Vec<GroupSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaskScheduleRecord {
    pub task_id: i64,
    pub scan_id: String,
    pub group_id: String,
    pub target_ranges: Vec<String>,
    pub enqueued_at: i64,
    pub started_at: Option<i64>,
    pub finished_at: Option<i64>,
    pub queue_duration_ms: Option<i64>,
    pub execution_duration_ms: Option<i64>,
    pub current_batch: usize,
    pub completed_batches: usize,
    pub total_batches: usize,
    pub forced: bool,
    pub starvation_detected: bool,
    pub cancelled: bool,
    pub status: String,
    pub reason: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn group(id: &str, enqueued_at: i64) -> GroupRuntime {
        GroupRuntime {
            group_id: id.to_string(),
            target_ranges: vec![id.to_string()],
            enqueued_at,
            ..Default::default()
        }
    }

    fn task(id: i64, group_id: &str, enqueued_at: i64) -> PendingTask {
        PendingTask {
            id,
            scan_id: id.to_string(),
            group_id: group_id.to_string(),
            target_ranges: vec![group_id.to_string()],
            enqueued_at,
            dependencies: DependencyReadiness::Ready,
            current_batch: 0,
            total_batches: 1,
        }
    }

    #[test]
    fn count_batches_can_cross_networks() {
        let result = resolve_targets(
            &[
                "10.0.0.1".to_string(),
                "10.0.0.2".to_string(),
                "10.0.1.1".to_string(),
            ],
            BatchConfig {
                strategy: BatchStrategy::Count,
                batch_size: 2,
                ..Default::default()
            },
        )
        .unwrap();

        assert_eq!(result.address_count, 3);
        assert_eq!(
            result.batches,
            vec![
                vec!["10.0.0.1".to_string(), "10.0.0.2".to_string()],
                vec!["10.0.1.1".to_string()]
            ]
        );
    }

    #[test]
    fn address_segment_batches_keep_segments_separate() {
        let result = resolve_targets(
            &["10.0.0.1-2".to_string(), "10.0.1.1".to_string()],
            BatchConfig {
                strategy: BatchStrategy::AddressSegment,
                batch_size: 10,
                ..Default::default()
            },
        )
        .unwrap();

        assert_eq!(
            result.batches,
            vec![
                vec!["10.0.0.1".to_string(), "10.0.0.2".to_string()],
                vec!["10.0.1.1".to_string()]
            ]
        );
    }

    #[test]
    fn hostname_with_multiple_addresses_is_supported() {
        let result = resolve_targets(
            &["localhost".to_string()],
            BatchConfig {
                strategy: BatchStrategy::Count,
                batch_size: 10,
                ..Default::default()
            },
        )
        .unwrap();

        assert!(result.address_count >= 1);
        assert!(!result.batches.is_empty());
    }

    #[test]
    fn groups_are_serialized_and_different_groups_run_in_parallel() {
        let pending = vec![
            task(1, "10.0.0.0/24", 1),
            task(2, "10.0.0.0/24", 2),
            task(3, "10.0.1.0/24", 3),
        ];
        let result = plan(&pending, &[], &HashSet::new(), 2, 5);

        assert_eq!(result.selections.len(), 2);
        assert_eq!(
            result
                .selections
                .iter()
                .map(|selection| selection.group_id.as_str())
                .collect::<HashSet<_>>(),
            HashSet::from(["10.0.0.0/24", "10.0.1.0/24"])
        );
        assert!(
            result
                .skips
                .iter()
                .any(|skip| skip.task_id == 2 && skip.reason.contains("serialized"))
        );
    }

    #[test]
    fn starvation_threshold_forces_long_waiting_group() {
        let pending = vec![task(1, "new", 100), task(2, "starving", 1)];
        let groups = vec![GroupRuntime {
            wait_rounds: 5,
            ..group("starving", 1)
        }];

        let result = plan(&pending, &groups, &HashSet::new(), 1, 5);

        assert_eq!(result.selections[0].task_id, 2);
        assert!(result.selections[0].forced);
        assert!(result.selections[0].reason.contains("fairness override"));
    }

    #[test]
    fn starving_group_is_reported_with_skip_reason() {
        let pending = vec![task(1, "a", 1), task(2, "b", 2)];
        let result = plan(&pending, &[], &HashSet::new(), 1, 1);

        assert_eq!(result.selections.len(), 1);
        let starving = result
            .groups
            .iter()
            .find(|group| group.group_id == "b")
            .unwrap();
        assert!(starving.wait_rounds >= 1);
        assert!(!starving.last_skip_reason.as_deref().unwrap_or_default().is_empty());
    }

    #[test]
    fn a_running_group_is_not_counted_as_starving() {
        let pending = vec![task(1, "active", 1)];
        let groups = vec![GroupRuntime {
            wait_rounds: 10,
            current_load: 1,
            ..group("active", 1)
        }];
        let running = HashSet::from(["active".to_string()]);

        let result = plan(&pending, &groups, &running, 1, 5);

        assert!(result.selections.is_empty());
        let active = result
            .groups
            .iter()
            .find(|group| group.group_id == "active")
            .unwrap();
        assert_eq!(active.wait_rounds, 0);
        assert!(!active.starvation_detected);
        assert!(result.skips[0].reason.contains("serialized"));
    }
}
