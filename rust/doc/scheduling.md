# Target-aware scan scheduling

openvasd keeps the original FIFO queue as the default. Set
`scheduler.mode = "target_aware"` to enable target grouping, fairness
overrides, batching and queue diagnostics.

## Queue model

- A task is assigned to a target group using `scheduler.group_prefix_v4`
  (default `/24`) or `scheduler.group_prefix_v6` (default `/64`).
- At most one task from a group runs at a time. Different groups may fill the
  remaining scanner capacity in parallel.
- Unrelated groups are normally selected by the enqueue time of their oldest
  waiting task.
- Every group has persisted `wait_rounds` and `skipped_rounds` counters. A group
  that has not been selected for `scheduler.starvation_threshold` rounds is
  forced ahead of normally ordered work once. This prevents a large target from
  permanently starving another group.
- A task whose dependency has failed or was not executed is moved to
  `not_executed`. It is never sent to the scanner.
- If the scanner reports that it cannot start work, a selected task returns to
  the queue. It is not marked failed.

## Batching

`scheduler.batch_strategy` controls how large target lists are split:

- `count` (default): split after `batch_size` expanded addresses. A batch may
  contain addresses from different networks.
- `address_segment`: group addresses by the configured prefix first and split
  each segment separately. This preserves network locality at the cost of more,
  potentially smaller batches.

After each successful batch openvasd imports the results, deletes the scanner
job for that batch, returns the task to `requested`, and releases the scanner
slot. Cancelling a task keeps results already imported from completed or
partially scanned batches.

## Dependencies

Dependencies are declared through the normal scan preference list:

```json
{
  "scan_preferences": [
    {
      "id": "depends_on",
      "value": "[\"port-discovery\", \"service-detection\"]"
    }
  ]
}
```

The value can be a JSON array or a comma-separated list of scan IDs. All
dependencies must succeed before the task can run. A failed, stopped or
`not_executed` dependency prevents the downstream task from being executed.

## Diagnostics

Each scheduling decision is written to `scheduler_events` and emitted as a
structured log containing the round, task, group, wait count, forced/fairness
flag and human-readable reason.

The latest queue snapshot and per-task scheduling records are available from:

- `GET /scans/scheduler/snapshot`
- `GET /scans/scheduler/snapshots` (retained history, newest first)
- `GET /scans/scheduler/records`

A snapshot group includes:

- group identifier
- target ranges
- enqueue time
- current wait duration
- current load
- wait/skip counters
- starvation flag and last skip reason
- queued tasks and their batch progress

Per-task records include enqueue/start/finish times, queue duration, accumulated
execution duration, batch progress, cancellation flag and whether the task was
selected by the fairness override.
