-- Rebuild scans to allow the explicit "not_executed" phase used when a task
-- dependency fails. All existing columns keep their previous defaults.
CREATE TABLE scans_new (
    id INTEGER PRIMARY KEY,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    start_time INTEGER,
    end_time INTEGER,
    host_dead INTEGER NOT NULL DEFAULT 0,
    host_alive INTEGER NOT NULL DEFAULT 0,
    host_queued INTEGER NOT NULL DEFAULT 0,
    host_excluded INTEGER NOT NULL DEFAULT 0,
    host_all INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'stored' CHECK(status IN ('stored', 'requested', 'running', 'stopped', 'failed', 'succeeded', 'not_executed')),
    auth_data TEXT NOT NULL,

    FOREIGN KEY (id) REFERENCES client_scan_map(id) ON DELETE CASCADE
);

INSERT INTO scans_new (
    id, created_at, start_time, end_time,
    host_dead, host_alive, host_queued, host_excluded, host_all,
    status, auth_data
)
SELECT
    id, created_at, start_time, end_time,
    host_dead, host_alive, host_queued, host_excluded, host_all,
    status, auth_data
FROM scans;

DROP TABLE scans;
ALTER TABLE scans_new RENAME TO scans;

CREATE INDEX idx_scans_status ON scans(status);

CREATE TRIGGER trg_update_scans_start_time
AFTER UPDATE OF status ON scans
FOR EACH ROW
WHEN NEW.status = 'running' AND OLD.status IS NOT 'running'
BEGIN
    UPDATE scans
    SET start_time = CAST(strftime('%s', 'now') AS INTEGER),
        end_time = NULL
    WHERE id = NEW.id;
END;

CREATE TRIGGER trg_update_scans_end_time
AFTER UPDATE OF status ON scans
FOR EACH ROW
WHEN (NEW.status = 'failed' OR NEW.status = 'succeeded' OR NEW.status = 'stopped' OR NEW.status = 'not_executed')
    AND OLD.status IS NOT NEW.status
BEGIN
    UPDATE scans
    SET end_time = CAST(strftime('%s', 'now') AS INTEGER)
    WHERE id = NEW.id;
END;

-- Persistent queue metadata. One row exists per task once it is requested.
CREATE TABLE scheduler_task_state (
    id INTEGER PRIMARY KEY,
    group_id TEXT NOT NULL,
    target_ranges TEXT NOT NULL,
    enqueued_at INTEGER NOT NULL,
    started_at INTEGER,
    finished_at INTEGER,
    last_started_at INTEGER,
    queue_duration_ms INTEGER,
    execution_duration_ms INTEGER NOT NULL DEFAULT 0,
    depends_on TEXT NOT NULL DEFAULT '[]',
    current_batch INTEGER NOT NULL DEFAULT 0,
    completed_batches INTEGER NOT NULL DEFAULT 0,
    total_batches INTEGER NOT NULL DEFAULT 1,
    batch_strategy TEXT NOT NULL DEFAULT 'count',
    batch_size INTEGER NOT NULL DEFAULT 256,
    cancelled INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'queued',
    reason TEXT,
    forced INTEGER NOT NULL DEFAULT 0,
    starvation_detected INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE INDEX idx_scheduler_task_state_group
    ON scheduler_task_state(group_id, status);

CREATE TABLE scheduler_group_state (
    group_id TEXT PRIMARY KEY,
    target_ranges TEXT NOT NULL,
    enqueued_at INTEGER NOT NULL,
    wait_rounds INTEGER NOT NULL DEFAULT 0,
    skipped_rounds INTEGER NOT NULL DEFAULT 0,
    forced INTEGER NOT NULL DEFAULT 0,
    current_load INTEGER NOT NULL DEFAULT 0,
    last_skip_reason TEXT,
    starvation_detected INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL,
    last_scheduled_at INTEGER
);

-- Structured decisions and timing records for post-mortem analysis.
CREATE TABLE scheduler_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    captured_at INTEGER NOT NULL,
    round INTEGER NOT NULL,
    task_id INTEGER,
    scan_id TEXT,
    group_id TEXT NOT NULL,
    decision TEXT NOT NULL,
    reason TEXT NOT NULL,
    wait_rounds INTEGER NOT NULL DEFAULT 0,
    queue_duration_ms INTEGER,
    execution_duration_ms INTEGER,
    forced INTEGER NOT NULL DEFAULT 0,
    starvation_detected INTEGER NOT NULL DEFAULT 0,
    batch_index INTEGER,
    snapshot_json TEXT
);

CREATE INDEX idx_scheduler_events_round ON scheduler_events(round);
CREATE INDEX idx_scheduler_events_task ON scheduler_events(task_id, captured_at);

-- The latest queue snapshot is exported via the API. A bounded history is
-- useful when an operator needs to compare adjacent scheduling decisions.
CREATE TABLE scheduler_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    captured_at INTEGER NOT NULL,
    round INTEGER NOT NULL,
    payload TEXT NOT NULL
);

CREATE INDEX idx_scheduler_snapshots_round ON scheduler_snapshots(round);

CREATE TABLE scheduler_round (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    round INTEGER NOT NULL DEFAULT 0
);

INSERT INTO scheduler_round (id, round) VALUES (1, 0);
