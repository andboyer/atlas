pub const SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    summary_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_runs_started ON runs(started_at);

CREATE TABLE IF NOT EXISTS samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT,
    sampled_at TEXT NOT NULL,
    metric TEXT NOT NULL,
    value REAL,
    label TEXT
);
CREATE INDEX IF NOT EXISTS idx_samples_metric_time
    ON samples(metric, sampled_at);

CREATE TABLE IF NOT EXISTS devices (
    mac TEXT PRIMARY KEY,
    ip TEXT,
    hostname TEXT,
    vendor TEXT,
    class TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    last_online INTEGER NOT NULL DEFAULT 0,
    watched INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS device_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    event_type TEXT NOT NULL,
    details TEXT
);
CREATE INDEX IF NOT EXISTS idx_device_events_mac_time
    ON device_events(mac, occurred_at);
CREATE INDEX IF NOT EXISTS idx_device_events_time
    ON device_events(occurred_at);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    run_id TEXT,
    rule_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence REAL NOT NULL,
    observed_at TEXT NOT NULL,
    payload_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_observed ON findings(observed_at);

CREATE TABLE IF NOT EXISTS roaming_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at TEXT NOT NULL,
    ssid TEXT,
    from_bssid TEXT,
    to_bssid TEXT,
    rssi_at_roam INTEGER
);
CREATE INDEX IF NOT EXISTS idx_roaming_events_time
    ON roaming_events(occurred_at);
"#;
