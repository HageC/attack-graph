ALTER TABLE simulation_jobs ADD COLUMN telemetry_cursor integer NOT NULL DEFAULT 0 CHECK (telemetry_cursor >= 0);

CREATE TABLE security_telemetry (
    id text PRIMARY KEY,
    environment_id text NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    job_id text NOT NULL REFERENCES simulation_jobs(id) ON DELETE CASCADE,
    run_id text NOT NULL REFERENCES simulation_runs(id) ON DELETE CASCADE,
    source_event_id text NOT NULL,
    sequence integer NOT NULL CHECK (sequence >= 1),
    schema_version integer NOT NULL DEFAULT 1 CHECK (schema_version = 1),
    occurred_at_seconds integer NOT NULL CHECK (occurred_at_seconds >= 0),
    event_type text NOT NULL,
    asset_id text NOT NULL,
    source_asset_id text NOT NULL,
    result text NOT NULL,
    severity integer NOT NULL CHECK (severity BETWEEN 1 AND 5),
    detected boolean NOT NULL,
    ground_truth text NOT NULL CHECK (ground_truth IN ('adversarial','control','scenario')),
    payload jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(job_id, source_event_id),
    UNIQUE(job_id, sequence)
);
CREATE INDEX security_telemetry_environment_time_idx ON security_telemetry (environment_id, created_at DESC, id DESC);
CREATE INDEX security_telemetry_job_sequence_idx ON security_telemetry (job_id, sequence);

CREATE TABLE detection_rules (
    id text PRIMARY KEY,
    environment_id text NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    name text NOT NULL,
    enabled boolean NOT NULL DEFAULT true,
    event_type text NOT NULL,
    min_severity integer NOT NULL CHECK (min_severity BETWEEN 1 AND 5),
    asset_id text NOT NULL DEFAULT '',
    created_by text NOT NULL REFERENCES users(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(environment_id, name)
);
CREATE INDEX detection_rules_environment_enabled_idx ON detection_rules (environment_id, enabled, event_type);

CREATE TABLE security_alerts (
    id text PRIMARY KEY,
    environment_id text NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    job_id text NOT NULL REFERENCES simulation_jobs(id) ON DELETE CASCADE,
    telemetry_id text NOT NULL REFERENCES security_telemetry(id) ON DELETE CASCADE,
    rule_id text NOT NULL REFERENCES detection_rules(id) ON DELETE CASCADE,
    severity integer NOT NULL CHECK (severity BETWEEN 1 AND 5),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(telemetry_id, rule_id)
);
CREATE INDEX security_alerts_environment_time_idx ON security_alerts (environment_id, created_at DESC, id DESC);
