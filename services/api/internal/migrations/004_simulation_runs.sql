CREATE TABLE simulation_runs (
    id text PRIMARY KEY,
    environment_id text NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    snapshot_id text NOT NULL REFERENCES environment_snapshots(id),
    seed bigint NOT NULL,
    config jsonb NOT NULL,
    summary jsonb NOT NULL,
    events jsonb NOT NULL,
    created_by text NOT NULL REFERENCES users(id),
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX simulation_runs_environment_time_idx ON simulation_runs (environment_id, created_at DESC);
