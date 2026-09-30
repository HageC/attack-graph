CREATE TABLE simulation_jobs (
    id text PRIMARY KEY,
    environment_id text NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    run_id text NOT NULL REFERENCES simulation_runs(id) ON DELETE CASCADE,
    status text NOT NULL CHECK (status IN ('running','paused','stopped','completed')),
    event_cursor integer NOT NULL DEFAULT 0 CHECK (event_cursor >= 0),
    speed double precision NOT NULL DEFAULT 1 CHECK (speed IN (0.5,1,2,4)),
    position_seconds double precision NOT NULL DEFAULT 0 CHECK (position_seconds >= 0),
    resumed_at timestamptz NOT NULL DEFAULT now(),
    created_by text NOT NULL REFERENCES users(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX simulation_jobs_running_idx ON simulation_jobs (status, updated_at) WHERE status = 'running';
CREATE INDEX simulation_jobs_environment_time_idx ON simulation_jobs (environment_id, created_at DESC);
CREATE UNIQUE INDEX simulation_jobs_one_active_run_idx ON simulation_jobs (environment_id, run_id) WHERE status IN ('running','paused');
