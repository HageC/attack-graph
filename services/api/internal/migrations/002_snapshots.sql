CREATE TABLE environment_snapshots (
    id text PRIMARY KEY,
    environment_id text NOT NULL REFERENCES environments(id),
    version bigint NOT NULL CHECK (version > 0),
    content_hash text NOT NULL,
    graph jsonb NOT NULL,
    vulnerabilities jsonb NOT NULL,
    created_by text NOT NULL REFERENCES users(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (environment_id, version)
);
CREATE INDEX environment_snapshots_environment_version_idx ON environment_snapshots (environment_id, version DESC);
