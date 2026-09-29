CREATE TABLE graph_layouts (
    id text PRIMARY KEY,
    environment_id text NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    name text NOT NULL CHECK (char_length(name) BETWEEN 2 AND 80),
    positions jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(positions) = 'object'),
    created_by text NOT NULL REFERENCES users(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX graph_layouts_env_name_idx ON graph_layouts (environment_id, lower(name));
CREATE INDEX graph_layouts_env_updated_idx ON graph_layouts (environment_id, updated_at DESC);
