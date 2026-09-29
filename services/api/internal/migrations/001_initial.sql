CREATE TABLE IF NOT EXISTS organizations (
    id text PRIMARY KEY,
    name text NOT NULL
);
CREATE TABLE IF NOT EXISTS environments (
    id text PRIMARY KEY,
    organization_id text NOT NULL REFERENCES organizations(id),
    name text NOT NULL,
    description text NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS environments_org_idx ON environments (organization_id);
CREATE TABLE IF NOT EXISTS users (
    id text PRIMARY KEY,
    email text NOT NULL,
    password_hash text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS users_email_lower_idx ON users (lower(email));
CREATE TABLE IF NOT EXISTS memberships (
    user_id text NOT NULL REFERENCES users(id),
    organization_id text NOT NULL REFERENCES organizations(id),
    role text NOT NULL CHECK (role IN ('viewer','editor','admin')),
    PRIMARY KEY (user_id, organization_id)
);
CREATE INDEX IF NOT EXISTS memberships_org_idx ON memberships (organization_id, user_id);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash bytea PRIMARY KEY,
    user_id text NOT NULL REFERENCES users(id),
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions (user_id);
CREATE INDEX IF NOT EXISTS sessions_expiry_idx ON sessions (expires_at);
CREATE TABLE IF NOT EXISTS audit_records (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_id text REFERENCES users(id),
    environment_id text REFERENCES environments(id),
    action text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    details jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS audit_environment_time_idx ON audit_records (environment_id, created_at DESC);
