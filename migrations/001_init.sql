CREATE TABLE IF NOT EXISTS secrets (
    id TEXT PRIMARY KEY NOT NULL,
    path TEXT NOT NULL UNIQUE,
    resource TEXT NULL,
    login TEXT NULL,
    password_encrypted TEXT NOT NULL,
    url TEXT NULL,
    notes_encrypted TEXT NULL,
    tags TEXT NOT NULL,
    custom_fields_encrypted TEXT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS tokens (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    scopes TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NULL,
    revoked_at INTEGER NULL,
    last_used_at INTEGER NULL
);
