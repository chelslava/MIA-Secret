use std::path::{Path, PathBuf};

use rusqlite::{Connection, OptionalExtension, params};
use uuid::Uuid;

use crate::domain::{SecretRecord, TokenRecord};
use crate::error::AppError;

#[derive(Debug, Clone)]
pub struct SqliteStorage {
    db_path: PathBuf,
}

impl SqliteStorage {
    pub fn new(path: impl AsRef<Path>) -> Result<Self, AppError> {
        let storage = Self {
            db_path: path.as_ref().to_path_buf(),
        };
        storage.migrate()?;
        Ok(storage)
    }

    pub fn migrate(&self) -> Result<(), AppError> {
        let conn = self.open_conn()?;
        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA foreign_keys = ON;

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
            "#,
        )?;
        Ok(())
    }

    pub fn has_any_tokens(&self) -> Result<bool, AppError> {
        let conn = self.open_conn()?;
        let count: i64 = conn.query_row("SELECT COUNT(1) FROM tokens", [], |row| row.get(0))?;
        Ok(count > 0)
    }

    pub fn insert_secret(&self, secret: &SecretRecord) -> Result<(), AppError> {
        let conn = self.open_conn()?;
        let tags = serde_json::to_string(&secret.tags)
            .map_err(|e| AppError::Serialization(format!("failed to serialize tags: {e}")))?;
        let result = conn.execute(
            r#"
            INSERT INTO secrets (
                id, path, resource, login, password_encrypted, url,
                notes_encrypted, tags, custom_fields_encrypted, created_at, updated_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
            "#,
            params![
                secret.id.to_string(),
                secret.path,
                secret.resource,
                secret.login,
                secret.password_encrypted,
                secret.url,
                secret.notes_encrypted,
                tags,
                secret.custom_fields_encrypted,
                secret.created_at,
                secret.updated_at
            ],
        );
        map_sqlite_write_result(result, "secret")
    }

    pub fn update_secret(&self, secret: &SecretRecord) -> Result<(), AppError> {
        let conn = self.open_conn()?;
        let tags = serde_json::to_string(&secret.tags)
            .map_err(|e| AppError::Serialization(format!("failed to serialize tags: {e}")))?;
        let changed = conn.execute(
            r#"
            UPDATE secrets SET
                path = ?2,
                resource = ?3,
                login = ?4,
                password_encrypted = ?5,
                url = ?6,
                notes_encrypted = ?7,
                tags = ?8,
                custom_fields_encrypted = ?9,
                updated_at = ?10
            WHERE id = ?1
            "#,
            params![
                secret.id.to_string(),
                secret.path,
                secret.resource,
                secret.login,
                secret.password_encrypted,
                secret.url,
                secret.notes_encrypted,
                tags,
                secret.custom_fields_encrypted,
                secret.updated_at
            ],
        );
        let changed = map_sqlite_write_rows(changed, "secret")?;
        if changed == 0 {
            return Err(AppError::NotFound(format!(
                "secret not found: {}",
                secret.id
            )));
        }
        Ok(())
    }

    pub fn delete_secret(&self, id: Uuid) -> Result<(), AppError> {
        let conn = self.open_conn()?;
        let changed = conn.execute("DELETE FROM secrets WHERE id = ?1", [id.to_string()])?;
        if changed == 0 {
            return Err(AppError::NotFound(format!("secret not found: {id}")));
        }
        Ok(())
    }

    pub fn list_secrets(&self) -> Result<Vec<SecretRecord>, AppError> {
        let conn = self.open_conn()?;
        let mut stmt = conn.prepare(
            r#"
            SELECT
                id, path, resource, login, password_encrypted, url,
                notes_encrypted, tags, custom_fields_encrypted, created_at, updated_at
            FROM secrets
            ORDER BY path ASC
            "#,
        )?;
        let rows = stmt.query_map([], map_secret_row)?;
        collect_rows(rows)
    }

    pub fn get_secret_by_id(&self, id: Uuid) -> Result<Option<SecretRecord>, AppError> {
        let conn = self.open_conn()?;
        conn.query_row(
            r#"
            SELECT
                id, path, resource, login, password_encrypted, url,
                notes_encrypted, tags, custom_fields_encrypted, created_at, updated_at
            FROM secrets WHERE id = ?1
            "#,
            [id.to_string()],
            map_secret_row,
        )
        .optional()
        .map_err(Into::into)
    }

    pub fn get_secret_by_path(&self, path: &str) -> Result<Option<SecretRecord>, AppError> {
        let conn = self.open_conn()?;
        conn.query_row(
            r#"
            SELECT
                id, path, resource, login, password_encrypted, url,
                notes_encrypted, tags, custom_fields_encrypted, created_at, updated_at
            FROM secrets WHERE path = ?1
            "#,
            [path],
            map_secret_row,
        )
        .optional()
        .map_err(Into::into)
    }

    pub fn insert_token(&self, token: &TokenRecord) -> Result<(), AppError> {
        let conn = self.open_conn()?;
        let scopes = serde_json::to_string(&token.scopes)
            .map_err(|e| AppError::Serialization(format!("failed to serialize scopes: {e}")))?;
        let result = conn.execute(
            r#"
            INSERT INTO tokens (
                id, name, token_hash, scopes, created_at, expires_at, revoked_at, last_used_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
            params![
                token.id.to_string(),
                token.name,
                token.token_hash,
                scopes,
                token.created_at,
                token.expires_at,
                token.revoked_at,
                token.last_used_at
            ],
        );
        map_sqlite_write_result(result, "token")
    }

    pub fn update_token(&self, token: &TokenRecord) -> Result<(), AppError> {
        let conn = self.open_conn()?;
        let scopes = serde_json::to_string(&token.scopes)
            .map_err(|e| AppError::Serialization(format!("failed to serialize scopes: {e}")))?;
        let changed = conn.execute(
            r#"
            UPDATE tokens SET
                name = ?2,
                token_hash = ?3,
                scopes = ?4,
                expires_at = ?5,
                revoked_at = ?6,
                last_used_at = ?7
            WHERE id = ?1
            "#,
            params![
                token.id.to_string(),
                token.name,
                token.token_hash,
                scopes,
                token.expires_at,
                token.revoked_at,
                token.last_used_at
            ],
        );
        let changed = map_sqlite_write_rows(changed, "token")?;
        if changed == 0 {
            return Err(AppError::NotFound(format!("token not found: {}", token.id)));
        }
        Ok(())
    }

    pub fn list_tokens(&self) -> Result<Vec<TokenRecord>, AppError> {
        let conn = self.open_conn()?;
        let mut stmt = conn.prepare(
            r#"
            SELECT id, name, token_hash, scopes, created_at, expires_at, revoked_at, last_used_at
            FROM tokens
            ORDER BY created_at DESC
            "#,
        )?;
        let rows = stmt.query_map([], map_token_row)?;
        collect_rows(rows)
    }

    pub fn get_token_by_id(&self, id: Uuid) -> Result<Option<TokenRecord>, AppError> {
        let conn = self.open_conn()?;
        conn.query_row(
            r#"
            SELECT id, name, token_hash, scopes, created_at, expires_at, revoked_at, last_used_at
            FROM tokens
            WHERE id = ?1
            "#,
            [id.to_string()],
            map_token_row,
        )
        .optional()
        .map_err(Into::into)
    }

    pub fn get_token_by_hash(&self, token_hash: &str) -> Result<Option<TokenRecord>, AppError> {
        let conn = self.open_conn()?;
        conn.query_row(
            r#"
            SELECT id, name, token_hash, scopes, created_at, expires_at, revoked_at, last_used_at
            FROM tokens
            WHERE token_hash = ?1
            "#,
            [token_hash],
            map_token_row,
        )
        .optional()
        .map_err(Into::into)
    }

    fn open_conn(&self) -> Result<Connection, AppError> {
        Connection::open(&self.db_path).map_err(Into::into)
    }
}

fn map_secret_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SecretRecord> {
    let tags_json: String = row.get(7)?;
    let tags = serde_json::from_str::<Vec<String>>(&tags_json).unwrap_or_default();
    Ok(SecretRecord {
        id: parse_uuid(row.get::<_, String>(0)?)?,
        path: row.get(1)?,
        resource: row.get(2)?,
        login: row.get(3)?,
        password_encrypted: row.get(4)?,
        url: row.get(5)?,
        notes_encrypted: row.get(6)?,
        tags,
        custom_fields_encrypted: row.get(8)?,
        created_at: row.get(9)?,
        updated_at: row.get(10)?,
    })
}

fn map_token_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<TokenRecord> {
    let scopes_json: String = row.get(3)?;
    let scopes = serde_json::from_str::<Vec<String>>(&scopes_json).unwrap_or_default();
    Ok(TokenRecord {
        id: parse_uuid(row.get::<_, String>(0)?)?,
        name: row.get(1)?,
        token_hash: row.get(2)?,
        scopes,
        created_at: row.get(4)?,
        expires_at: row.get(5)?,
        revoked_at: row.get(6)?,
        last_used_at: row.get(7)?,
    })
}

fn parse_uuid(value: String) -> rusqlite::Result<Uuid> {
    Uuid::parse_str(&value).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(err))
    })
}

fn collect_rows<T, F>(rows: rusqlite::MappedRows<'_, F>) -> Result<Vec<T>, AppError>
where
    F: FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
{
    rows.collect::<rusqlite::Result<Vec<T>>>()
        .map_err(Into::into)
}

fn map_sqlite_write_result(result: rusqlite::Result<usize>, entity: &str) -> Result<(), AppError> {
    match result {
        Ok(_) => Ok(()),
        Err(rusqlite::Error::SqliteFailure(err, _))
            if err.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            Err(AppError::Conflict(format!("{entity} already exists")))
        }
        Err(other) => Err(AppError::Storage(other.to_string())),
    }
}

fn map_sqlite_write_rows(result: rusqlite::Result<usize>, entity: &str) -> Result<usize, AppError> {
    match result {
        Ok(changed) => Ok(changed),
        Err(rusqlite::Error::SqliteFailure(err, _))
            if err.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            Err(AppError::Conflict(format!("{entity} already exists")))
        }
        Err(other) => Err(AppError::Storage(other.to_string())),
    }
}
