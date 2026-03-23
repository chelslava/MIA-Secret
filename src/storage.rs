use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use uuid::Uuid;

use crate::config::Config;
use crate::domain::{SecretRecord, TokenRecord};
use crate::error::AppError;

const MIGRATIONS: &[(&str, &str)] = &[("001_init.sql", include_str!("../migrations/001_init.sql"))];

#[derive(Debug, Clone)]
pub struct StorageOptions {
    pub create_backup_before_write: bool,
    pub max_backups: usize,
    pub backup_dir: PathBuf,
    pub sqlite_busy_timeout_ms: u64,
}

impl Default for StorageOptions {
    fn default() -> Self {
        Self {
            create_backup_before_write: false,
            max_backups: 10,
            backup_dir: PathBuf::from("./data/backups"),
            sqlite_busy_timeout_ms: 5_000,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SqliteStorage {
    db_path: PathBuf,
    options: StorageOptions,
}

impl SqliteStorage {
    #[allow(dead_code)]
    pub fn new(path: impl AsRef<Path>) -> Result<Self, AppError> {
        Self::new_with_options(path, StorageOptions::default())
    }

    pub fn from_config(cfg: &Config) -> Result<Self, AppError> {
        let options = StorageOptions {
            create_backup_before_write: cfg.storage.create_backup_before_write,
            max_backups: cfg.storage.max_backups.max(1) as usize,
            backup_dir: PathBuf::from(&cfg.general.data_dir).join("backups"),
            sqlite_busy_timeout_ms: cfg.storage.sqlite_busy_timeout_ms,
        };
        Self::new_with_options(&cfg.general.database_path, options)
    }

    pub fn new_with_options(
        path: impl AsRef<Path>,
        options: StorageOptions,
    ) -> Result<Self, AppError> {
        let storage = Self {
            db_path: path.as_ref().to_path_buf(),
            options,
        };
        storage.migrate()?;
        Ok(storage)
    }

    pub fn migrate(&self) -> Result<(), AppError> {
        let mut conn = self.open_conn()?;
        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA foreign_keys = ON;
            CREATE TABLE IF NOT EXISTS schema_migrations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                applied_at INTEGER NOT NULL
            );
            "#,
        )?;
        apply_migrations(&mut conn)?;
        Ok(())
    }

    pub fn has_any_tokens(&self) -> Result<bool, AppError> {
        let conn = self.open_conn()?;
        let count: i64 = conn.query_row("SELECT COUNT(1) FROM tokens", [], |row| row.get(0))?;
        Ok(count > 0)
    }

    pub fn insert_secret(&self, secret: &SecretRecord) -> Result<(), AppError> {
        let tags = serde_json::to_string(&secret.tags)
            .map_err(|e| AppError::Serialization(format!("failed to serialize tags: {e}")))?;
        self.run_write_tx("secret", move |tx| {
            let result = tx.execute(
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
        })
    }

    pub fn update_secret(&self, secret: &SecretRecord) -> Result<(), AppError> {
        let tags = serde_json::to_string(&secret.tags)
            .map_err(|e| AppError::Serialization(format!("failed to serialize tags: {e}")))?;
        self.run_write_tx("secret", move |tx| {
            let changed = tx.execute(
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
        })
    }

    pub fn delete_secret(&self, id: Uuid) -> Result<(), AppError> {
        self.run_write_tx("secret", move |tx| {
            let changed = tx.execute("DELETE FROM secrets WHERE id = ?1", [id.to_string()])?;
            if changed == 0 {
                return Err(AppError::NotFound(format!("secret not found: {id}")));
            }
            Ok(())
        })
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
        get_secret_by_path_in_tx(&conn, path)
    }

    pub fn insert_token(&self, token: &TokenRecord) -> Result<(), AppError> {
        let scopes = serde_json::to_string(&token.scopes)
            .map_err(|e| AppError::Serialization(format!("failed to serialize scopes: {e}")))?;
        self.run_write_tx("token", move |tx| {
            let result = tx.execute(
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
        })
    }

    pub fn update_token(&self, token: &TokenRecord) -> Result<(), AppError> {
        let scopes = serde_json::to_string(&token.scopes)
            .map_err(|e| AppError::Serialization(format!("failed to serialize scopes: {e}")))?;
        self.run_write_tx("token", move |tx| {
            let changed = tx.execute(
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
        })
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

    fn run_write_tx<T>(
        &self,
        _entity: &str,
        op: impl FnOnce(&Transaction<'_>) -> Result<T, AppError>,
    ) -> Result<T, AppError> {
        if self.options.create_backup_before_write {
            self.backup_database()?;
        }
        let mut conn = self.open_conn()?;
        let tx = conn.transaction()?;
        let result = op(&tx)?;
        tx.commit()?;
        Ok(result)
    }

    pub fn run_import_tx<T>(
        &self,
        op: impl FnOnce(&Transaction<'_>) -> Result<T, AppError>,
    ) -> Result<T, AppError> {
        if self.options.create_backup_before_write {
            self.backup_database()?;
        }
        let mut conn = self.open_conn()?;
        let tx = conn.transaction()?;
        let result = op(&tx)?;
        tx.commit()?;
        Ok(result)
    }

    pub fn get_secret_by_path_tx(
        &self,
        tx: &Transaction<'_>,
        path: &str,
    ) -> Result<Option<SecretRecord>, AppError> {
        get_secret_by_path_in_tx(tx, path)
    }

    pub fn insert_secret_tx(
        &self,
        tx: &Transaction<'_>,
        secret: &SecretRecord,
    ) -> Result<(), AppError> {
        let tags = serde_json::to_string(&secret.tags)
            .map_err(|e| AppError::Serialization(format!("failed to serialize tags: {e}")))?;
        let result = tx.execute(
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

    pub fn update_secret_tx(
        &self,
        tx: &Transaction<'_>,
        secret: &SecretRecord,
    ) -> Result<(), AppError> {
        let tags = serde_json::to_string(&secret.tags)
            .map_err(|e| AppError::Serialization(format!("failed to serialize tags: {e}")))?;
        let changed = tx.execute(
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

    fn backup_database(&self) -> Result<(), AppError> {
        if !self.db_path.exists() {
            return Ok(());
        }
        std::fs::create_dir_all(&self.options.backup_dir)?;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let backup_name = format!("secrets-{timestamp}-{}.db", Uuid::new_v4());
        let backup_path = self.options.backup_dir.join(backup_name);
        std::fs::copy(&self.db_path, &backup_path)?;
        self.rotate_backups()
    }

    fn rotate_backups(&self) -> Result<(), AppError> {
        let mut entries = std::fs::read_dir(&self.options.backup_dir)?
            .filter_map(Result::ok)
            .filter(|entry| entry.path().is_file())
            .collect::<Vec<_>>();
        entries.sort_by_key(|entry| {
            entry
                .metadata()
                .and_then(|m| m.modified())
                .unwrap_or(SystemTime::UNIX_EPOCH)
        });
        let keep = self.options.max_backups;
        if entries.len() <= keep {
            return Ok(());
        }
        let to_delete = entries.len() - keep;
        for entry in entries.into_iter().take(to_delete) {
            let _ = std::fs::remove_file(entry.path());
        }
        Ok(())
    }

    fn open_conn(&self) -> Result<Connection, AppError> {
        let conn = Connection::open(&self.db_path)?;
        conn.busy_timeout(std::time::Duration::from_millis(
            self.options.sqlite_busy_timeout_ms,
        ))?;
        Ok(conn)
    }
}

fn get_secret_by_path_in_tx(conn: &Connection, path: &str) -> Result<Option<SecretRecord>, AppError> {
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

fn apply_migrations(conn: &mut Connection) -> Result<(), AppError> {
    for (name, sql) in MIGRATIONS {
        let already_applied: Option<i64> = conn
            .query_row(
                "SELECT id FROM schema_migrations WHERE name = ?1",
                [*name],
                |row| row.get(0),
            )
            .optional()?;
        if already_applied.is_some() {
            continue;
        }

        let tx = conn.transaction()?;
        tx.execute_batch(sql)?;
        tx.execute(
            "INSERT INTO schema_migrations (name, applied_at) VALUES (?1, ?2)",
            params![*name, current_unix_ts()],
        )?;
        tx.commit()?;
    }

    Ok(())
}

fn current_unix_ts() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
