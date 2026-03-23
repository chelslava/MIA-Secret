use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use mia_secret::bootstrap;
use mia_secret::config::Config;
use mia_secret::crypto::CryptoService;
use mia_secret::domain::{CreateSecretRequest, CreateTokenRequest, UpdateSecretRequest};
use mia_secret::error::AppError;
use mia_secret::service::AppService;
use mia_secret::storage::{SqliteStorage, StorageOptions};
use rusqlite::Connection;
use serde_json::json;
use uuid::Uuid;

const MASTER_KEY: [u8; 32] = [0x42; 32];
const ARGON2_MEMORY_KB: u32 = 65_536;
const ARGON2_TIME_COST: u32 = 3;
const ARGON2_PARALLELISM: u32 = 1;

struct TestDir {
    path: PathBuf,
}

impl TestDir {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("mia-secret-{name}-{}", Uuid::new_v4()));
        fs::create_dir_all(&path).expect("failed to create temp dir");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn test_config(root: &Path) -> Config {
    let mut cfg = Config::default();
    let data_dir = root.join("data");
    let database_path = data_dir.join("secrets.db");

    cfg.general.data_dir = data_dir.to_string_lossy().into_owned();
    cfg.general.database_path = database_path.to_string_lossy().into_owned();
    cfg.crypto.argon2_memory_kb = ARGON2_MEMORY_KB;
    cfg.crypto.argon2_time_cost = ARGON2_TIME_COST;
    cfg.crypto.argon2_parallelism = ARGON2_PARALLELISM;
    cfg.crypto.encrypt_notes = true;
    cfg.crypto.encrypt_custom_fields = true;
    cfg
}

fn write_master_key(cfg: &Config) {
    let path = Path::new(&cfg.general.data_dir).join("master.key");
    fs::create_dir_all(&cfg.general.data_dir).expect("failed to create data dir");
    fs::write(path, MASTER_KEY).expect("failed to write master key");
}

fn build_service(cfg: &Config) -> AppService {
    let storage = Arc::new(SqliteStorage::new(&cfg.general.database_path).expect("storage init"));
    let crypto = CryptoService::from_config(cfg).expect("crypto init");
    AppService::new(storage, crypto)
}

fn read_sqlite_artifacts(db_path: &Path) -> Vec<u8> {
    let mut bytes = Vec::new();
    for candidate in sqlite_related_paths(db_path) {
        if let Ok(chunk) = fs::read(candidate) {
            bytes.extend_from_slice(&chunk);
        }
    }
    bytes
}

fn sqlite_related_paths(db_path: &Path) -> [PathBuf; 4] {
    [
        db_path.to_path_buf(),
        PathBuf::from(format!("{}-wal", db_path.display())),
        PathBuf::from(format!("{}-shm", db_path.display())),
        PathBuf::from(format!("{}-journal", db_path.display())),
    ]
}

fn assert_not_contains(haystack: &[u8], needle: &str) {
    let needle = needle.as_bytes();
    assert!(
        !haystack
            .windows(needle.len())
            .any(|window| window == needle),
        "found plaintext {needle:?} in sqlite artifacts"
    );
}

fn is_not_found(err: AppError) -> bool {
    matches!(err, AppError::NotFound(_))
}

#[test]
fn init_storage_and_migrate_is_idempotent() {
    let root = TestDir::new("init");
    let cfg = test_config(root.path());

    bootstrap::ensure_layout(&cfg).expect("ensure layout");
    bootstrap::ensure_layout(&cfg).expect("ensure layout idempotent");

    let master_key = Path::new(&cfg.general.data_dir).join("master.key");
    assert!(master_key.exists(), "master key should exist after init");
    assert_eq!(fs::read(&master_key).expect("read master key").len(), 32);

    let storage = SqliteStorage::new(&cfg.general.database_path).expect("storage init");
    storage.migrate().expect("idempotent migrate");
    assert!(!storage.has_any_tokens().expect("token count"));

    let conn = Connection::open(&cfg.general.database_path).expect("open sqlite");
    let mut stmt = conn
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
        .expect("prepare sqlite_master query");
    let tables = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .expect("query sqlite_master")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect table names");

    assert!(tables.iter().any(|name| name == "secrets"));
    assert!(tables.iter().any(|name| name == "tokens"));
}

#[test]
fn token_create_authorize_and_revoke_flow() {
    let root = TestDir::new("token");
    let cfg = test_config(root.path());
    write_master_key(&cfg);

    let service = build_service(&cfg);
    let created = service
        .create_token(CreateTokenRequest {
            name: "ops-token".to_owned(),
            scopes: vec!["tokens.manage".to_owned(), "secrets.read".to_owned()],
            expires_at: None,
        })
        .expect("create token");

    assert!(!created.token.is_empty());
    assert_eq!(created.record.name, "ops-token");
    assert!(
        created
            .record
            .scopes
            .iter()
            .any(|scope| scope == "tokens.manage")
    );
    assert!(created.record.revoked_at.is_none());

    let authorized = service
        .authorize(&created.token, "tokens.manage")
        .expect("authorize token");
    assert_eq!(authorized.id, created.record.id);
    assert!(authorized.last_used_at.is_some());

    let storage = SqliteStorage::new(&cfg.general.database_path).expect("storage inspect");
    let stored = storage
        .get_token_by_id(created.record.id)
        .expect("load token")
        .expect("token exists");
    assert!(stored.last_used_at.is_some());
    assert!(stored.revoked_at.is_none());

    let revoked = service
        .revoke_token(created.record.id)
        .expect("revoke token");
    assert_eq!(revoked.id, created.record.id);
    assert!(revoked.revoked_at.is_some());

    let auth_after_revoke = service.authorize(&created.token, "tokens.manage");
    assert!(matches!(auth_after_revoke, Err(AppError::Unauthorized(_))));
}

#[test]
fn secret_crud_roundtrip_and_plaintext_is_not_written_to_sqlite() {
    let root = TestDir::new("secret");
    let cfg = test_config(root.path());
    write_master_key(&cfg);

    let db_path = PathBuf::from(&cfg.general.database_path);
    let secret_id = {
        let service = build_service(&cfg);

        let created = service
            .create_secret(CreateSecretRequest {
                path: "prod/api".to_owned(),
                resource: Some("api".to_owned()),
                login: Some("svc-user".to_owned()),
                password: "super-secret-password".to_owned(),
                url: Some("https://example.invalid".to_owned()),
                notes: Some("top secret notes".to_owned()),
                tags: Some(vec!["prod".to_owned(), "api".to_owned()]),
                custom_fields: Some(json!({
                    "client_secret": "abc123",
                    "retry": 3
                })),
            })
            .expect("create secret");

        assert_eq!(created.path, "prod/api");
        assert_eq!(created.password, "super-secret-password");
        assert_eq!(created.notes.as_deref(), Some("top secret notes"));
        assert_eq!(created.tags, vec!["prod", "api"]);
        assert!(matches!(
            created.custom_fields.as_ref().and_then(|value| value.get("client_secret")),
            Some(serde_json::Value::String(value)) if value == "abc123"
        ));

        let fetched_by_id = service.get_secret(created.id).expect("get by id");
        assert_eq!(fetched_by_id.password, "super-secret-password");

        let fetched_by_path = service.get_secret_by_path("prod/api").expect("get by path");
        assert_eq!(fetched_by_path.id, created.id);

        let listed = service.list_secrets().expect("list secrets");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, created.id);

        let updated = service
            .update_secret(
                created.id,
                UpdateSecretRequest {
                    path: Some("prod/api-v2".to_owned()),
                    resource: Some("api-v2".to_owned()),
                    login: Some("svc-user-2".to_owned()),
                    password: Some("updated-secret-password".to_owned()),
                    url: Some("https://example.invalid/v2".to_owned()),
                    notes: Some("updated secret notes".to_owned()),
                    tags: Some(vec!["prod".to_owned(), "api-v2".to_owned()]),
                    custom_fields: Some(json!({
                        "client_secret": "def456",
                        "retry": 4
                    })),
                },
            )
            .expect("update secret");

        assert_eq!(updated.path, "prod/api-v2");
        assert_eq!(updated.password, "updated-secret-password");
        assert_eq!(updated.notes.as_deref(), Some("updated secret notes"));
        assert_eq!(updated.tags, vec!["prod", "api-v2"]);
        assert!(matches!(
            updated.custom_fields.as_ref().and_then(|value| value.get("client_secret")),
            Some(serde_json::Value::String(value)) if value == "def456"
        ));

        let fetched_updated = service.get_secret(created.id).expect("get updated");
        assert_eq!(fetched_updated.path, "prod/api-v2");
        assert_eq!(fetched_updated.password, "updated-secret-password");

        created.id
    };

    let sqlite_bytes = read_sqlite_artifacts(&db_path);
    assert_not_contains(&sqlite_bytes, "super-secret-password");
    assert_not_contains(&sqlite_bytes, "updated-secret-password");
    assert_not_contains(&sqlite_bytes, "top secret notes");
    assert_not_contains(&sqlite_bytes, "updated secret notes");
    assert_not_contains(&sqlite_bytes, r#""client_secret":"abc123""#);
    assert_not_contains(&sqlite_bytes, r#""client_secret":"def456""#);

    {
        let service = build_service(&cfg);
        let fetched = service.get_secret(secret_id).expect("secret still exists");
        assert_eq!(fetched.path, "prod/api-v2");
        assert_eq!(fetched.password, "updated-secret-password");

        let listed = service.list_secrets().expect("list secrets");
        assert_eq!(listed.len(), 1);

        service.delete_secret(secret_id).expect("delete secret");
        assert!(is_not_found(
            service
                .get_secret(secret_id)
                .expect_err("deleted secret should not exist")
        ));
        assert!(
            service
                .list_secrets()
                .expect("list after delete")
                .is_empty()
        );
    }
}

#[test]
fn storage_backup_rotation_keeps_configured_limit() {
    let root = TestDir::new("backup-rotation");
    let cfg = test_config(root.path());
    write_master_key(&cfg);

    let backup_dir = root.path().join("backup-artifacts");
    let options = StorageOptions {
        create_backup_before_write: true,
        max_backups: 2,
        backup_dir: backup_dir.clone(),
        sqlite_busy_timeout_ms: 5_000,
    };
    let storage = SqliteStorage::new_with_options(&cfg.general.database_path, options)
        .expect("storage with backup options");
    let crypto = CryptoService::from_config(&cfg).expect("crypto init");
    let service = AppService::new(Arc::new(storage), crypto);

    for index in 0..4 {
        let _ = service
            .create_secret(CreateSecretRequest {
                path: format!("backup/item-{index}"),
                resource: None,
                login: None,
                password: format!("pwd-{index}"),
                url: None,
                notes: None,
                tags: None,
                custom_fields: None,
            })
            .expect("create secret for backup");
    }

    let backup_files = fs::read_dir(&backup_dir)
        .expect("read backup directory")
        .filter_map(Result::ok)
        .filter(|entry| entry.path().is_file())
        .count();

    assert!(
        backup_files <= 2,
        "expected no more than 2 backups, got {backup_files}"
    );
}

#[test]
fn config_rejects_non_loopback_bind_host() {
    let mut cfg = Config::default();
    cfg.server.host = "0.0.0.0".to_owned();
    let result = cfg.validate();
    assert!(
        matches!(result, Err(AppError::Validation(ref message)) if message.contains("loopback")),
        "expected loopback validation error, got {result:?}"
    );
}
