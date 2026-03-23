use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use mia_secret::api;
use mia_secret::bootstrap;
use mia_secret::config::Config;
use rusqlite::Connection;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use uuid::Uuid;

struct TestDir {
    path: PathBuf,
}

impl TestDir {
    fn new(name: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("mia-secret-contract-{name}-{}", Uuid::new_v4()));
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
    cfg.server.host = "127.0.0.1".to_owned();
    cfg.server.request_timeout_secs = 10;
    cfg
}

async fn start_server(cfg: &Config) -> (String, oneshot::Sender<()>, JoinHandle<()>) {
    let app = api::build_app(cfg.clone()).expect("build app");
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral listener");
    let addr = listener.local_addr().expect("local addr");
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app.into_make_service())
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await;
    });

    (format!("http://{addr}"), shutdown_tx, handle)
}

async fn stop_server(tx: oneshot::Sender<()>, handle: JoinHandle<()>) {
    let _ = tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(3), handle).await;
}

fn assert_has_string(value: &Value, key: &str) {
    assert!(
        value.get(key).and_then(Value::as_str).is_some(),
        "expected string field `{key}`, got {value}"
    );
}

fn assert_exact_keys(value: &Value, expected: &[&str]) {
    let object = value.as_object().expect("expected json object");
    let actual = object.keys().map(|k| k.as_str()).collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    assert_eq!(actual, expected, "unexpected key set: {value}");
}

fn assert_error_contract(value: &Value, expected_code: &str) {
    let error = value.get("error").expect("error envelope");
    assert_exact_keys(error, &["code", "message", "traceId"]);
    assert_eq!(error.get("code"), Some(&json!(expected_code)));
    assert!(
        error.get("message").and_then(Value::as_str).is_some(),
        "error.message must be string"
    );
    assert!(
        error.get("traceId").and_then(Value::as_str).is_some(),
        "error.traceId must be string"
    );
}

#[tokio::test]
async fn contract_health_and_readiness_payload() {
    let root = TestDir::new("health-ready");
    let cfg = test_config(root.path());
    bootstrap::ensure_layout(&cfg).expect("ensure layout");

    let (base_url, shutdown_tx, handle) = start_server(&cfg).await;
    let client = reqwest::Client::new();

    let health = client
        .get(format!("{base_url}/api/v1/health"))
        .send()
        .await
        .expect("health request");
    assert_eq!(health.status(), reqwest::StatusCode::OK);
    let health_json: Value = health.json().await.expect("health json");
    assert_eq!(health_json.get("status"), Some(&json!("ok")));
    assert_has_string(&health_json, "version");
    assert!(
        health_json
            .get("database_ready")
            .and_then(Value::as_bool)
            .is_some(),
        "database_ready must be bool"
    );
    assert!(
        health_json
            .get("config_loaded")
            .and_then(Value::as_bool)
            .is_some(),
        "config_loaded must be bool"
    );

    let ready = client
        .get(format!("{base_url}/api/v1/ready"))
        .send()
        .await
        .expect("ready request");
    assert_eq!(ready.status(), reqwest::StatusCode::OK);
    let ready_json: Value = ready.json().await.expect("ready json");
    assert_eq!(ready_json.get("status"), Some(&json!("ready")));
    assert_has_string(&ready_json, "version");
    let checks = ready_json.get("checks").expect("checks");
    assert!(
        checks
            .get("config_loaded")
            .and_then(Value::as_bool)
            .is_some(),
        "checks.config_loaded must be bool"
    );
    assert!(
        checks
            .get("database_connection")
            .and_then(Value::as_bool)
            .is_some(),
        "checks.database_connection must be bool"
    );
    assert!(
        checks
            .get("schema_migrations_present")
            .and_then(Value::as_bool)
            .is_some(),
        "checks.schema_migrations_present must be bool"
    );

    stop_server(shutdown_tx, handle).await;
}

#[tokio::test]
async fn contract_error_envelope_and_metrics_shape() {
    let root = TestDir::new("errors-metrics");
    let cfg = test_config(root.path());
    bootstrap::ensure_layout(&cfg).expect("ensure layout");

    let (base_url, shutdown_tx, handle) = start_server(&cfg).await;
    let client = reqwest::Client::new();

    let unauthorized = client
        .get(format!("{base_url}/api/v1/secrets"))
        .send()
        .await
        .expect("unauthorized request");
    assert_eq!(unauthorized.status(), reqwest::StatusCode::UNAUTHORIZED);
    let unauthorized_json: Value = unauthorized.json().await.expect("unauthorized json");
    assert_error_contract(&unauthorized_json, "unauthorized");

    let metrics = client
        .get(format!("{base_url}/api/v1/metrics"))
        .send()
        .await
        .expect("metrics request");
    assert_eq!(metrics.status(), reqwest::StatusCode::OK);
    let body = metrics.text().await.expect("metrics body");
    assert!(body.contains("mia_http_requests_total"));
    assert!(body.contains("mia_http_errors_total"));
    assert!(body.contains("mia_auth_failures_total"));
    assert!(body.contains("mia_token_created_total"));
    assert!(body.contains("mia_token_revoked_total"));

    stop_server(shutdown_tx, handle).await;
}

#[tokio::test]
async fn contract_negative_error_shapes_for_common_failures() {
    let root = TestDir::new("negative-errors");
    let cfg = test_config(root.path());
    bootstrap::ensure_layout(&cfg).expect("ensure layout");

    let (base_url, shutdown_tx, handle) = start_server(&cfg).await;
    let client = reqwest::Client::new();

    let unauthorized = client
        .get(format!("{base_url}/api/v1/secrets"))
        .send()
        .await
        .expect("unauthorized request");
    assert_eq!(unauthorized.status(), reqwest::StatusCode::UNAUTHORIZED);
    let unauthorized_json: Value = unauthorized.json().await.expect("unauthorized json");
    assert_error_contract(&unauthorized_json, "unauthorized");

    let admin_resp = client
        .post(format!("{base_url}/api/v1/tokens"))
        .json(&json!({
            "name": "admin",
            "scopes": ["tokens.manage", "secrets.read", "secrets.list", "secrets.write"]
        }))
        .send()
        .await
        .expect("admin token create");
    assert_eq!(admin_resp.status(), reqwest::StatusCode::OK);
    let admin_json: Value = admin_resp.json().await.expect("admin token json");
    let admin_token = admin_json["token"].as_str().expect("token").to_owned();

    let limited_resp = client
        .post(format!("{base_url}/api/v1/tokens"))
        .bearer_auth(&admin_token)
        .json(&json!({
            "name": "limited",
            "scopes": ["config.read"]
        }))
        .send()
        .await
        .expect("limited token create");
    assert_eq!(limited_resp.status(), reqwest::StatusCode::OK);
    let limited_json: Value = limited_resp.json().await.expect("limited token json");
    let limited_token = limited_json["token"].as_str().expect("token").to_owned();

    let forbidden = client
        .post(format!("{base_url}/api/v1/secrets"))
        .bearer_auth(&limited_token)
        .json(&json!({
            "path": "forbidden/path",
            "password": "pwd"
        }))
        .send()
        .await
        .expect("forbidden request");
    assert_eq!(forbidden.status(), reqwest::StatusCode::FORBIDDEN);
    let forbidden_json: Value = forbidden.json().await.expect("forbidden json");
    assert_error_contract(&forbidden_json, "forbidden");

    let invalid_uuid = client
        .get(format!("{base_url}/api/v1/secrets/not-a-uuid"))
        .bearer_auth(&admin_token)
        .send()
        .await
        .expect("invalid uuid request");
    assert_eq!(invalid_uuid.status(), reqwest::StatusCode::BAD_REQUEST);
    let invalid_uuid_json: Value = invalid_uuid.json().await.expect("invalid uuid json");
    assert_error_contract(&invalid_uuid_json, "validation_error");

    let missing_secret = client
        .get(format!("{base_url}/api/v1/secrets/{}", Uuid::new_v4()))
        .bearer_auth(&admin_token)
        .send()
        .await
        .expect("missing secret request");
    assert_eq!(missing_secret.status(), reqwest::StatusCode::NOT_FOUND);
    let missing_secret_json: Value = missing_secret.json().await.expect("missing secret json");
    assert_error_contract(&missing_secret_json, "not_found");

    stop_server(shutdown_tx, handle).await;
}

#[tokio::test]
async fn contract_rate_limited_error_shape() {
    let root = TestDir::new("rate-limited-error");
    let mut cfg = test_config(root.path());
    cfg.server.protected_rate_limit_rps = 1;
    bootstrap::ensure_layout(&cfg).expect("ensure layout");

    let (base_url, shutdown_tx, handle) = start_server(&cfg).await;
    let client = reqwest::Client::new();

    let token_resp = client
        .post(format!("{base_url}/api/v1/tokens"))
        .json(&json!({
            "name": "list-token",
            "scopes": ["secrets.list"]
        }))
        .send()
        .await
        .expect("token create");
    assert_eq!(token_resp.status(), reqwest::StatusCode::OK);
    let token_json: Value = token_resp.json().await.expect("token json");
    let token = token_json["token"].as_str().expect("token").to_owned();

    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

    let first = client
        .get(format!("{base_url}/api/v1/secrets"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("first protected request");
    assert_eq!(first.status(), reqwest::StatusCode::OK);

    let second = client
        .get(format!("{base_url}/api/v1/secrets"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("second protected request");
    assert_eq!(second.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);
    let second_json: Value = second.json().await.expect("rate limited json");
    assert_error_contract(&second_json, "rate_limited");

    stop_server(shutdown_tx, handle).await;
}

#[tokio::test]
async fn contract_readiness_not_ready_when_schema_migrations_missing() {
    let root = TestDir::new("readiness-schema-missing");
    let cfg = test_config(root.path());
    bootstrap::ensure_layout(&cfg).expect("ensure layout");
    let (base_url, shutdown_tx, handle) = start_server(&cfg).await;
    let client = reqwest::Client::new();

    let conn = Connection::open(&cfg.general.database_path).expect("open sqlite");
    conn.execute("DROP TABLE IF EXISTS schema_migrations", [])
        .expect("drop schema_migrations");

    let ready = client
        .get(format!("{base_url}/api/v1/ready"))
        .send()
        .await
        .expect("ready request");
    assert_eq!(ready.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);

    let ready_json: Value = ready.json().await.expect("ready json");
    assert_eq!(ready_json.get("status"), Some(&json!("not_ready")));
    let checks = ready_json.get("checks").expect("checks");
    assert_eq!(
        checks.get("database_connection"),
        Some(&Value::Bool(true)),
        "db must still be reachable"
    );
    assert_eq!(
        checks.get("schema_migrations_present"),
        Some(&Value::Bool(false)),
        "schema_migrations check must fail"
    );

    stop_server(shutdown_tx, handle).await;
}

#[tokio::test]
async fn contract_safe_config_shape() {
    let root = TestDir::new("safe-config");
    let cfg = test_config(root.path());
    bootstrap::ensure_layout(&cfg).expect("ensure layout");

    let (base_url, shutdown_tx, handle) = start_server(&cfg).await;
    let client = reqwest::Client::new();

    let token_resp = client
        .post(format!("{base_url}/api/v1/tokens"))
        .json(&json!({
            "name": "config-reader",
            "scopes": ["config.read"]
        }))
        .send()
        .await
        .expect("token create");
    assert_eq!(token_resp.status(), reqwest::StatusCode::OK);
    let token_json: Value = token_resp.json().await.expect("token json");
    let token = token_json["token"].as_str().expect("token").to_owned();

    let cfg_resp = client
        .get(format!("{base_url}/api/v1/config"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("config request");
    assert_eq!(cfg_resp.status(), reqwest::StatusCode::OK);
    let cfg_json: Value = cfg_resp.json().await.expect("config json");

    assert_exact_keys(
        &cfg_json,
        &["general", "server", "security", "crypto", "storage", "cli"],
    );
    assert_exact_keys(
        &cfg_json["server"],
        &[
            "host",
            "port",
            "request_timeout_secs",
            "max_request_body_kb",
            "protected_rate_limit_rps",
        ],
    );
    assert_exact_keys(
        &cfg_json["storage"],
        &[
            "auto_migrate",
            "create_backup_before_write",
            "max_backups",
            "sqlite_busy_timeout_ms",
        ],
    );

    stop_server(shutdown_tx, handle).await;
}

#[tokio::test]
async fn contract_secret_and_token_payload_shape() {
    let root = TestDir::new("secret-token-shape");
    let cfg = test_config(root.path());
    bootstrap::ensure_layout(&cfg).expect("ensure layout");

    let (base_url, shutdown_tx, handle) = start_server(&cfg).await;
    let client = reqwest::Client::new();

    let token_resp = client
        .post(format!("{base_url}/api/v1/tokens"))
        .json(&json!({
            "name": "contract-admin",
            "scopes": ["tokens.manage", "secrets.write", "secrets.read", "secrets.delete"]
        }))
        .send()
        .await
        .expect("token create");
    assert_eq!(token_resp.status(), reqwest::StatusCode::OK);
    let token_json: Value = token_resp.json().await.expect("token json");
    assert_exact_keys(&token_json, &["token", "record"]);
    assert_has_string(&token_json, "token");
    assert_exact_keys(
        &token_json["record"],
        &[
            "id",
            "name",
            "scopes",
            "created_at",
            "expires_at",
            "revoked_at",
            "last_used_at",
        ],
    );
    let token = token_json["token"].as_str().expect("token").to_owned();
    let token_id = token_json["record"]["id"]
        .as_str()
        .expect("token id")
        .to_owned();

    let secret_resp = client
        .post(format!("{base_url}/api/v1/secrets"))
        .bearer_auth(&token)
        .json(&json!({
            "path": "contract/item",
            "resource": "db",
            "login": "user",
            "password": "pwd",
            "url": "https://example.invalid",
            "notes": "note",
            "tags": ["a", "b"],
            "custom_fields": {"x": 1}
        }))
        .send()
        .await
        .expect("create secret");
    assert_eq!(secret_resp.status(), reqwest::StatusCode::OK);
    let secret_json: Value = secret_resp.json().await.expect("secret json");
    assert_exact_keys(
        &secret_json,
        &[
            "id",
            "path",
            "resource",
            "login",
            "password",
            "url",
            "notes",
            "tags",
            "custom_fields",
            "created_at",
            "updated_at",
        ],
    );

    let revoke_resp = client
        .post(format!("{base_url}/api/v1/tokens/{token_id}/revoke"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("revoke token");
    assert_eq!(revoke_resp.status(), reqwest::StatusCode::OK);
    let revoke_json: Value = revoke_resp.json().await.expect("revoke json");
    assert_exact_keys(
        &revoke_json,
        &[
            "id",
            "name",
            "scopes",
            "created_at",
            "expires_at",
            "revoked_at",
            "last_used_at",
        ],
    );

    stop_server(shutdown_tx, handle).await;
}

#[tokio::test]
async fn contract_secret_conflict_and_update_delete_edge_errors() {
    let root = TestDir::new("secret-edge-errors");
    let cfg = test_config(root.path());
    bootstrap::ensure_layout(&cfg).expect("ensure layout");

    let (base_url, shutdown_tx, handle) = start_server(&cfg).await;
    let client = reqwest::Client::new();

    let token_resp = client
        .post(format!("{base_url}/api/v1/tokens"))
        .json(&json!({
            "name": "edge-admin",
            "scopes": ["secrets.write", "secrets.read", "secrets.delete"]
        }))
        .send()
        .await
        .expect("token create");
    assert_eq!(token_resp.status(), reqwest::StatusCode::OK);
    let token_json: Value = token_resp.json().await.expect("token json");
    let token = token_json["token"].as_str().expect("token").to_owned();

    let created = client
        .post(format!("{base_url}/api/v1/secrets"))
        .bearer_auth(&token)
        .json(&json!({
            "path": "apps/prod/edge",
            "password": "secret-1"
        }))
        .send()
        .await
        .expect("create secret");
    assert_eq!(created.status(), reqwest::StatusCode::OK);

    let conflict = client
        .post(format!("{base_url}/api/v1/secrets"))
        .bearer_auth(&token)
        .json(&json!({
            "path": "apps/prod/edge",
            "password": "secret-2"
        }))
        .send()
        .await
        .expect("conflict create");
    assert_eq!(conflict.status(), reqwest::StatusCode::CONFLICT);
    let conflict_json: Value = conflict.json().await.expect("conflict json");
    assert_error_contract(&conflict_json, "conflict");

    let missing_update = client
        .patch(format!("{base_url}/api/v1/secrets/{}", Uuid::new_v4()))
        .bearer_auth(&token)
        .json(&json!({
            "password": "new-password"
        }))
        .send()
        .await
        .expect("missing update");
    assert_eq!(missing_update.status(), reqwest::StatusCode::NOT_FOUND);
    let missing_update_json: Value = missing_update.json().await.expect("update json");
    assert_error_contract(&missing_update_json, "not_found");

    let missing_delete = client
        .delete(format!("{base_url}/api/v1/secrets/{}", Uuid::new_v4()))
        .bearer_auth(&token)
        .send()
        .await
        .expect("missing delete");
    assert_eq!(missing_delete.status(), reqwest::StatusCode::NOT_FOUND);
    let missing_delete_json: Value = missing_delete.json().await.expect("delete json");
    assert_error_contract(&missing_delete_json, "not_found");

    stop_server(shutdown_tx, handle).await;
}

#[tokio::test]
async fn contract_token_revoke_edge_errors() {
    let root = TestDir::new("token-revoke-edge-errors");
    let cfg = test_config(root.path());
    bootstrap::ensure_layout(&cfg).expect("ensure layout");

    let (base_url, shutdown_tx, handle) = start_server(&cfg).await;
    let client = reqwest::Client::new();

    let token_resp = client
        .post(format!("{base_url}/api/v1/tokens"))
        .json(&json!({
            "name": "token-admin",
            "scopes": ["tokens.manage"]
        }))
        .send()
        .await
        .expect("token create");
    assert_eq!(token_resp.status(), reqwest::StatusCode::OK);
    let token_json: Value = token_resp.json().await.expect("token json");
    let token = token_json["token"].as_str().expect("token").to_owned();

    let invalid_uuid = client
        .post(format!("{base_url}/api/v1/tokens/not-a-uuid/revoke"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("invalid uuid revoke");
    assert_eq!(invalid_uuid.status(), reqwest::StatusCode::BAD_REQUEST);
    let invalid_uuid_json: Value = invalid_uuid.json().await.expect("invalid uuid json");
    assert_error_contract(&invalid_uuid_json, "validation_error");

    let missing_revoke = client
        .post(format!("{base_url}/api/v1/tokens/{}/revoke", Uuid::new_v4()))
        .bearer_auth(&token)
        .send()
        .await
        .expect("missing revoke");
    assert_eq!(missing_revoke.status(), reqwest::StatusCode::NOT_FOUND);
    let missing_revoke_json: Value = missing_revoke.json().await.expect("missing revoke json");
    assert_error_contract(&missing_revoke_json, "not_found");

    stop_server(shutdown_tx, handle).await;
}
