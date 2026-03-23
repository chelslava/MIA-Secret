use std::fs;
use std::path::{Path, PathBuf};

use mia_secret::api;
use mia_secret::bootstrap;
use mia_secret::config::Config;
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
        let path = std::env::temp_dir().join(format!("mia-secret-contract-{name}-{}", Uuid::new_v4()));
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
        health_json.get("database_ready").and_then(Value::as_bool).is_some(),
        "database_ready must be bool"
    );
    assert!(
        health_json.get("config_loaded").and_then(Value::as_bool).is_some(),
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
        checks.get("config_loaded").and_then(Value::as_bool).is_some(),
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
    let error = unauthorized_json.get("error").expect("error envelope");
    assert_has_string(error, "code");
    assert_has_string(error, "message");
    assert_has_string(error, "traceId");

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
