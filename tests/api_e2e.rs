use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use mia_secret::api;
use mia_secret::bootstrap;
use mia_secret::config::Config;
use serde_json::json;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use uuid::Uuid;

struct TestDir {
    path: PathBuf,
}

impl TestDir {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("mia-secret-api-{name}-{}", Uuid::new_v4()));
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
    spawn_app(app).await
}

async fn spawn_app(app: Router) -> (String, oneshot::Sender<()>, JoinHandle<()>) {
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

#[tokio::test]
async fn api_health_and_authz_middleware_behaviour() {
    let root = TestDir::new("health-authz");
    let cfg = test_config(root.path());
    bootstrap::ensure_layout(&cfg).expect("ensure layout");

    let (base_url, shutdown_tx, handle) = start_server(&cfg).await;
    let client = reqwest::Client::new();

    let health = client
        .get(format!("{base_url}/api/v1/health"))
        .send()
        .await
        .expect("health request");
    assert!(health.status().is_success());
    assert!(
        health.headers().get("x-trace-id").is_some(),
        "x-trace-id header must exist"
    );

    let unauthorized = client
        .get(format!("{base_url}/api/v1/secrets"))
        .send()
        .await
        .expect("unauthorized request");
    assert_eq!(unauthorized.status(), reqwest::StatusCode::UNAUTHORIZED);
    let unauthorized_body: serde_json::Value = unauthorized.json().await.expect("json body");
    assert_eq!(unauthorized_body["error"]["code"], "unauthorized");

    let unauthorized_config = client
        .get(format!("{base_url}/api/v1/config"))
        .send()
        .await
        .expect("unauthorized config request");
    assert_eq!(
        unauthorized_config.status(),
        reqwest::StatusCode::UNAUTHORIZED
    );

    let first_token_resp = client
        .post(format!("{base_url}/api/v1/tokens"))
        .json(&json!({
            "name": "bootstrap",
            "scopes": ["secrets.read", "config.read"]
        }))
        .send()
        .await
        .expect("create first token");
    assert!(first_token_resp.status().is_success());
    let first_token: serde_json::Value = first_token_resp.json().await.expect("json token");
    let bearer = first_token["token"]
        .as_str()
        .expect("token string")
        .to_owned();

    let forbidden_write = client
        .post(format!("{base_url}/api/v1/secrets"))
        .bearer_auth(&bearer)
        .json(&json!({
            "path": "apps/prod",
            "password": "secret-1"
        }))
        .send()
        .await
        .expect("forbidden write");
    assert_eq!(forbidden_write.status(), reqwest::StatusCode::FORBIDDEN);
    let forbidden_body: serde_json::Value = forbidden_write.json().await.expect("json body");
    assert_eq!(forbidden_body["error"]["code"], "forbidden");

    let config_resp = client
        .get(format!("{base_url}/api/v1/config"))
        .bearer_auth(&bearer)
        .send()
        .await
        .expect("config request");
    assert!(config_resp.status().is_success());
    let config_json: serde_json::Value = config_resp.json().await.expect("config json");
    assert_eq!(config_json["server"]["host"], "127.0.0.1");
    assert!(config_json["server"]["port"].is_number());

    let second_token_without_auth = client
        .post(format!("{base_url}/api/v1/tokens"))
        .json(&json!({
            "name": "no-auth-second-token",
            "scopes": ["secrets.read"]
        }))
        .send()
        .await
        .expect("second token request");
    assert_eq!(
        second_token_without_auth.status(),
        reqwest::StatusCode::UNAUTHORIZED
    );

    stop_server(shutdown_tx, handle).await;
}

#[tokio::test]
async fn api_revoked_token_is_rejected() {
    let root = TestDir::new("revoked");
    let cfg = test_config(root.path());
    bootstrap::ensure_layout(&cfg).expect("ensure layout");

    let (base_url, shutdown_tx, handle) = start_server(&cfg).await;
    let client = reqwest::Client::new();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_secs() as i64;

    let admin_resp = client
        .post(format!("{base_url}/api/v1/tokens"))
        .json(&json!({
            "name": "admin",
            "scopes": ["tokens.manage", "secrets.list"],
            "expires_at": now + 3600
        }))
        .send()
        .await
        .expect("admin token create");
    assert!(admin_resp.status().is_success());
    let admin_json: serde_json::Value = admin_resp.json().await.expect("admin json");
    let admin_token = admin_json["token"]
        .as_str()
        .expect("admin token")
        .to_owned();

    let worker_resp = client
        .post(format!("{base_url}/api/v1/tokens"))
        .bearer_auth(&admin_token)
        .json(&json!({
            "name": "worker",
            "scopes": ["secrets.list"]
        }))
        .send()
        .await
        .expect("worker token create");
    assert!(worker_resp.status().is_success());
    let worker_json: serde_json::Value = worker_resp.json().await.expect("worker json");
    let worker_token = worker_json["token"]
        .as_str()
        .expect("worker token")
        .to_owned();
    let worker_id = worker_json["record"]["id"]
        .as_str()
        .expect("worker id")
        .to_owned();

    let revoke_resp = client
        .post(format!("{base_url}/api/v1/tokens/{worker_id}/revoke"))
        .bearer_auth(&admin_token)
        .send()
        .await
        .expect("revoke token");
    assert!(revoke_resp.status().is_success());

    let revoked_access = client
        .get(format!("{base_url}/api/v1/secrets"))
        .bearer_auth(&worker_token)
        .send()
        .await
        .expect("revoked token request");
    assert_eq!(revoked_access.status(), reqwest::StatusCode::UNAUTHORIZED);
    let revoked_body: serde_json::Value = revoked_access.json().await.expect("revoked body");
    assert_eq!(revoked_body["error"]["code"], "unauthorized");

    stop_server(shutdown_tx, handle).await;
}

#[tokio::test]
async fn api_expired_token_is_rejected() {
    let root = TestDir::new("expired");
    let cfg = test_config(root.path());
    bootstrap::ensure_layout(&cfg).expect("ensure layout");

    let (base_url, shutdown_tx, handle) = start_server(&cfg).await;
    let client = reqwest::Client::new();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_secs() as i64;

    let admin_resp = client
        .post(format!("{base_url}/api/v1/tokens"))
        .json(&json!({
            "name": "admin-exp",
            "scopes": ["tokens.manage", "secrets.list"],
            "expires_at": now + 3600
        }))
        .send()
        .await
        .expect("admin token create");
    assert!(admin_resp.status().is_success());
    let admin_json: serde_json::Value = admin_resp.json().await.expect("admin json");
    let admin_token = admin_json["token"]
        .as_str()
        .expect("admin token")
        .to_owned();

    let expiring_resp = client
        .post(format!("{base_url}/api/v1/tokens"))
        .bearer_auth(&admin_token)
        .json(&json!({
            "name": "expiring",
            "scopes": ["secrets.list"],
            "expires_at": now + 1
        }))
        .send()
        .await
        .expect("expiring token create");
    assert!(expiring_resp.status().is_success());
    let expiring_json: serde_json::Value = expiring_resp.json().await.expect("expiring json");
    let expiring_token = expiring_json["token"]
        .as_str()
        .expect("expiring token")
        .to_owned();

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let expired_access = client
        .get(format!("{base_url}/api/v1/secrets"))
        .bearer_auth(&expiring_token)
        .send()
        .await
        .expect("expired token request");
    assert_eq!(expired_access.status(), reqwest::StatusCode::UNAUTHORIZED);
    let expired_body: serde_json::Value = expired_access.json().await.expect("expired body");
    assert_eq!(expired_body["error"]["code"], "unauthorized");

    stop_server(shutdown_tx, handle).await;
}
