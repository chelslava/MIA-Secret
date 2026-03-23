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

    let ready = client
        .get(format!("{base_url}/api/v1/ready"))
        .send()
        .await
        .expect("ready request");
    assert!(ready.status().is_success());
    let ready_body: serde_json::Value = ready.json().await.expect("ready body");
    assert_eq!(ready_body["status"], "ready");
    assert_eq!(ready_body["checks"]["database_connection"], true);
    assert_eq!(ready_body["checks"]["schema_migrations_present"], true);

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

#[tokio::test]
async fn api_secret_crud_and_token_routes_work_end_to_end() {
    let root = TestDir::new("crud-and-token-routes");
    let cfg = test_config(root.path());
    bootstrap::ensure_layout(&cfg).expect("ensure layout");

    let (base_url, shutdown_tx, handle) = start_server(&cfg).await;
    let client = reqwest::Client::new();

    let bootstrap_token_resp = client
        .post(format!("{base_url}/api/v1/tokens"))
        .json(&json!({
            "name": "crud-admin",
            "scopes": [
                "tokens.manage",
                "secrets.write",
                "secrets.read",
                "secrets.list",
                "secrets.delete"
            ]
        }))
        .send()
        .await
        .expect("bootstrap token create");
    assert!(bootstrap_token_resp.status().is_success());
    let bootstrap_token_json: serde_json::Value = bootstrap_token_resp
        .json()
        .await
        .expect("bootstrap token json");
    let token = bootstrap_token_json["token"]
        .as_str()
        .expect("bootstrap token")
        .to_owned();
    let token_id = bootstrap_token_json["record"]["id"]
        .as_str()
        .expect("bootstrap token id")
        .to_owned();

    let created_resp = client
        .post(format!("{base_url}/api/v1/secrets"))
        .bearer_auth(&token)
        .json(&json!({
            "path": "apps/prod",
            "resource": "api",
            "login": "svc-user",
            "password": "secret-pass",
            "url": "https://example.invalid",
            "notes": "secret note",
            "tags": ["prod", "api"]
        }))
        .send()
        .await
        .expect("create secret");
    assert!(created_resp.status().is_success());
    let created_json: serde_json::Value = created_resp.json().await.expect("created json");
    let secret_id = created_json["id"].as_str().expect("secret id").to_owned();

    let list_resp = client
        .get(format!("{base_url}/api/v1/secrets"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list secrets");
    assert!(list_resp.status().is_success());
    let list_json: serde_json::Value = list_resp.json().await.expect("list json");
    assert!(list_json.is_array());
    assert_eq!(list_json.as_array().expect("array").len(), 1);

    let get_by_id_resp = client
        .get(format!("{base_url}/api/v1/secrets/{secret_id}"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("get secret by id");
    assert!(get_by_id_resp.status().is_success());
    let get_by_id_json: serde_json::Value = get_by_id_resp.json().await.expect("get by id json");
    assert_eq!(get_by_id_json["path"], "apps/prod");

    let get_by_path_resp = client
        .get(format!("{base_url}/api/v1/secrets/by-path/apps%2Fprod"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("get by path");
    assert!(get_by_path_resp.status().is_success());
    let get_by_path_json: serde_json::Value = get_by_path_resp.json().await.expect("by path json");
    assert_eq!(get_by_path_json["id"], secret_id);

    let update_resp = client
        .patch(format!("{base_url}/api/v1/secrets/{secret_id}"))
        .bearer_auth(&token)
        .json(&json!({
            "path": "apps/prod-v2",
            "password": "secret-pass-v2",
            "notes": "updated note",
            "tags": ["prod", "api-v2"]
        }))
        .send()
        .await
        .expect("update secret");
    assert!(update_resp.status().is_success());
    let update_json: serde_json::Value = update_resp.json().await.expect("update json");
    assert_eq!(update_json["path"], "apps/prod-v2");

    let invalid_uuid_resp = client
        .get(format!("{base_url}/api/v1/secrets/not-a-uuid"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("invalid uuid request");
    assert_eq!(invalid_uuid_resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let invalid_uuid_json: serde_json::Value =
        invalid_uuid_resp.json().await.expect("invalid uuid json");
    assert_eq!(invalid_uuid_json["error"]["code"], "validation_error");

    let list_tokens_resp = client
        .get(format!("{base_url}/api/v1/tokens"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("list tokens");
    assert!(list_tokens_resp.status().is_success());
    let list_tokens_json: serde_json::Value =
        list_tokens_resp.json().await.expect("list tokens json");
    assert!(list_tokens_json.is_array());
    assert_eq!(list_tokens_json.as_array().expect("array").len(), 1);

    let delete_resp = client
        .delete(format!("{base_url}/api/v1/secrets/{secret_id}"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("delete secret");
    assert_eq!(delete_resp.status(), reqwest::StatusCode::NO_CONTENT);

    let not_found_resp = client
        .get(format!("{base_url}/api/v1/secrets/{secret_id}"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("get deleted secret");
    assert_eq!(not_found_resp.status(), reqwest::StatusCode::NOT_FOUND);

    let revoke_self_resp = client
        .post(format!("{base_url}/api/v1/tokens/{token_id}/revoke"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("revoke self");
    assert!(revoke_self_resp.status().is_success());

    let unauthorized_after_revoke = client
        .get(format!("{base_url}/api/v1/tokens"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("request after revoke");
    assert_eq!(
        unauthorized_after_revoke.status(),
        reqwest::StatusCode::UNAUTHORIZED
    );

    stop_server(shutdown_tx, handle).await;
}

#[tokio::test]
async fn api_rejects_payload_larger_than_configured_limit() {
    let root = TestDir::new("payload-limit");
    let mut cfg = test_config(root.path());
    cfg.server.max_request_body_kb = 1;
    bootstrap::ensure_layout(&cfg).expect("ensure layout");

    let (base_url, shutdown_tx, handle) = start_server(&cfg).await;
    let client = reqwest::Client::new();

    let token_resp = client
        .post(format!("{base_url}/api/v1/tokens"))
        .json(&json!({
            "name": "limit-admin",
            "scopes": ["secrets.write"]
        }))
        .send()
        .await
        .expect("create token");
    assert!(token_resp.status().is_success());
    let token_json: serde_json::Value = token_resp.json().await.expect("token json");
    let token = token_json["token"].as_str().expect("token").to_owned();

    let oversized_notes = "x".repeat(8 * 1024);
    let oversized_resp = client
        .post(format!("{base_url}/api/v1/secrets"))
        .bearer_auth(&token)
        .json(&json!({
            "path": "oversized/payload",
            "password": "small-password",
            "notes": oversized_notes
        }))
        .send()
        .await
        .expect("oversized request");

    assert_eq!(
        oversized_resp.status(),
        reqwest::StatusCode::PAYLOAD_TOO_LARGE
    );

    stop_server(shutdown_tx, handle).await;
}
