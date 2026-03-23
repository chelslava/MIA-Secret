use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use mia_secret::api;
use mia_secret::bootstrap;
use mia_secret::config::Config;
use rusqlite::Connection;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use uuid::Uuid;

struct TestDir {
    path: PathBuf,
}

impl TestDir {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("mia-secret-cli-{name}-{}", Uuid::new_v4()));
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

fn bin_path() -> &'static str {
    env!("CARGO_BIN_EXE_mia-secret")
}

fn run_cli(cwd: &Path, args: &[&str]) -> std::process::Output {
    run_cli_with_env(cwd, args, &[])
}

fn run_cli_with_env(cwd: &Path, args: &[&str], envs: &[(&str, &str)]) -> std::process::Output {
    Command::new(bin_path())
        .current_dir(cwd)
        .envs(envs.iter().copied())
        .args(args)
        .output()
        .expect("failed to run cli")
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

async fn wait_until_healthy(base_url: &str) {
    let client = reqwest::Client::new();
    for _ in 0..40 {
        if let Ok(resp) = client.get(format!("{base_url}/api/v1/health")).send().await
            && resp.status().is_success()
        {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("server did not become healthy in time: {base_url}");
}

fn write_config(path: &Path, port: u16) {
    let parent = path.parent().expect("config parent");
    let data_dir = parent.join("data");
    let db_path = data_dir.join("secrets.db");
    let rendered = format!(
        r#"[general]
data_dir = "{}"
database_path = "{}"
log_level = "info"
enable_file_logging = true

[server]
host = "127.0.0.1"
port = {port}
request_timeout_secs = 10
max_request_body_kb = 64
protected_rate_limit_rps = 30

[security]
token_header = "Authorization"
lock_timeout_secs = 300
max_failed_attempts = 5
min_master_password_length = 12

[crypto]
argon2_memory_kb = 65536
argon2_time_cost = 3
argon2_parallelism = 4
encrypt_notes = true
encrypt_custom_fields = true

[storage]
auto_migrate = true
create_backup_before_write = true
max_backups = 10
sqlite_busy_timeout_ms = 5000

[cli]
output_format = "table"
interactive = true
"#,
        data_dir.to_string_lossy().replace('\\', "/"),
        db_path.to_string_lossy().replace('\\', "/"),
    );
    fs::write(path, rendered).expect("write config");
}

fn write_importable_config(path: &Path) {
    write_config(path, 3765);
}

fn stdout_text(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr_text(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn db_path_from_config(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .expect("config parent")
        .join("data")
        .join("secrets.db")
}

fn count_secrets(db_path: &Path) -> i64 {
    let conn = Connection::open(db_path).expect("open sqlite");
    conn.query_row("SELECT COUNT(1) FROM secrets", [], |row| row.get(0))
        .expect("count secrets")
}

fn read_secret_tags(db_path: &Path, path: &str) -> String {
    let conn = Connection::open(db_path).expect("open sqlite");
    conn.query_row("SELECT tags FROM secrets WHERE path = ?1", [path], |row| {
        row.get(0)
    })
    .expect("read tags")
}

#[test]
fn cli_config_init_validate_and_show_work() {
    let root = TestDir::new("config-flow");
    let config_path = root.path().join("mia-secret.toml");
    let config_arg = config_path.to_string_lossy().into_owned();

    let init = run_cli(
        root.path(),
        &["--config", &config_arg, "config", "init", "--force"],
    );
    assert!(
        init.status.success(),
        "init failed: stderr={}",
        stderr_text(&init)
    );
    assert!(
        stdout_text(&init).contains("Config initialized"),
        "unexpected init output: {}",
        stdout_text(&init)
    );

    let validate = run_cli(
        root.path(),
        &["--config", &config_arg, "config", "validate"],
    );
    assert!(
        validate.status.success(),
        "validate failed: stderr={}",
        stderr_text(&validate)
    );
    assert!(
        stdout_text(&validate).contains("Config is valid"),
        "unexpected validate output: {}",
        stdout_text(&validate)
    );

    let show = run_cli(root.path(), &["--config", &config_arg, "config", "show"]);
    assert!(
        show.status.success(),
        "show failed: stderr={}",
        stderr_text(&show)
    );
    let show_text = stdout_text(&show);
    assert!(show_text.contains("[server]"), "show output: {show_text}");
    assert!(
        show_text.contains("host = \"127.0.0.1\""),
        "show output: {show_text}"
    );
}

#[test]
fn cli_config_init_without_force_fails_on_existing_file() {
    let root = TestDir::new("config-init-fail");
    let config_path = root.path().join("mia-secret.toml");
    let config_arg = config_path.to_string_lossy().into_owned();

    let first = run_cli(
        root.path(),
        &["--config", &config_arg, "config", "init", "--force"],
    );
    assert!(first.status.success(), "first init failed");

    let second = run_cli(root.path(), &["--config", &config_arg, "config", "init"]);
    assert!(
        !second.status.success(),
        "second init should fail, stdout={}",
        stdout_text(&second)
    );
    assert_eq!(
        second.status.code(),
        Some(2),
        "config conflict should map to exit code 2"
    );
    assert!(
        stderr_text(&second).contains("config already exists"),
        "unexpected stderr: {}",
        stderr_text(&second)
    );
}

#[test]
fn cli_serve_rejects_non_loopback_host_override() {
    let root = TestDir::new("serve-host");
    let config_path = root.path().join("mia-secret.toml");
    let config_arg = config_path.to_string_lossy().into_owned();

    let output = run_cli(
        root.path(),
        &["--config", &config_arg, "serve", "--host", "0.0.0.0"],
    );
    assert!(
        !output.status.success(),
        "serve should fail for non-loopback host"
    );
    assert_eq!(
        output.status.code(),
        Some(2),
        "validation should map to exit code 2"
    );
    let err = stderr_text(&output);
    assert!(
        err.contains("loopback"),
        "expected loopback validation error, got: {err}"
    );
}

#[test]
fn cli_init_creates_data_layout() {
    let root = TestDir::new("init-layout");
    let config_path = root.path().join("mia-secret.toml");
    let config_arg = config_path.to_string_lossy().into_owned();

    let config_init = run_cli(
        root.path(),
        &["--config", &config_arg, "config", "init", "--force"],
    );
    assert!(config_init.status.success(), "config init failed");

    let init = run_cli(root.path(), &["--config", &config_arg, "init"]);
    assert!(
        init.status.success(),
        "init failed: stderr={}",
        stderr_text(&init)
    );
    assert!(
        root.path().join("data").exists(),
        "data directory must exist"
    );
    assert!(
        root.path().join("data").join("master.key").exists(),
        "master key must exist"
    );
    assert!(
        root.path().join("data").join("secrets.db").exists(),
        "database must exist"
    );
}

#[test]
fn cli_import_csv_generic_works_and_reports_summary() {
    let root = TestDir::new("import-generic");
    let config_path = root.path().join("mia-secret.toml");
    write_importable_config(&config_path);
    let csv_path = root.path().join("import.csv");
    fs::write(
        &csv_path,
        "path,password,resource,login,url,notes,tags\napps/prod/db,secret,postgres,admin,https://example.invalid,note,\"prod,db\"\n",
    )
    .expect("write import csv");

    let config_arg = config_path.to_string_lossy().into_owned();
    let file_arg = csv_path.to_string_lossy().into_owned();

    let import = run_cli(
        root.path(),
        &[
            "--config",
            &config_arg,
            "import",
            "csv",
            "--file",
            &file_arg,
            "--source",
            "generic",
        ],
    );
    assert!(
        import.status.success(),
        "import failed: stderr={}",
        stderr_text(&import)
    );
    assert!(
        stdout_text(&import).contains("Import summary: imported=1"),
        "unexpected import output: {}",
        stdout_text(&import)
    );
}

#[test]
fn cli_import_csv_is_atomic_and_rolls_back_on_row_error() {
    let root = TestDir::new("import-atomic");
    let config_path = root.path().join("mia-secret.toml");
    write_importable_config(&config_path);
    let csv_path = root.path().join("import-atomic.csv");
    fs::write(
        &csv_path,
        "path,password,resource\napps/prod/db,secret,postgres\napps/prod/api,,service\n",
    )
    .expect("write import csv");

    let config_arg = config_path.to_string_lossy().into_owned();
    let file_arg = csv_path.to_string_lossy().into_owned();
    let import = run_cli(
        root.path(),
        &[
            "--config",
            &config_arg,
            "import",
            "csv",
            "--file",
            &file_arg,
            "--source",
            "generic",
            "--on-duplicate",
            "update",
        ],
    );
    assert!(
        !import.status.success(),
        "import must fail, stdout={}, stderr={}",
        stdout_text(&import),
        stderr_text(&import)
    );
    assert_eq!(
        import.status.code(),
        Some(2),
        "validation failure should map to exit code 2"
    );
    assert!(
        stderr_text(&import).contains("import row"),
        "stderr should contain row context: {}",
        stderr_text(&import)
    );

    let db_path = db_path_from_config(&config_path);
    assert_eq!(
        count_secrets(&db_path),
        0,
        "failed atomic import must not persist partial data"
    );
}

#[test]
fn cli_import_update_keeps_existing_tags_when_column_missing() {
    let root = TestDir::new("import-tags-keep");
    let config_path = root.path().join("mia-secret.toml");
    write_importable_config(&config_path);

    let csv_initial = root.path().join("import-initial.csv");
    fs::write(
        &csv_initial,
        "path,password,resource,tags\napps/prod/db,secret-1,postgres,\"prod,db\"\n",
    )
    .expect("write initial csv");

    let csv_update = root.path().join("import-update.csv");
    fs::write(
        &csv_update,
        "path,password,resource\napps/prod/db,secret-2,postgres-updated\n",
    )
    .expect("write update csv");

    let config_arg = config_path.to_string_lossy().into_owned();
    let initial_file_arg = csv_initial.to_string_lossy().into_owned();
    let update_file_arg = csv_update.to_string_lossy().into_owned();

    let first = run_cli(
        root.path(),
        &[
            "--config",
            &config_arg,
            "import",
            "csv",
            "--file",
            &initial_file_arg,
            "--source",
            "generic",
        ],
    );
    assert!(
        first.status.success(),
        "initial import failed: stderr={}",
        stderr_text(&first)
    );

    let second = run_cli(
        root.path(),
        &[
            "--config",
            &config_arg,
            "import",
            "csv",
            "--file",
            &update_file_arg,
            "--source",
            "generic",
            "--on-duplicate",
            "update",
        ],
    );
    assert!(
        second.status.success(),
        "update import failed: stderr={}",
        stderr_text(&second)
    );
    assert!(
        stdout_text(&second).contains("updated=1"),
        "unexpected update output: {}",
        stdout_text(&second)
    );

    let db_path = db_path_from_config(&config_path);
    assert_eq!(
        read_secret_tags(&db_path, "apps/prod/db"),
        "[\"prod\",\"db\"]",
        "tags must remain unchanged when tags column is absent in CSV update"
    );
}

#[test]
fn cli_list_without_server_returns_operational_exit_code() {
    let root = TestDir::new("list-no-server");
    let config_path = root.path().join("mia-secret.toml");
    write_config(&config_path, 37771);
    let config_arg = config_path.to_string_lossy().into_owned();

    let list = run_cli(root.path(), &["--config", &config_arg, "list"]);
    assert!(!list.status.success(), "list should fail without server");
    assert_eq!(
        list.status.code(),
        Some(6),
        "http connectivity errors should map to exit code 6"
    );
    assert!(
        stderr_text(&list).contains("HTTP client error"),
        "unexpected stderr: {}",
        stderr_text(&list)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_list_without_token_returns_auth_exit_code() {
    let root = TestDir::new("list-unauthorized");
    let config_path = root.path().join("mia-secret.toml");

    let mut cfg = Config::default();
    let data_dir = root.path().join("data");
    let db_path = data_dir.join("secrets.db");
    cfg.general.data_dir = data_dir.to_string_lossy().into_owned();
    cfg.general.database_path = db_path.to_string_lossy().into_owned();
    cfg.server.host = "127.0.0.1".to_owned();
    bootstrap::ensure_layout(&cfg).expect("ensure layout");

    let (base_url, shutdown_tx, handle) = start_server(&cfg).await;
    wait_until_healthy(&base_url).await;
    let port = base_url
        .rsplit(':')
        .next()
        .expect("port string")
        .parse::<u16>()
        .expect("port parse");
    write_config(&config_path, port);
    let config_arg = config_path.to_string_lossy().into_owned();

    let list = run_cli(root.path(), &["--config", &config_arg, "list"]);
    assert!(!list.status.success(), "list should fail without token");
    assert_eq!(
        list.status.code(),
        Some(3),
        "auth failures should map to exit code 3, stderr={}",
        stderr_text(&list)
    );
    assert!(
        stderr_text(&list).contains("authentication error"),
        "unexpected stderr: {}",
        stderr_text(&list)
    );

    stop_server(shutdown_tx, handle).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_get_missing_secret_returns_not_found_exit_code() {
    let root = TestDir::new("cli-get-missing");
    let config_path = root.path().join("mia-secret.toml");

    let mut cfg = Config::default();
    let data_dir = root.path().join("data");
    let db_path = data_dir.join("secrets.db");
    cfg.general.data_dir = data_dir.to_string_lossy().into_owned();
    cfg.general.database_path = db_path.to_string_lossy().into_owned();
    cfg.server.host = "127.0.0.1".to_owned();
    bootstrap::ensure_layout(&cfg).expect("ensure layout");

    let (base_url, shutdown_tx, handle) = start_server(&cfg).await;
    wait_until_healthy(&base_url).await;
    let port = base_url
        .rsplit(':')
        .next()
        .expect("port string")
        .parse::<u16>()
        .expect("port parse");
    write_config(&config_path, port);

    let client = reqwest::Client::new();
    let token_resp = client
        .post(format!("{base_url}/api/v1/tokens"))
        .json(&serde_json::json!({
            "name": "reader",
            "scopes": ["secrets.read"]
        }))
        .send()
        .await
        .expect("token create");
    assert!(token_resp.status().is_success());
    let token_json: serde_json::Value = token_resp.json().await.expect("token json");
    let token = token_json["token"].as_str().expect("token").to_owned();

    let config_arg = config_path.to_string_lossy().into_owned();
    let get = run_cli_with_env(
        root.path(),
        &["--config", &config_arg, "get", "missing/secret/path"],
        &[("MIA_SECRET_TOKEN", token.as_str())],
    );
    assert!(!get.status.success(), "get should fail for missing path");
    assert_eq!(
        get.status.code(),
        Some(4),
        "not found should map to exit code 4, stderr={}",
        stderr_text(&get)
    );
    assert!(
        stderr_text(&get).contains("not found"),
        "unexpected stderr: {}",
        stderr_text(&get)
    );

    stop_server(shutdown_tx, handle).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_token_revoke_invalid_uuid_returns_validation_exit_code() {
    let root = TestDir::new("cli-token-revoke-invalid");
    let config_path = root.path().join("mia-secret.toml");

    let mut cfg = Config::default();
    let data_dir = root.path().join("data");
    let db_path = data_dir.join("secrets.db");
    cfg.general.data_dir = data_dir.to_string_lossy().into_owned();
    cfg.general.database_path = db_path.to_string_lossy().into_owned();
    cfg.server.host = "127.0.0.1".to_owned();
    bootstrap::ensure_layout(&cfg).expect("ensure layout");

    let (base_url, shutdown_tx, handle) = start_server(&cfg).await;
    wait_until_healthy(&base_url).await;
    let port = base_url
        .rsplit(':')
        .next()
        .expect("port string")
        .parse::<u16>()
        .expect("port parse");
    write_config(&config_path, port);

    let client = reqwest::Client::new();
    let token_resp = client
        .post(format!("{base_url}/api/v1/tokens"))
        .json(&serde_json::json!({
            "name": "admin",
            "scopes": ["tokens.manage"]
        }))
        .send()
        .await
        .expect("token create");
    assert!(token_resp.status().is_success());
    let token_json: serde_json::Value = token_resp.json().await.expect("token json");
    let token = token_json["token"].as_str().expect("token").to_owned();

    let config_arg = config_path.to_string_lossy().into_owned();
    let revoke = run_cli_with_env(
        root.path(),
        &["--config", &config_arg, "token", "revoke", "not-a-uuid"],
        &[("MIA_SECRET_TOKEN", token.as_str())],
    );
    assert!(
        !revoke.status.success(),
        "revoke should fail for invalid uuid"
    );
    assert_eq!(
        revoke.status.code(),
        Some(2),
        "validation should map to exit code 2, stderr={}",
        stderr_text(&revoke)
    );
    assert!(
        stderr_text(&revoke).contains("invalid uuid"),
        "unexpected stderr: {}",
        stderr_text(&revoke)
    );

    stop_server(shutdown_tx, handle).await;
}
