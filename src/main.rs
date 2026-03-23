mod api;
mod bootstrap;
mod cli;
mod config;
mod crypto;
mod domain;
mod error;
mod security;
mod service;
mod storage;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use cli::{
    Cli, Commands, ConfigCommands, DuplicateStrategy, ImportCommands, ImportSource, TokenCommands,
};
use error::AppError;
use security::redact_json;
use serde::{Deserialize, Serialize};
use service::{
    AppService, ImportDuplicateStrategy, ImportOutcome, ImportSecretRequest as ServiceImportSecret,
};
use storage::SqliteStorage;

#[tokio::main]
async fn main() {
    init_tracing();

    let cli = Cli::parse();
    if let Err(err) = dispatch(cli).await {
        eprintln!("{err}");
        std::process::exit(exit_code_for_error(&err));
    }
}

fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

async fn dispatch(cli: Cli) -> Result<(), AppError> {
    match cli.command {
        Commands::Serve { host, port } => {
            let path = config::resolve_config_path(cli.config.clone());
            config::write_default_if_missing(&path)?;
            let cfg = config::load(&path, config::ConfigOverrides { host, port })?;
            bootstrap::ensure_layout(&cfg)?;
            api::serve(cfg).await
        }
        Commands::Health { port } => {
            let path = config::resolve_config_path(cli.config);
            let cfg = config::load(&path, config::ConfigOverrides { host: None, port })?;
            api::check_health(&cfg).await
        }
        Commands::Init => {
            let path = config::resolve_config_path(cli.config);
            config::write_default_if_missing(&path)?;
            let cfg = config::load(&path, config::ConfigOverrides::default())?;
            bootstrap::ensure_layout(&cfg)?;
            let _storage = SqliteStorage::from_config(&cfg)?;
            println!("Initialized data directory at {}", cfg.general.data_dir);
            Ok(())
        }
        Commands::Config { command } => handle_config_command(cli.config, command),
        Commands::Add {
            path,
            resource,
            login,
            password,
            url,
            notes,
            tags,
        } => {
            let cfg = load_command_config(cli.config, None)?;
            call_local_api(
                &cfg,
                reqwest::Method::POST,
                "/api/v1/secrets",
                Some(serde_json::json!({
                    "path": path,
                    "resource": resource,
                    "login": login,
                    "password": password,
                    "url": url,
                    "notes": notes,
                    "tags": tags,
                    "custom_fields": serde_json::Value::Null
                })),
            )
            .await
        }
        Commands::Get { path } => {
            let cfg = load_command_config(cli.config, None)?;
            let encoded = urlencoding::encode(&path);
            call_local_api::<serde_json::Value>(
                &cfg,
                reqwest::Method::GET,
                &format!("/api/v1/secrets/by-path/{encoded}"),
                None,
            )
            .await
        }
        Commands::List => {
            let cfg = load_command_config(cli.config, None)?;
            call_local_api::<serde_json::Value>(&cfg, reqwest::Method::GET, "/api/v1/secrets", None)
                .await
        }
        Commands::Update {
            path,
            new_path,
            resource,
            login,
            password,
            url,
            notes,
            tags,
        } => {
            let cfg = load_command_config(cli.config, None)?;
            let encoded = urlencoding::encode(&path);
            let current = request_json(
                &cfg,
                reqwest::Method::GET,
                &format!("/api/v1/secrets/by-path/{encoded}"),
                None::<serde_json::Value>,
            )
            .await?;
            let id = current
                .get("id")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| AppError::Server("unable to get secret id".to_owned()))?;
            call_local_api(
                &cfg,
                reqwest::Method::PATCH,
                &format!("/api/v1/secrets/{id}"),
                Some(serde_json::json!({
                    "path": new_path,
                    "resource": resource,
                    "login": login,
                    "password": password,
                    "url": url,
                    "notes": notes,
                    "tags": tags,
                    "custom_fields": serde_json::Value::Null
                })),
            )
            .await
        }
        Commands::Delete { path } => {
            let cfg = load_command_config(cli.config, None)?;
            let encoded = urlencoding::encode(&path);
            let current = request_json(
                &cfg,
                reqwest::Method::GET,
                &format!("/api/v1/secrets/by-path/{encoded}"),
                None::<serde_json::Value>,
            )
            .await?;
            let id = current
                .get("id")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| AppError::Server("unable to get secret id".to_owned()))?;
            call_local_api::<serde_json::Value>(
                &cfg,
                reqwest::Method::DELETE,
                &format!("/api/v1/secrets/{id}"),
                None,
            )
            .await
        }
        Commands::Token { command } => {
            let cfg = load_command_config(cli.config, None)?;
            handle_token_command(&cfg, command).await
        }
        Commands::Import { command } => handle_import_command(cli.config, command),
    }
}

fn handle_config_command(path: Option<PathBuf>, command: ConfigCommands) -> Result<(), AppError> {
    let path = config::resolve_config_path(path);

    match command {
        ConfigCommands::Init { force } => {
            config::write_default(&path, force)?;
            println!("Config initialized at {}", path.display());
            Ok(())
        }
        ConfigCommands::Show => {
            let cfg = config::load(&path, config::ConfigOverrides::default())?;
            let rendered = toml::to_string_pretty(&cfg)
                .map_err(|err| AppError::Config(format!("failed to serialize config: {err}")))?;
            println!("{rendered}");
            Ok(())
        }
        ConfigCommands::Validate => {
            config::load(&path, config::ConfigOverrides::default())?;
            println!("Config is valid: {}", path.display());
            Ok(())
        }
    }
}

fn load_command_config(
    path: Option<PathBuf>,
    port: Option<u16>,
) -> Result<config::Config, AppError> {
    let path = config::resolve_config_path(path);
    config::load(&path, config::ConfigOverrides { host: None, port })
}

async fn handle_token_command(
    cfg: &config::Config,
    command: TokenCommands,
) -> Result<(), AppError> {
    match command {
        TokenCommands::Create {
            name,
            scopes,
            expires_at,
        } => {
            call_local_api(
                cfg,
                reqwest::Method::POST,
                "/api/v1/tokens",
                Some(serde_json::json!({
                    "name": name,
                    "scopes": scopes,
                    "expires_at": expires_at
                })),
            )
            .await
        }
        TokenCommands::List => {
            call_local_api::<serde_json::Value>(cfg, reqwest::Method::GET, "/api/v1/tokens", None)
                .await
        }
        TokenCommands::Revoke { id } => {
            call_local_api::<serde_json::Value>(
                cfg,
                reqwest::Method::POST,
                &format!("/api/v1/tokens/{id}/revoke"),
                None,
            )
            .await
        }
    }
}

#[derive(Debug, Clone)]
struct ImportSecretRow {
    path: String,
    resource: Option<String>,
    login: Option<String>,
    password: String,
    url: Option<String>,
    notes: Option<String>,
    tags: Option<Vec<String>>,
}

#[derive(Debug, Default)]
struct ImportSummary {
    imported: usize,
    updated: usize,
    skipped: usize,
    failed: usize,
}

const MAX_IMPORT_FILE_SIZE_BYTES: u64 = 10 * 1024 * 1024;
const MAX_IMPORT_ROWS: usize = 50_000;
const MAX_IMPORT_FIELD_LENGTH: usize = 8_192;

fn handle_import_command(path: Option<PathBuf>, command: ImportCommands) -> Result<(), AppError> {
    match command {
        ImportCommands::Csv {
            file,
            source,
            on_duplicate,
        } => import_csv(path, &file, source, on_duplicate),
    }
}

fn import_csv(
    config_path: Option<PathBuf>,
    file: &std::path::Path,
    source: ImportSource,
    on_duplicate: DuplicateStrategy,
) -> Result<(), AppError> {
    let cfg = load_command_config(config_path, None)?;
    bootstrap::ensure_layout(&cfg)?;
    let service = build_local_service(&cfg)?;
    let strategy = map_duplicate_strategy(on_duplicate);
    let source_for_parse = source;
    let summary = service.run_import_tx(|tx| {
        let mut summary = ImportSummary::default();
        let valid_rows = stream_import_csv(file, source_for_parse, |line, row| {
            let outcome = service
                .import_secret_tx(tx, to_service_import_row(row), strategy)
                .map_err(|err| AppError::Validation(format!("import row {line} failed: {err}")))?;
            match outcome {
                ImportOutcome::Imported => summary.imported += 1,
                ImportOutcome::Updated => summary.updated += 1,
                ImportOutcome::Skipped => summary.skipped += 1,
            }
            Ok(())
        })?;
        if valid_rows == 0 {
            return Err(AppError::Validation(format!(
                "import file {} does not contain any valid rows",
                file.display()
            )));
        }
        Ok(summary)
    })?;

    println!(
        "Import summary: imported={} updated={} skipped={} failed={}",
        summary.imported, summary.updated, summary.skipped, summary.failed
    );
    Ok(())
}

fn build_local_service(cfg: &config::Config) -> Result<AppService, AppError> {
    let storage = Arc::new(SqliteStorage::from_config(cfg)?);
    let crypto = crypto::CryptoService::from_config(cfg)?;
    Ok(AppService::new(storage, crypto))
}

#[cfg(test)]
fn parse_import_csv(
    file: &std::path::Path,
    source: ImportSource,
) -> Result<Vec<ImportSecretRow>, AppError> {
    let mut rows = Vec::new();
    stream_import_csv(file, source, |_line, row| {
        rows.push(row);
        Ok(())
    })?;
    Ok(rows)
}

fn stream_import_csv(
    file: &std::path::Path,
    source: ImportSource,
    mut on_row: impl FnMut(usize, ImportSecretRow) -> Result<(), AppError>,
) -> Result<usize, AppError> {
    validate_import_file(file)?;

    let mut reader = csv::ReaderBuilder::new()
        .trim(csv::Trim::All)
        .from_path(file)
        .map_err(|err| {
            AppError::Validation(format!("unable to read CSV {}: {err}", file.display()))
        })?;
    let headers = reader
        .headers()
        .map_err(|err| AppError::Validation(format!("unable to parse CSV headers: {err}")))?
        .iter()
        .map(|h| h.trim().to_ascii_lowercase())
        .collect::<Vec<_>>();

    let mut valid_rows = 0usize;
    for (record_index, record) in reader.records().enumerate() {
        if record_index >= MAX_IMPORT_ROWS {
            return Err(AppError::Validation(format!(
                "CSV import exceeds maximum rows limit ({MAX_IMPORT_ROWS})"
            )));
        }

        let record = record
            .map_err(|err| AppError::Validation(format!("unable to read CSV record: {err}")))?;
        let mut row = HashMap::<String, String>::new();
        for (index, value) in record.iter().enumerate() {
            if let Some(header) = headers.get(index) {
                let trimmed = value.trim();
                if trimmed.chars().count() > MAX_IMPORT_FIELD_LENGTH {
                    return Err(AppError::Validation(format!(
                        "CSV field '{}' exceeds maximum length ({MAX_IMPORT_FIELD_LENGTH} characters)",
                        header
                    )));
                }
                row.insert(header.clone(), trimmed.to_owned());
            }
        }
        let line = record_index + 2;
        if let Some(parsed) = parse_import_row(&row, source.clone())
            .map_err(|err| AppError::Validation(format!("import row {line} parse failed: {err}")))?
        {
            on_row(line, parsed)?;
            valid_rows += 1;
        }
    }
    Ok(valid_rows)
}

fn parse_import_row(
    row: &HashMap<String, String>,
    source: ImportSource,
) -> Result<Option<ImportSecretRow>, AppError> {
    match source {
        ImportSource::Generic => parse_generic_row(row),
        ImportSource::Bitwarden => parse_bitwarden_row(row),
    }
}

fn parse_generic_row(row: &HashMap<String, String>) -> Result<Option<ImportSecretRow>, AppError> {
    let path = get_csv_value(row, "path");
    let password = get_csv_value(row, "password");
    if path.is_empty() && password.is_empty() {
        return Ok(None);
    }
    if path.is_empty() || password.is_empty() {
        return Err(AppError::Validation(
            "generic CSV row requires non-empty path and password".to_owned(),
        ));
    }
    validate_import_path(path)?;
    let tags = row.get("tags").map(|raw| {
        raw.split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>()
    });
    Ok(Some(ImportSecretRow {
        path: path.to_owned(),
        resource: optional_csv_value(row, "resource"),
        login: optional_csv_value(row, "login"),
        password: password.to_owned(),
        url: optional_csv_value(row, "url"),
        notes: optional_csv_value(row, "notes"),
        tags,
    }))
}

fn parse_bitwarden_row(row: &HashMap<String, String>) -> Result<Option<ImportSecretRow>, AppError> {
    let name = get_csv_value(row, "name");
    let password = get_csv_value(row, "login_password");
    if name.is_empty() && password.is_empty() {
        return Ok(None);
    }
    if name.is_empty() || password.is_empty() {
        return Err(AppError::Validation(
            "bitwarden CSV row requires non-empty name and login_password".to_owned(),
        ));
    }

    let folder = get_csv_value(row, "folder");
    let path = if folder.is_empty() {
        name.to_owned()
    } else {
        format!("{folder}/{name}")
    };
    validate_import_path(&path)?;

    let mut notes = optional_csv_value(row, "notes");
    if let Some(totp) = optional_csv_value(row, "login_totp") {
        notes = Some(match notes {
            Some(value) if !value.is_empty() => format!("{value}\nTOTP: {totp}"),
            _ => format!("TOTP: {totp}"),
        });
    }

    let tags = if folder.is_empty() {
        Vec::new()
    } else {
        vec![folder.to_owned()]
    };

    Ok(Some(ImportSecretRow {
        path,
        resource: optional_csv_value(row, "type"),
        login: optional_csv_value(row, "login_username"),
        password: password.to_owned(),
        url: optional_csv_value(row, "login_uri"),
        notes,
        tags: Some(tags),
    }))
}

fn map_duplicate_strategy(value: DuplicateStrategy) -> ImportDuplicateStrategy {
    match value {
        DuplicateStrategy::Skip => ImportDuplicateStrategy::Skip,
        DuplicateStrategy::Update => ImportDuplicateStrategy::Update,
    }
}

fn to_service_import_row(row: ImportSecretRow) -> ServiceImportSecret {
    ServiceImportSecret {
        path: row.path,
        resource: row.resource,
        login: row.login,
        password: row.password,
        url: row.url,
        notes: row.notes,
        tags: row.tags,
    }
}

fn get_csv_value<'a>(row: &'a HashMap<String, String>, key: &str) -> &'a str {
    row.get(key).map(String::as_str).unwrap_or("")
}

fn optional_csv_value(row: &HashMap<String, String>, key: &str) -> Option<String> {
    let value = get_csv_value(row, key).trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_owned())
    }
}

fn validate_import_file(file: &std::path::Path) -> Result<(), AppError> {
    let metadata = std::fs::metadata(file).map_err(|err| {
        AppError::Validation(format!("unable to access CSV {}: {err}", file.display()))
    })?;
    if !metadata.is_file() {
        return Err(AppError::Validation(format!(
            "CSV import path is not a file: {}",
            file.display()
        )));
    }
    if metadata.len() > MAX_IMPORT_FILE_SIZE_BYTES {
        return Err(AppError::Validation(format!(
            "CSV import file exceeds maximum size ({} bytes)",
            MAX_IMPORT_FILE_SIZE_BYTES
        )));
    }
    Ok(())
}

fn validate_import_path(path: &str) -> Result<(), AppError> {
    if path.chars().any(char::is_control) {
        return Err(AppError::Validation(
            "path contains forbidden control characters".to_owned(),
        ));
    }
    Ok(())
}

async fn call_local_api<T: Serialize>(
    cfg: &config::Config,
    method: reqwest::Method,
    path: &str,
    payload: Option<T>,
) -> Result<(), AppError> {
    let value = request_json(cfg, method, path, payload).await?;
    println!(
        "{}",
        serde_json::to_string_pretty(&value).map_err(|e| AppError::Serialization(e.to_string()))?
    );
    Ok(())
}

async fn request_json<T: Serialize>(
    cfg: &config::Config,
    method: reqwest::Method,
    path: &str,
    payload: Option<T>,
) -> Result<serde_json::Value, AppError> {
    let host = if cfg.server.host.eq_ignore_ascii_case("localhost") {
        "127.0.0.1".to_owned()
    } else {
        cfg.server.host.clone()
    };
    let base_url = if host.contains(':') {
        format!("http://[{host}]:{}", cfg.server.port)
    } else {
        format!("http://{host}:{}", cfg.server.port)
    };

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(
            cfg.server.request_timeout_secs,
        ))
        .build()?;

    let mut request = client.request(method, format!("{base_url}{path}"));
    if let Some(token) = std::env::var_os("MIA_SECRET_TOKEN") {
        request = request.bearer_auth(token.to_string_lossy().to_string());
    }
    if let Some(payload) = payload {
        request = request.json(&payload);
    }
    let response = request.send().await?;
    let status = response.status();
    if status == reqwest::StatusCode::NO_CONTENT {
        return Ok(serde_json::json!({ "status": "ok" }));
    }
    let text = response.text().await?;
    let parsed: serde_json::Value =
        serde_json::from_str(&text).unwrap_or_else(|_| serde_json::json!({ "raw": text }));
    if !status.is_success() {
        return Err(map_api_error(status, &parsed));
    }
    Ok(parsed)
}

#[derive(Debug, Deserialize)]
struct ApiErrorEnvelope {
    error: ApiErrorBody,
}

#[derive(Debug, Deserialize)]
struct ApiErrorBody {
    code: String,
    message: String,
}

fn map_api_error(status: reqwest::StatusCode, parsed: &serde_json::Value) -> AppError {
    if let Ok(envelope) = serde_json::from_value::<ApiErrorEnvelope>(parsed.clone()) {
        return match envelope.error.code.as_str() {
            "validation_error" => AppError::Validation(envelope.error.message),
            "not_found" => AppError::NotFound(envelope.error.message),
            "conflict" => AppError::Conflict(envelope.error.message),
            "unauthorized" => AppError::Unauthorized(envelope.error.message),
            "forbidden" => AppError::Forbidden(envelope.error.message),
            "crypto_error" => AppError::Crypto(envelope.error.message),
            "config_error" => AppError::Config(envelope.error.message),
            "storage_error" => AppError::Storage(envelope.error.message),
            _ => AppError::Server(envelope.error.message),
        };
    }

    let safe = redact_json(parsed);
    AppError::Server(format!("api error {status}: {safe}"))
}

fn exit_code_for_error(err: &AppError) -> i32 {
    match err {
        AppError::Validation(_) | AppError::Config(_) | AppError::Address(_) => 2,
        AppError::Unauthorized(_) | AppError::Forbidden(_) => 3,
        AppError::NotFound(_) => 4,
        AppError::Conflict(_) => 5,
        AppError::Http(_)
        | AppError::Io(_)
        | AppError::Storage(_)
        | AppError::Crypto(_)
        | AppError::Serialization(_)
        | AppError::Server(_) => 6,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ConfigCommands, MAX_IMPORT_FIELD_LENGTH, MAX_IMPORT_FILE_SIZE_BYTES, MAX_IMPORT_ROWS,
        exit_code_for_error, load_command_config, map_api_error, parse_bitwarden_row,
        parse_generic_row, parse_import_csv, request_json, validate_import_file,
    };
    use crate::config::Config;
    use crate::error::AppError;
    use axum::http::StatusCode;
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use serde_json::json;
    use std::collections::HashMap;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    fn temp_dir(name: &str) -> PathBuf {
        let unique = format!(
            "mia-secret-main-test-{name}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(unique);
        fs::create_dir_all(&path).expect("create temp dir");
        path
    }

    async fn spawn_test_server() -> (u16, oneshot::Sender<()>) {
        async fn ok() -> Json<serde_json::Value> {
            Json(json!({ "ok": true }))
        }
        async fn no_content() -> StatusCode {
            StatusCode::NO_CONTENT
        }
        async fn structured_error() -> (StatusCode, Json<serde_json::Value>) {
            (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "error": {
                        "code": "forbidden",
                        "message": "denied by policy"
                    }
                })),
            )
        }
        async fn raw_error() -> (StatusCode, Json<serde_json::Value>) {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "password": "super-secret",
                    "note": "visible"
                })),
            )
        }
        async fn echo_payload(Json(payload): Json<serde_json::Value>) -> Json<serde_json::Value> {
            Json(payload)
        }

        let app = Router::new()
            .route("/ok", get(ok))
            .route("/no-content", get(no_content))
            .route("/err-structured", get(structured_error))
            .route("/err-raw", get(raw_error))
            .route("/echo", post(echo_payload));

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let port = listener.local_addr().expect("local addr").port();
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

        tokio::spawn(async move {
            let _ = axum::serve(listener, app.into_make_service())
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await;
        });

        (port, shutdown_tx)
    }

    #[test]
    fn maps_structured_api_error_to_typed_app_error() {
        let input = json!({
            "error": {
                "code": "forbidden",
                "message": "missing required scope: secrets.write",
                "traceId": "abc"
            }
        });
        let err = map_api_error(reqwest::StatusCode::FORBIDDEN, &input);
        assert!(matches!(err, AppError::Forbidden(_)));
    }

    #[test]
    fn maps_all_known_structured_error_codes() {
        let cases = [
            (
                "validation_error",
                reqwest::StatusCode::BAD_REQUEST,
                "Validation",
            ),
            ("not_found", reqwest::StatusCode::NOT_FOUND, "NotFound"),
            ("conflict", reqwest::StatusCode::CONFLICT, "Conflict"),
            (
                "unauthorized",
                reqwest::StatusCode::UNAUTHORIZED,
                "Unauthorized",
            ),
            ("forbidden", reqwest::StatusCode::FORBIDDEN, "Forbidden"),
            (
                "crypto_error",
                reqwest::StatusCode::INTERNAL_SERVER_ERROR,
                "Crypto",
            ),
            (
                "config_error",
                reqwest::StatusCode::INTERNAL_SERVER_ERROR,
                "Config",
            ),
            (
                "storage_error",
                reqwest::StatusCode::INTERNAL_SERVER_ERROR,
                "Storage",
            ),
            (
                "unknown_code",
                reqwest::StatusCode::INTERNAL_SERVER_ERROR,
                "Server",
            ),
        ];

        for (code, status, expected_kind) in cases {
            let input = json!({
                "error": {
                    "code": code,
                    "message": format!("message for {code}")
                }
            });
            let err = map_api_error(status, &input);
            let got = match err {
                AppError::Validation(_) => "Validation",
                AppError::NotFound(_) => "NotFound",
                AppError::Conflict(_) => "Conflict",
                AppError::Unauthorized(_) => "Unauthorized",
                AppError::Forbidden(_) => "Forbidden",
                AppError::Crypto(_) => "Crypto",
                AppError::Config(_) => "Config",
                AppError::Storage(_) => "Storage",
                AppError::Server(_) => "Server",
                _ => "Other",
            };
            assert_eq!(got, expected_kind, "unexpected mapping for code={code}");
        }
    }

    #[test]
    fn redacts_unstructured_api_error_payload() {
        let input = json!({
            "raw": {
                "password": "secret",
                "note": "visible"
            }
        });
        let err = map_api_error(reqwest::StatusCode::BAD_REQUEST, &input);
        let text = err.to_string();
        assert!(!text.contains("secret"));
        assert!(text.contains("***REDACTED***"));
    }

    #[tokio::test]
    async fn request_json_handles_success_no_content_and_errors() {
        let (port, shutdown_tx) = spawn_test_server().await;

        let mut cfg = Config::default();
        cfg.server.host = "localhost".to_owned();
        cfg.server.port = port;
        cfg.server.request_timeout_secs = 5;

        let ok = request_json(&cfg, reqwest::Method::GET, "/ok", None::<serde_json::Value>)
            .await
            .expect("ok response");
        assert_eq!(ok["ok"], true);

        let echoed = request_json(
            &cfg,
            reqwest::Method::POST,
            "/echo",
            Some(json!({ "name": "mia" })),
        )
        .await
        .expect("echo response");
        assert_eq!(echoed["name"], "mia");

        let no_content = request_json(
            &cfg,
            reqwest::Method::GET,
            "/no-content",
            None::<serde_json::Value>,
        )
        .await
        .expect("no content response");
        assert_eq!(no_content["status"], "ok");

        let structured_err = request_json(
            &cfg,
            reqwest::Method::GET,
            "/err-structured",
            None::<serde_json::Value>,
        )
        .await
        .expect_err("expected structured error");
        assert!(matches!(structured_err, AppError::Forbidden(_)));

        let raw_err = request_json(
            &cfg,
            reqwest::Method::GET,
            "/err-raw",
            None::<serde_json::Value>,
        )
        .await
        .expect_err("expected raw error");
        let text = raw_err.to_string();
        assert!(!text.contains("super-secret"));
        assert!(text.contains("***REDACTED***"));

        let _ = shutdown_tx.send(());
    }

    #[test]
    fn load_command_config_applies_port_override() {
        let root = temp_dir("load-config");
        let path = root.join("mia-secret.toml");
        fs::write(
            &path,
            r#"
[server]
host = "127.0.0.1"
port = 3765
request_timeout_secs = 20
"#,
        )
        .expect("write config");

        let cfg = load_command_config(Some(path.clone()), Some(4000)).expect("load config");
        assert_eq!(cfg.server.port, 4000);

        fs::remove_dir_all(root).expect("cleanup temp dir");
    }

    #[test]
    fn config_init_refuses_overwrite_without_force() {
        let root = temp_dir("config-init");
        let path = root.join("mia-secret.toml");
        fs::write(&path, "existing = true").expect("write existing file");
        let err = super::handle_config_command(Some(path), ConfigCommands::Init { force: false })
            .expect_err("expected config already exists error");
        assert!(matches!(err, AppError::Config(message) if message.contains("already exists")));
        fs::remove_dir_all(root).expect("cleanup temp dir");
    }

    #[test]
    fn exit_codes_are_stable_for_error_categories() {
        assert_eq!(
            exit_code_for_error(&AppError::Validation("x".to_owned())),
            2
        );
        assert_eq!(exit_code_for_error(&AppError::Config("x".to_owned())), 2);
        assert_eq!(exit_code_for_error(&AppError::Address("x".to_owned())), 2);
        assert_eq!(
            exit_code_for_error(&AppError::Unauthorized("x".to_owned())),
            3
        );
        assert_eq!(exit_code_for_error(&AppError::Forbidden("x".to_owned())), 3);
        assert_eq!(exit_code_for_error(&AppError::NotFound("x".to_owned())), 4);
        assert_eq!(exit_code_for_error(&AppError::Conflict("x".to_owned())), 5);
        assert_eq!(exit_code_for_error(&AppError::Storage("x".to_owned())), 6);
        assert_eq!(exit_code_for_error(&AppError::Crypto("x".to_owned())), 6);
        assert_eq!(
            exit_code_for_error(&AppError::Serialization("x".to_owned())),
            6
        );
        assert_eq!(exit_code_for_error(&AppError::Server("x".to_owned())), 6);
        assert_eq!(
            exit_code_for_error(&AppError::Io(std::io::Error::other("io"))),
            6
        );
    }

    #[test]
    fn parse_generic_row_supports_optional_fields() {
        let mut row = HashMap::new();
        row.insert("path".to_owned(), "apps/prod/db".to_owned());
        row.insert("password".to_owned(), "secret".to_owned());
        row.insert("resource".to_owned(), "postgres".to_owned());
        row.insert("login".to_owned(), "admin".to_owned());
        row.insert("url".to_owned(), "https://example.invalid".to_owned());
        row.insert("notes".to_owned(), "note".to_owned());
        row.insert("tags".to_owned(), "prod, db".to_owned());

        let parsed = parse_generic_row(&row)
            .expect("parse generic")
            .expect("row");
        assert_eq!(parsed.path, "apps/prod/db");
        assert_eq!(parsed.password, "secret");
        assert_eq!(parsed.resource.as_deref(), Some("postgres"));
        assert_eq!(parsed.login.as_deref(), Some("admin"));
        assert_eq!(parsed.tags, Some(vec!["prod".to_owned(), "db".to_owned()]));
    }

    #[test]
    fn parse_generic_row_rejects_missing_required_columns() {
        let mut row = HashMap::new();
        row.insert("path".to_owned(), "apps/prod/db".to_owned());
        let err = parse_generic_row(&row).expect_err("must fail without password");
        assert!(
            matches!(err, AppError::Validation(message) if message.contains("path and password"))
        );
    }

    #[test]
    fn parse_bitwarden_row_maps_folder_and_totp() {
        let mut row = HashMap::new();
        row.insert("folder".to_owned(), "prod".to_owned());
        row.insert("name".to_owned(), "db".to_owned());
        row.insert("type".to_owned(), "login".to_owned());
        row.insert("login_username".to_owned(), "root".to_owned());
        row.insert("login_password".to_owned(), "pwd".to_owned());
        row.insert("login_uri".to_owned(), "https://example.invalid".to_owned());
        row.insert("notes".to_owned(), "legacy".to_owned());
        row.insert("login_totp".to_owned(), "otpauth://totp/x".to_owned());

        let parsed = parse_bitwarden_row(&row)
            .expect("parse bitwarden")
            .expect("row");
        assert_eq!(parsed.path, "prod/db");
        assert_eq!(parsed.password, "pwd");
        assert_eq!(parsed.login.as_deref(), Some("root"));
        assert_eq!(parsed.resource.as_deref(), Some("login"));
        assert_eq!(parsed.tags, Some(vec!["prod".to_owned()]));
        assert!(
            parsed
                .notes
                .as_deref()
                .is_some_and(|value| value.contains("TOTP:"))
        );
    }

    #[test]
    fn parse_generic_row_rejects_control_characters_in_path() {
        let mut row = HashMap::new();
        row.insert("path".to_owned(), "apps/\nprod/db".to_owned());
        row.insert("password".to_owned(), "secret".to_owned());

        let err = parse_generic_row(&row).expect_err("must fail for control char in path");
        assert!(
            matches!(err, AppError::Validation(message) if message.contains("control characters"))
        );
    }

    #[test]
    fn parse_bitwarden_row_rejects_control_characters_in_generated_path() {
        let mut row = HashMap::new();
        row.insert("folder".to_owned(), "prod".to_owned());
        row.insert("name".to_owned(), "db\tmain".to_owned());
        row.insert("login_password".to_owned(), "secret".to_owned());

        let err = parse_bitwarden_row(&row).expect_err("must fail for control char in path");
        assert!(
            matches!(err, AppError::Validation(message) if message.contains("control characters"))
        );
    }

    #[test]
    fn parse_import_csv_rejects_too_long_field() {
        let root = temp_dir("import-long-field");
        let csv_path = root.join("long.csv");
        let long_value = "a".repeat(MAX_IMPORT_FIELD_LENGTH + 1);
        fs::write(
            &csv_path,
            format!("path,password\napps/prod/db,{long_value}\n"),
        )
        .expect("write csv");

        let err = parse_import_csv(&csv_path, super::ImportSource::Generic)
            .expect_err("must fail for oversized field");
        assert!(
            matches!(err, AppError::Validation(message) if message.contains("exceeds maximum length"))
        );
        fs::remove_dir_all(root).expect("cleanup temp dir");
    }

    #[test]
    fn validate_import_file_rejects_too_large_file() {
        let root = temp_dir("import-size-limit");
        let csv_path = root.join("large.csv");
        fs::write(
            &csv_path,
            vec![b'a'; (MAX_IMPORT_FILE_SIZE_BYTES as usize) + 1],
        )
        .expect("write large csv");

        let err = validate_import_file(&csv_path).expect_err("must fail for large file");
        assert!(matches!(err, AppError::Validation(message) if message.contains("maximum size")));
        fs::remove_dir_all(root).expect("cleanup temp dir");
    }

    #[test]
    fn parse_import_csv_rejects_too_many_rows() {
        let root = temp_dir("import-row-limit");
        let csv_path = root.join("rows.csv");
        let mut content = String::from("path,password\n");
        for idx in 0..=MAX_IMPORT_ROWS {
            content.push_str(&format!("apps/prod/{idx},secret\n"));
        }
        fs::write(&csv_path, content).expect("write csv");

        let err = parse_import_csv(&csv_path, super::ImportSource::Generic)
            .expect_err("must fail for too many rows");
        assert!(
            matches!(err, AppError::Validation(message) if message.contains("maximum rows limit"))
        );
        fs::remove_dir_all(root).expect("cleanup temp dir");
    }
}
