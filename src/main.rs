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

use std::path::PathBuf;

use clap::Parser;
use cli::{Cli, Commands, ConfigCommands, TokenCommands};
use error::AppError;
use security::redact_json;
use serde::{Deserialize, Serialize};
use storage::SqliteStorage;

#[tokio::main]
async fn main() -> Result<(), AppError> {
    init_tracing();

    let cli = Cli::parse();
    dispatch(cli).await
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

#[cfg(test)]
mod tests {
    use super::map_api_error;
    use crate::error::AppError;
    use serde_json::json;

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
}
