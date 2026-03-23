use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use uuid::Uuid;

use crate::config::Config;
use crate::crypto::CryptoService;
use crate::domain::{
    CreateSecretRequest, CreateTokenRequest, Secret, Token, TokenCreationResult,
    UpdateSecretRequest,
};
use crate::error::AppError;
use crate::service::AppService;
use crate::storage::SqliteStorage;

#[derive(Debug, Clone)]
struct ApiState {
    cfg: Config,
    service: Arc<AppService>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HealthResponse {
    status: String,
    version: String,
    database_ready: bool,
    config_loaded: bool,
}

#[derive(Debug, Serialize)]
struct ErrorEnvelope {
    error: ApiErrorBody,
}

#[derive(Debug, Serialize)]
struct ApiErrorBody {
    code: String,
    message: String,
    #[serde(rename = "traceId")]
    trace_id: String,
}

pub async fn serve(cfg: Config) -> Result<(), AppError> {
    let storage = Arc::new(SqliteStorage::new(&cfg.general.database_path)?);
    let crypto = CryptoService::from_config(&cfg)?;
    let service = Arc::new(AppService::new(storage, crypto));
    let state = ApiState {
        cfg: cfg.clone(),
        service,
    };

    let addr = bind_addr(&cfg.server.host, cfg.server.port)?;
    let app = Router::new()
        .route("/api/v1/health", get(health))
        .route("/api/v1/secrets", post(create_secret).get(list_secrets))
        .route(
            "/api/v1/secrets/{id}",
            get(get_secret).patch(update_secret).delete(delete_secret),
        )
        .route("/api/v1/secrets/by-path/{*path}", get(get_secret_by_path))
        .route("/api/v1/tokens", post(create_token).get(list_tokens))
        .route("/api/v1/tokens/{id}/revoke", post(revoke_token))
        .with_state(state);

    let listener = TcpListener::bind(addr).await?;
    tracing::info!("listening on http://{addr}");
    axum::serve(listener, app.into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|err| AppError::Server(err.to_string()))
}

pub async fn check_health(cfg: &Config) -> Result<(), AppError> {
    let url = health_url(&cfg.server.host, cfg.server.port)?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(cfg.server.request_timeout_secs))
        .build()?;
    let response = client.get(url).send().await?.error_for_status()?;
    let body: HealthResponse = response.json().await?;
    println!(
        "{} version={} database_ready={} config_loaded={}",
        body.status, body.version, body.database_ready, body.config_loaded
    );
    Ok(())
}

async fn health(State(state): State<ApiState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_owned(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        database_ready: Path::new(&state.cfg.general.database_path).exists(),
        config_loaded: true,
    })
}

async fn create_secret(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<CreateSecretRequest>,
) -> Result<Json<Secret>, ApiHttpError> {
    authorize(&state, &headers, "secrets.write")?;
    state
        .service
        .create_secret(req)
        .map(Json)
        .map_err(ApiHttpError::from)
}

async fn list_secrets(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<Json<Vec<Secret>>, ApiHttpError> {
    authorize(&state, &headers, "secrets.list")?;
    state
        .service
        .list_secrets()
        .map(Json)
        .map_err(ApiHttpError::from)
}

async fn get_secret(
    State(state): State<ApiState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<Secret>, ApiHttpError> {
    authorize(&state, &headers, "secrets.read")?;
    let id = parse_uuid(&id)?;
    state
        .service
        .get_secret(id)
        .map(Json)
        .map_err(ApiHttpError::from)
}

async fn get_secret_by_path(
    State(state): State<ApiState>,
    headers: HeaderMap,
    AxumPath(path): AxumPath<String>,
) -> Result<Json<Secret>, ApiHttpError> {
    authorize(&state, &headers, "secrets.read")?;
    state
        .service
        .get_secret_by_path(path.trim_start_matches('/'))
        .map(Json)
        .map_err(ApiHttpError::from)
}

async fn update_secret(
    State(state): State<ApiState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(req): Json<UpdateSecretRequest>,
) -> Result<Json<Secret>, ApiHttpError> {
    authorize(&state, &headers, "secrets.write")?;
    let id = parse_uuid(&id)?;
    state
        .service
        .update_secret(id, req)
        .map(Json)
        .map_err(ApiHttpError::from)
}

async fn delete_secret(
    State(state): State<ApiState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Result<StatusCode, ApiHttpError> {
    authorize(&state, &headers, "secrets.delete")?;
    let id = parse_uuid(&id)?;
    state.service.delete_secret(id)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn create_token(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<CreateTokenRequest>,
) -> Result<Json<TokenCreationResult>, ApiHttpError> {
    if state.service.has_any_tokens()? {
        authorize(&state, &headers, "tokens.manage")?;
    }
    state
        .service
        .create_token(req)
        .map(Json)
        .map_err(ApiHttpError::from)
}

async fn list_tokens(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<Json<Vec<Token>>, ApiHttpError> {
    authorize(&state, &headers, "tokens.manage")?;
    state
        .service
        .list_tokens()
        .map(Json)
        .map_err(ApiHttpError::from)
}

async fn revoke_token(
    State(state): State<ApiState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<Token>, ApiHttpError> {
    authorize(&state, &headers, "tokens.manage")?;
    let id = parse_uuid(&id)?;
    state
        .service
        .revoke_token(id)
        .map(Json)
        .map_err(ApiHttpError::from)
}

fn authorize(state: &ApiState, headers: &HeaderMap, scope: &str) -> Result<(), ApiHttpError> {
    let token = extract_bearer_token(headers)?;
    state
        .service
        .authorize(token, scope)
        .map(|_| ())
        .map_err(ApiHttpError::from)
}

fn extract_bearer_token(headers: &HeaderMap) -> Result<&str, ApiHttpError> {
    let header = headers.get("Authorization").ok_or_else(|| {
        ApiHttpError::from(AppError::Unauthorized("missing bearer token".to_owned()))
    })?;
    let value = header.to_str().map_err(|_| {
        ApiHttpError::from(AppError::Unauthorized(
            "invalid authorization header".to_owned(),
        ))
    })?;
    let token = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
        .ok_or_else(|| {
            ApiHttpError::from(AppError::Unauthorized("expected Bearer token".to_owned()))
        })?;
    Ok(token)
}

fn parse_uuid(value: &str) -> Result<Uuid, ApiHttpError> {
    Uuid::parse_str(value)
        .map_err(|_| ApiHttpError::from(AppError::Validation(format!("invalid uuid: {value}"))))
}

fn bind_addr(host: &str, port: u16) -> Result<SocketAddr, AppError> {
    if host.eq_ignore_ascii_case("localhost") {
        return Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port));
    }
    let ip = host
        .parse::<IpAddr>()
        .map_err(|_| AppError::Address(format!("unable to parse server host: {host}")))?;
    Ok(SocketAddr::new(ip, port))
}

fn health_url(host: &str, port: u16) -> Result<String, AppError> {
    if host.eq_ignore_ascii_case("localhost") {
        return Ok(format!("http://localhost:{port}/api/v1/health"));
    }
    let ip = host
        .parse::<IpAddr>()
        .map_err(|_| AppError::Address(format!("unable to parse server host: {host}")))?;
    let formatted = match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("[{v6}]"),
    };
    Ok(format!("http://{formatted}:{port}/api/v1/health"))
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

struct ApiHttpError {
    status: StatusCode,
    code: &'static str,
    message: String,
}

impl From<AppError> for ApiHttpError {
    fn from(err: AppError) -> Self {
        match err {
            AppError::Validation(message) => Self {
                status: StatusCode::BAD_REQUEST,
                code: "validation_error",
                message,
            },
            AppError::NotFound(message) => Self {
                status: StatusCode::NOT_FOUND,
                code: "not_found",
                message,
            },
            AppError::Conflict(message) => Self {
                status: StatusCode::CONFLICT,
                code: "conflict",
                message,
            },
            AppError::Unauthorized(message) => Self {
                status: StatusCode::UNAUTHORIZED,
                code: "unauthorized",
                message,
            },
            AppError::Forbidden(message) => Self {
                status: StatusCode::FORBIDDEN,
                code: "forbidden",
                message,
            },
            AppError::Crypto(message) => Self {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                code: "crypto_error",
                message,
            },
            AppError::Config(message) => Self {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                code: "config_error",
                message,
            },
            AppError::Storage(message) => Self {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                code: "storage_error",
                message,
            },
            other => Self {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                code: "internal_error",
                message: other.to_string(),
            },
        }
    }
}

impl axum::response::IntoResponse for ApiHttpError {
    fn into_response(self) -> axum::response::Response {
        let trace_id = Uuid::new_v4().to_string();
        let body = Json(ErrorEnvelope {
            error: ApiErrorBody {
                code: self.code.to_owned(),
                message: self.message,
                trace_id,
            },
        });
        (self.status, body).into_response()
    }
}
