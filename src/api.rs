use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use axum::extract::{DefaultBodyLimit, Path as AxumPath, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use rusqlite::OpenFlags;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
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
    protected_request_timestamps: Arc<Mutex<VecDeque<Instant>>>,
    metrics: Arc<Mutex<ApiMetrics>>,
}

#[derive(Debug, Clone)]
struct TraceId(String);

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HealthResponse {
    status: String,
    version: String,
    database_ready: bool,
    config_loaded: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReadinessResponse {
    status: String,
    version: String,
    checks: ReadinessChecks,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReadinessChecks {
    config_loaded: bool,
    database_connection: bool,
    schema_migrations_present: bool,
}

#[derive(Debug, Clone, Serialize)]
struct SafeConfigResponse {
    general: SafeGeneralConfig,
    server: SafeServerConfig,
    security: SafeSecurityConfig,
    crypto: SafeCryptoConfig,
    storage: SafeStorageConfig,
    cli: SafeCliConfig,
}

#[derive(Debug, Clone, Serialize)]
struct SafeGeneralConfig {
    data_dir: String,
    database_path: String,
    log_level: String,
    enable_file_logging: bool,
}

#[derive(Debug, Clone, Serialize)]
struct SafeServerConfig {
    host: String,
    port: u16,
    request_timeout_secs: u64,
    max_request_body_kb: u64,
    protected_rate_limit_rps: u64,
}

#[derive(Debug, Clone, Serialize)]
struct SafeSecurityConfig {
    token_header: String,
    lock_timeout_secs: u64,
    max_failed_attempts: u32,
    min_master_password_length: u32,
}

#[derive(Debug, Clone, Serialize)]
struct SafeCryptoConfig {
    argon2_memory_kb: u32,
    argon2_time_cost: u32,
    argon2_parallelism: u32,
    encrypt_notes: bool,
    encrypt_custom_fields: bool,
}

#[derive(Debug, Clone, Serialize)]
struct SafeStorageConfig {
    auto_migrate: bool,
    create_backup_before_write: bool,
    max_backups: u32,
    sqlite_busy_timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
struct SafeCliConfig {
    output_format: String,
    interactive: bool,
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

#[derive(Debug, Default)]
struct ApiMetrics {
    total_requests: u64,
    total_errors: u64,
    total_timeouts: u64,
    auth_failures_total: u64,
    rate_limited_total: u64,
    token_created_total: u64,
    token_revoked_total: u64,
    by_route: HashMap<RouteMetricKey, RouteMetricValue>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct RouteMetricKey {
    method: String,
    path: String,
    status: u16,
}

#[derive(Debug, Default)]
struct RouteMetricValue {
    count: u64,
    latency_sum_ms: u128,
}

pub async fn serve(cfg: Config) -> Result<(), AppError> {
    let app = build_app(cfg.clone())?;
    let addr = bind_addr(&cfg.server.host, cfg.server.port)?;
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("listening on http://{addr}");
    axum::serve(listener, app.into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|err| AppError::Server(err.to_string()))
}

pub fn build_app(cfg: Config) -> Result<Router, AppError> {
    let storage = Arc::new(SqliteStorage::from_config(&cfg)?);
    let crypto = CryptoService::from_config(&cfg)?;
    let service = Arc::new(AppService::new(storage, crypto));
    let state = ApiState {
        cfg: cfg.clone(),
        service,
        protected_request_timestamps: Arc::new(Mutex::new(VecDeque::new())),
        metrics: Arc::new(Mutex::new(ApiMetrics::default())),
    };

    let protected_routes = Router::new()
        .route("/api/v1/secrets", post(create_secret).get(list_secrets))
        .route(
            "/api/v1/secrets/{id}",
            get(get_secret).patch(update_secret).delete(delete_secret),
        )
        .route("/api/v1/secrets/by-path/{*path}", get(get_secret_by_path))
        .route("/api/v1/tokens", post(create_token).get(list_tokens))
        .route("/api/v1/tokens/{id}/revoke", post(revoke_token))
        .route("/api/v1/config", get(read_config))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            authz_middleware,
        ));

    let app = Router::new()
        .route("/api/v1/health", get(health))
        .route("/api/v1/ready", get(readiness))
        .route("/api/v1/metrics", get(metrics))
        .merge(protected_routes)
        .with_state(state.clone())
        .layer(DefaultBodyLimit::max(max_request_body_bytes(&cfg)))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            access_log_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            timeout_middleware,
        ))
        .layer(middleware::from_fn(trace_id_middleware));

    Ok(app)
}

pub async fn check_health(cfg: &Config) -> Result<(), AppError> {
    let url = health_url(&cfg.server.host, cfg.server.port)?;
    let ready_url = readiness_url(&cfg.server.host, cfg.server.port)?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(cfg.server.request_timeout_secs))
        .build()?;
    let response = client.get(url).send().await?.error_for_status()?;
    let body: HealthResponse = response.json().await?;
    let ready_response = client.get(ready_url).send().await?;
    let ready_status = ready_response.status();
    let ready_body: ReadinessResponse = ready_response.json().await?;
    if !ready_status.is_success() {
        return Err(AppError::Server(format!(
            "service is not ready: status={} database_connection={} schema_migrations_present={}",
            ready_body.status,
            ready_body.checks.database_connection,
            ready_body.checks.schema_migrations_present
        )));
    }
    println!(
        "{} version={} database_ready={} config_loaded={} readiness={}",
        body.status, body.version, body.database_ready, body.config_loaded, ready_body.status
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

async fn metrics(State(state): State<ApiState>) -> String {
    render_prometheus_metrics(&state.metrics).await
}

async fn readiness(State(state): State<ApiState>) -> (StatusCode, Json<ReadinessResponse>) {
    let checks = compute_readiness_checks(&state.cfg);
    let is_ready =
        checks.config_loaded && checks.database_connection && checks.schema_migrations_present;
    let status = if is_ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    let body = ReadinessResponse {
        status: if is_ready {
            "ready".to_owned()
        } else {
            "not_ready".to_owned()
        },
        version: env!("CARGO_PKG_VERSION").to_owned(),
        checks,
    };
    (status, Json(body))
}

fn compute_readiness_checks(cfg: &Config) -> ReadinessChecks {
    let db_path = Path::new(&cfg.general.database_path);
    let (database_connection, schema_migrations_present) = match open_database_readonly(db_path) {
        Ok(conn) => {
            let schema_ok = schema_migrations_table_exists(&conn).unwrap_or(false);
            (true, schema_ok)
        }
        Err(_) => (false, false),
    };

    ReadinessChecks {
        config_loaded: true,
        database_connection,
        schema_migrations_present,
    }
}

fn max_request_body_bytes(cfg: &Config) -> usize {
    cfg.server
        .max_request_body_kb
        .saturating_mul(1024)
        .min(usize::MAX as u64) as usize
}

fn open_database_readonly(path: &Path) -> Result<rusqlite::Connection, AppError> {
    rusqlite::Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(Into::into)
}

fn schema_migrations_table_exists(conn: &rusqlite::Connection) -> Result<bool, AppError> {
    let exists: i64 = conn.query_row(
        "SELECT COUNT(1) FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'",
        [],
        |row| row.get(0),
    )?;
    Ok(exists > 0)
}

async fn read_config(
    State(state): State<ApiState>,
) -> Result<Json<SafeConfigResponse>, ApiHttpError> {
    let cfg = &state.cfg;
    let response = SafeConfigResponse {
        general: SafeGeneralConfig {
            data_dir: cfg.general.data_dir.clone(),
            database_path: cfg.general.database_path.clone(),
            log_level: cfg.general.log_level.clone(),
            enable_file_logging: cfg.general.enable_file_logging,
        },
        server: SafeServerConfig {
            host: cfg.server.host.clone(),
            port: cfg.server.port,
            request_timeout_secs: cfg.server.request_timeout_secs,
            max_request_body_kb: cfg.server.max_request_body_kb,
            protected_rate_limit_rps: cfg.server.protected_rate_limit_rps,
        },
        security: SafeSecurityConfig {
            token_header: cfg.security.token_header.clone(),
            lock_timeout_secs: cfg.security.lock_timeout_secs,
            max_failed_attempts: cfg.security.max_failed_attempts,
            min_master_password_length: cfg.security.min_master_password_length,
        },
        crypto: SafeCryptoConfig {
            argon2_memory_kb: cfg.crypto.argon2_memory_kb,
            argon2_time_cost: cfg.crypto.argon2_time_cost,
            argon2_parallelism: cfg.crypto.argon2_parallelism,
            encrypt_notes: cfg.crypto.encrypt_notes,
            encrypt_custom_fields: cfg.crypto.encrypt_custom_fields,
        },
        storage: SafeStorageConfig {
            auto_migrate: cfg.storage.auto_migrate,
            create_backup_before_write: cfg.storage.create_backup_before_write,
            max_backups: cfg.storage.max_backups,
            sqlite_busy_timeout_ms: cfg.storage.sqlite_busy_timeout_ms,
        },
        cli: SafeCliConfig {
            output_format: cfg.cli.output_format.clone(),
            interactive: cfg.cli.interactive,
        },
    };
    Ok(Json(response))
}

async fn create_secret(
    State(state): State<ApiState>,
    Extension(trace): Extension<TraceId>,
    Json(req): Json<CreateSecretRequest>,
) -> Result<Json<Secret>, ApiHttpError> {
    state
        .service
        .create_secret(req)
        .map(Json)
        .map_err(|err| ApiHttpError::from_app(err, Some(trace.0)))
}

async fn list_secrets(
    State(state): State<ApiState>,
    Extension(trace): Extension<TraceId>,
) -> Result<Json<Vec<Secret>>, ApiHttpError> {
    state
        .service
        .list_secrets()
        .map(Json)
        .map_err(|err| ApiHttpError::from_app(err, Some(trace.0)))
}

async fn get_secret(
    State(state): State<ApiState>,
    Extension(trace): Extension<TraceId>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<Secret>, ApiHttpError> {
    let id = Uuid::parse_str(&id).map_err(|_| {
        ApiHttpError::from_app(
            AppError::Validation(format!("invalid uuid: {id}")),
            Some(trace.0.clone()),
        )
    })?;
    state
        .service
        .get_secret(id)
        .map(Json)
        .map_err(|err| ApiHttpError::from_app(err, Some(trace.0)))
}

async fn get_secret_by_path(
    State(state): State<ApiState>,
    Extension(trace): Extension<TraceId>,
    AxumPath(path): AxumPath<String>,
) -> Result<Json<Secret>, ApiHttpError> {
    state
        .service
        .get_secret_by_path(path.trim_start_matches('/'))
        .map(Json)
        .map_err(|err| ApiHttpError::from_app(err, Some(trace.0)))
}

async fn update_secret(
    State(state): State<ApiState>,
    Extension(trace): Extension<TraceId>,
    AxumPath(id): AxumPath<String>,
    Json(req): Json<UpdateSecretRequest>,
) -> Result<Json<Secret>, ApiHttpError> {
    let id = Uuid::parse_str(&id).map_err(|_| {
        ApiHttpError::from_app(
            AppError::Validation(format!("invalid uuid: {id}")),
            Some(trace.0.clone()),
        )
    })?;
    state
        .service
        .update_secret(id, req)
        .map(Json)
        .map_err(|err| ApiHttpError::from_app(err, Some(trace.0)))
}

async fn delete_secret(
    State(state): State<ApiState>,
    Extension(trace): Extension<TraceId>,
    AxumPath(id): AxumPath<String>,
) -> Result<StatusCode, ApiHttpError> {
    let id = Uuid::parse_str(&id).map_err(|_| {
        ApiHttpError::from_app(
            AppError::Validation(format!("invalid uuid: {id}")),
            Some(trace.0.clone()),
        )
    })?;
    state
        .service
        .delete_secret(id)
        .map_err(|err| ApiHttpError::from_app(err, Some(trace.0)))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn create_token(
    State(state): State<ApiState>,
    Extension(trace): Extension<TraceId>,
    Json(req): Json<CreateTokenRequest>,
) -> Result<Json<TokenCreationResult>, ApiHttpError> {
    let created = state
        .service
        .create_token(req)
        .map_err(|err| ApiHttpError::from_app(err, Some(trace.0)))?;
    increment_token_created(&state.metrics).await;
    Ok(Json(created))
}

async fn list_tokens(
    State(state): State<ApiState>,
    Extension(trace): Extension<TraceId>,
) -> Result<Json<Vec<Token>>, ApiHttpError> {
    state
        .service
        .list_tokens()
        .map(Json)
        .map_err(|err| ApiHttpError::from_app(err, Some(trace.0)))
}

async fn revoke_token(
    State(state): State<ApiState>,
    Extension(trace): Extension<TraceId>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<Token>, ApiHttpError> {
    let id = Uuid::parse_str(&id).map_err(|_| {
        ApiHttpError::from_app(
            AppError::Validation(format!("invalid uuid: {id}")),
            Some(trace.0.clone()),
        )
    })?;
    let revoked = state
        .service
        .revoke_token(id)
        .map_err(|err| ApiHttpError::from_app(err, Some(trace.0)))?;
    increment_token_revoked(&state.metrics).await;
    Ok(Json(revoked))
}

async fn trace_id_middleware(mut req: Request, next: Next) -> Response {
    let trace_id = Uuid::new_v4().to_string();
    req.extensions_mut().insert(TraceId(trace_id.clone()));
    let mut response = next.run(req).await;
    if let Ok(value) = HeaderValue::from_str(&trace_id) {
        response.headers_mut().insert("x-trace-id", value);
    }
    response
}

async fn access_log_middleware(
    State(state): State<ApiState>,
    req: Request,
    next: Next,
) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_owned();
    let trace_id = extract_trace_id_from_request(&req).unwrap_or_else(|| "n/a".to_owned());
    let start = Instant::now();
    let response = next.run(req).await;
    let status = response.status().as_u16();
    let elapsed_ms = start.elapsed().as_millis();
    record_request_metrics(&state.metrics, &method, &path, status, elapsed_ms).await;
    tracing::info!(
        trace_id = %trace_id,
        method = %method,
        path = %path,
        status = status,
        elapsed_ms = elapsed_ms,
        "request handled"
    );
    response
}

async fn timeout_middleware(
    State(state): State<ApiState>,
    req: Request,
    next: Next,
) -> Result<Response, ApiHttpError> {
    let trace_id = extract_trace_id_from_request(&req);
    match tokio::time::timeout(
        Duration::from_secs(state.cfg.server.request_timeout_secs),
        next.run(req),
    )
    .await
    {
        Ok(response) => Ok(response),
        Err(_) => Err(ApiHttpError {
            status: StatusCode::REQUEST_TIMEOUT,
            code: "internal_error",
            message: "request timeout exceeded".to_owned(),
            trace_id,
        }),
    }
}

async fn authz_middleware(
    State(state): State<ApiState>,
    req: Request,
    next: Next,
) -> Result<Response, ApiHttpError> {
    let trace_id = extract_trace_id_from_request(&req);
    if !allow_protected_request(&state).await {
        increment_rate_limited(&state.metrics).await;
        return Err(ApiHttpError {
            status: StatusCode::TOO_MANY_REQUESTS,
            code: "rate_limited",
            message: format!(
                "rate limit exceeded: {} requests per second",
                state.cfg.server.protected_rate_limit_rps
            ),
            trace_id,
        });
    }
    if let Some(scope) = required_scope_for_request(&state, req.method(), req.uri().path())
        .map_err(|err| ApiHttpError::from_app(err, trace_id.clone()))?
    {
        let token = match extract_bearer_token(req.headers(), &state.cfg.security.token_header) {
            Ok(value) => value,
            Err(err) => {
                increment_auth_failure(&state.metrics).await;
                return Err(ApiHttpError::from_app(err, trace_id.clone()));
            }
        };
        if let Err(err) = state.service.authorize(token, scope) {
            increment_auth_failure(&state.metrics).await;
            return Err(ApiHttpError::from_app(err, trace_id.clone()));
        }
    }
    Ok(next.run(req).await)
}

async fn allow_protected_request(state: &ApiState) -> bool {
    let now = Instant::now();
    let mut timestamps = state.protected_request_timestamps.lock().await;
    while let Some(first) = timestamps.front().copied() {
        if now.duration_since(first) >= Duration::from_secs(1) {
            let _ = timestamps.pop_front();
        } else {
            break;
        }
    }

    if timestamps.len() as u64 >= state.cfg.server.protected_rate_limit_rps {
        return false;
    }

    timestamps.push_back(now);
    true
}

fn required_scope_for_request(
    state: &ApiState,
    method: &Method,
    path: &str,
) -> Result<Option<&'static str>, AppError> {
    if method == Method::GET && path == "/api/v1/health" {
        return Ok(None);
    }
    if method == Method::GET && path == "/api/v1/ready" {
        return Ok(None);
    }
    if method == Method::GET && path == "/api/v1/metrics" {
        return Ok(None);
    }
    if method == Method::GET && path == "/api/v1/config" {
        return Ok(Some("config.read"));
    }

    if path == "/api/v1/secrets" {
        if method == Method::POST {
            return Ok(Some("secrets.write"));
        }
        if method == Method::GET {
            return Ok(Some("secrets.list"));
        }
    }

    if method == Method::GET && path.starts_with("/api/v1/secrets/by-path/") {
        return Ok(Some("secrets.read"));
    }

    if path.starts_with("/api/v1/secrets/") {
        if method == Method::GET {
            return Ok(Some("secrets.read"));
        }
        if method == Method::PATCH {
            return Ok(Some("secrets.write"));
        }
        if method == Method::DELETE {
            return Ok(Some("secrets.delete"));
        }
    }

    if path == "/api/v1/tokens" {
        if method == Method::POST {
            if state.service.has_any_tokens()? {
                return Ok(Some("tokens.manage"));
            }
            return Ok(None);
        }
        if method == Method::GET {
            return Ok(Some("tokens.manage"));
        }
    }

    if method == Method::POST && path.starts_with("/api/v1/tokens/") && path.ends_with("/revoke") {
        return Ok(Some("tokens.manage"));
    }

    Ok(None)
}

fn extract_bearer_token<'a>(
    headers: &'a HeaderMap,
    header_name: &str,
) -> Result<&'a str, AppError> {
    let header = headers
        .get(header_name)
        .ok_or_else(|| AppError::Unauthorized("missing bearer token".to_owned()))?;
    let value = header
        .to_str()
        .map_err(|_| AppError::Unauthorized("invalid authorization header".to_owned()))?;
    value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
        .ok_or_else(|| AppError::Unauthorized("expected Bearer token".to_owned()))
}

fn extract_trace_id_from_request(req: &Request) -> Option<String> {
    req.extensions()
        .get::<TraceId>()
        .map(|trace| trace.0.clone())
}

async fn record_request_metrics(
    metrics: &Arc<Mutex<ApiMetrics>>,
    method: &Method,
    path: &str,
    status: u16,
    elapsed_ms: u128,
) {
    let mut metrics = metrics.lock().await;
    metrics.total_requests += 1;
    if status >= 400 {
        metrics.total_errors += 1;
    }
    if status == StatusCode::REQUEST_TIMEOUT.as_u16() {
        metrics.total_timeouts += 1;
    }

    let key = RouteMetricKey {
        method: method.as_str().to_owned(),
        path: path.to_owned(),
        status,
    };
    let route = metrics.by_route.entry(key).or_default();
    route.count += 1;
    route.latency_sum_ms += elapsed_ms;
}

async fn increment_auth_failure(metrics: &Arc<Mutex<ApiMetrics>>) {
    let mut metrics = metrics.lock().await;
    metrics.auth_failures_total += 1;
}

async fn increment_rate_limited(metrics: &Arc<Mutex<ApiMetrics>>) {
    let mut metrics = metrics.lock().await;
    metrics.rate_limited_total += 1;
}

async fn increment_token_created(metrics: &Arc<Mutex<ApiMetrics>>) {
    let mut metrics = metrics.lock().await;
    metrics.token_created_total += 1;
}

async fn increment_token_revoked(metrics: &Arc<Mutex<ApiMetrics>>) {
    let mut metrics = metrics.lock().await;
    metrics.token_revoked_total += 1;
}

async fn render_prometheus_metrics(metrics: &Arc<Mutex<ApiMetrics>>) -> String {
    let metrics = metrics.lock().await;
    let mut lines = vec![
        "# HELP mia_http_requests_total Total HTTP requests processed.".to_owned(),
        "# TYPE mia_http_requests_total counter".to_owned(),
        format!("mia_http_requests_total {}", metrics.total_requests),
        "# HELP mia_http_errors_total Total HTTP requests with status >= 400.".to_owned(),
        "# TYPE mia_http_errors_total counter".to_owned(),
        format!("mia_http_errors_total {}", metrics.total_errors),
        "# HELP mia_http_timeouts_total Total HTTP requests completed with 408.".to_owned(),
        "# TYPE mia_http_timeouts_total counter".to_owned(),
        format!("mia_http_timeouts_total {}", metrics.total_timeouts),
        "# HELP mia_auth_failures_total Total authorization failures.".to_owned(),
        "# TYPE mia_auth_failures_total counter".to_owned(),
        format!("mia_auth_failures_total {}", metrics.auth_failures_total),
        "# HELP mia_rate_limited_total Total requests rejected by rate limiting.".to_owned(),
        "# TYPE mia_rate_limited_total counter".to_owned(),
        format!("mia_rate_limited_total {}", metrics.rate_limited_total),
        "# HELP mia_token_created_total Total successfully created tokens.".to_owned(),
        "# TYPE mia_token_created_total counter".to_owned(),
        format!("mia_token_created_total {}", metrics.token_created_total),
        "# HELP mia_token_revoked_total Total successfully revoked tokens.".to_owned(),
        "# TYPE mia_token_revoked_total counter".to_owned(),
        format!("mia_token_revoked_total {}", metrics.token_revoked_total),
        "# HELP mia_http_requests_by_route_total Requests grouped by method/path/status."
            .to_owned(),
        "# TYPE mia_http_requests_by_route_total counter".to_owned(),
        "# HELP mia_http_latency_ms_sum Total latency sum in milliseconds by method/path/status."
            .to_owned(),
        "# TYPE mia_http_latency_ms_sum counter".to_owned(),
    ];

    let mut route_entries = metrics.by_route.iter().collect::<Vec<_>>();
    route_entries.sort_by(|(a, _), (b, _)| {
        (&a.path, &a.method, a.status).cmp(&(&b.path, &b.method, b.status))
    });

    for (key, value) in route_entries {
        let labels = format!(
            "method=\"{}\",path=\"{}\",status=\"{}\"",
            escape_prometheus_label(&key.method),
            escape_prometheus_label(&key.path),
            key.status
        );
        lines.push(format!(
            "mia_http_requests_by_route_total{{{labels}}} {}",
            value.count
        ));
        lines.push(format!(
            "mia_http_latency_ms_sum{{{labels}}} {}",
            value.latency_sum_ms
        ));
    }

    lines.join("\n")
}

fn escape_prometheus_label(input: &str) -> String {
    input
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
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

fn readiness_url(host: &str, port: u16) -> Result<String, AppError> {
    if host.eq_ignore_ascii_case("localhost") {
        return Ok(format!("http://localhost:{port}/api/v1/ready"));
    }
    let ip = host
        .parse::<IpAddr>()
        .map_err(|_| AppError::Address(format!("unable to parse server host: {host}")))?;
    let formatted = match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("[{v6}]"),
    };
    Ok(format!("http://{formatted}:{port}/api/v1/ready"))
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

struct ApiHttpError {
    status: StatusCode,
    code: &'static str,
    message: String,
    trace_id: Option<String>,
}

impl ApiHttpError {
    fn from_app(err: AppError, trace_id: Option<String>) -> Self {
        match err {
            AppError::Validation(message) => Self {
                status: StatusCode::BAD_REQUEST,
                code: "validation_error",
                message,
                trace_id,
            },
            AppError::NotFound(message) => Self {
                status: StatusCode::NOT_FOUND,
                code: "not_found",
                message,
                trace_id,
            },
            AppError::Conflict(message) => Self {
                status: StatusCode::CONFLICT,
                code: "conflict",
                message,
                trace_id,
            },
            AppError::Unauthorized(message) => Self {
                status: StatusCode::UNAUTHORIZED,
                code: "unauthorized",
                message,
                trace_id,
            },
            AppError::Forbidden(message) => Self {
                status: StatusCode::FORBIDDEN,
                code: "forbidden",
                message,
                trace_id,
            },
            AppError::Crypto(message) => Self {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                code: "crypto_error",
                message,
                trace_id,
            },
            AppError::Config(message) => Self {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                code: "config_error",
                message,
                trace_id,
            },
            AppError::Storage(message) => Self {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                code: "storage_error",
                message,
                trace_id,
            },
            other => Self {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                code: "internal_error",
                message: other.to_string(),
                trace_id,
            },
        }
    }
}

impl IntoResponse for ApiHttpError {
    fn into_response(self) -> Response {
        let trace_id = self.trace_id.unwrap_or_else(|| Uuid::new_v4().to_string());
        let body = Json(ErrorEnvelope {
            error: ApiErrorBody {
                code: self.code.to_owned(),
                message: self.message,
                trace_id: trace_id.clone(),
            },
        });
        let mut response = (self.status, body).into_response();
        if let Ok(value) = HeaderValue::from_str(&trace_id) {
            response.headers_mut().insert("x-trace-id", value);
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(name: &str) -> PathBuf {
        let unique = format!(
            "mia-secret-api-test-{name}-{}-{}",
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

    fn test_config(root: &std::path::Path) -> Config {
        let mut cfg = Config::default();
        let data_dir = root.join("data");
        let db_path = data_dir.join("secrets.db");
        cfg.general.data_dir = data_dir.to_string_lossy().into_owned();
        cfg.general.database_path = db_path.to_string_lossy().into_owned();
        cfg.server.host = "127.0.0.1".to_owned();
        cfg
    }

    fn make_state() -> ApiState {
        let root = temp_dir("state");
        let cfg = test_config(&root);
        bootstrap::ensure_layout(&cfg).expect("ensure layout");
        let storage = Arc::new(SqliteStorage::from_config(&cfg).expect("storage"));
        let crypto = CryptoService::from_config(&cfg).expect("crypto");
        let service = Arc::new(AppService::new(storage, crypto));
        ApiState {
            cfg,
            service,
            protected_request_timestamps: Arc::new(Mutex::new(VecDeque::new())),
            metrics: Arc::new(Mutex::new(ApiMetrics::default())),
        }
    }

    #[test]
    fn required_scope_maps_routes_to_expected_permissions() {
        let state = make_state();
        assert_eq!(
            required_scope_for_request(&state, &Method::GET, "/api/v1/health").expect("health"),
            None
        );
        assert_eq!(
            required_scope_for_request(&state, &Method::GET, "/api/v1/ready").expect("ready"),
            None
        );
        assert_eq!(
            required_scope_for_request(&state, &Method::GET, "/api/v1/metrics").expect("metrics"),
            None
        );
        assert_eq!(
            required_scope_for_request(&state, &Method::GET, "/api/v1/config").expect("config"),
            Some("config.read")
        );
        assert_eq!(
            required_scope_for_request(&state, &Method::POST, "/api/v1/secrets")
                .expect("create secret"),
            Some("secrets.write")
        );
        assert_eq!(
            required_scope_for_request(&state, &Method::GET, "/api/v1/secrets").expect("list"),
            Some("secrets.list")
        );
        assert_eq!(
            required_scope_for_request(&state, &Method::GET, "/api/v1/secrets/by-path/a")
                .expect("by path"),
            Some("secrets.read")
        );
        assert_eq!(
            required_scope_for_request(&state, &Method::PATCH, "/api/v1/secrets/abc")
                .expect("update"),
            Some("secrets.write")
        );
        assert_eq!(
            required_scope_for_request(&state, &Method::DELETE, "/api/v1/secrets/abc")
                .expect("delete"),
            Some("secrets.delete")
        );
        assert_eq!(
            required_scope_for_request(&state, &Method::POST, "/api/v1/tokens")
                .expect("bootstrap token"),
            None
        );
        assert_eq!(
            required_scope_for_request(&state, &Method::GET, "/api/v1/tokens").expect("list tok"),
            Some("tokens.manage")
        );
        assert_eq!(
            required_scope_for_request(&state, &Method::POST, "/api/v1/tokens/x/revoke")
                .expect("revoke"),
            Some("tokens.manage")
        );
        assert_eq!(
            required_scope_for_request(&state, &Method::GET, "/api/v1/unknown").expect("unknown"),
            None
        );
    }

    #[test]
    fn extract_bearer_token_validates_header_format() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "Authorization",
            HeaderValue::from_static("Bearer token-123"),
        );
        assert_eq!(
            extract_bearer_token(&headers, "Authorization").expect("token"),
            "token-123"
        );

        headers.insert(
            "Authorization",
            HeaderValue::from_static("bearer token-456"),
        );
        assert_eq!(
            extract_bearer_token(&headers, "Authorization").expect("token lowercase"),
            "token-456"
        );

        let missing = HeaderMap::new();
        assert!(matches!(
            extract_bearer_token(&missing, "Authorization"),
            Err(AppError::Unauthorized(_))
        ));

        let mut invalid = HeaderMap::new();
        invalid.insert("Authorization", HeaderValue::from_static("Token abc"));
        assert!(matches!(
            extract_bearer_token(&invalid, "Authorization"),
            Err(AppError::Unauthorized(_))
        ));
    }

    #[test]
    fn bind_addr_and_health_url_handle_localhost_ipv4_and_ipv6() {
        let localhost = bind_addr("localhost", 8080).expect("localhost bind");
        assert_eq!(
            localhost,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080)
        );

        let ipv4 = bind_addr("127.0.0.1", 9090).expect("ipv4 bind");
        assert_eq!(ipv4, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9090));

        let ipv6_url = health_url("::1", 3765).expect("ipv6 health");
        assert_eq!(ipv6_url, "http://[::1]:3765/api/v1/health");

        let localhost_url = health_url("localhost", 3765).expect("localhost health");
        assert_eq!(localhost_url, "http://localhost:3765/api/v1/health");
        let localhost_ready = readiness_url("localhost", 3765).expect("localhost ready");
        assert_eq!(localhost_ready, "http://localhost:3765/api/v1/ready");
        let ipv6_ready = readiness_url("::1", 3765).expect("ipv6 ready");
        assert_eq!(ipv6_ready, "http://[::1]:3765/api/v1/ready");

        assert!(matches!(
            bind_addr("not-an-ip", 1),
            Err(AppError::Address(_))
        ));
        assert!(matches!(
            health_url("not-an-ip", 1),
            Err(AppError::Address(_))
        ));
        assert!(matches!(
            readiness_url("not-an-ip", 1),
            Err(AppError::Address(_))
        ));
    }

    #[test]
    fn api_http_error_maps_and_sets_trace_id() {
        let err = ApiHttpError::from_app(
            AppError::Validation("bad request".to_owned()),
            Some("trace-123".to_owned()),
        );
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response
                .headers()
                .get("x-trace-id")
                .and_then(|h| h.to_str().ok()),
            Some("trace-123")
        );

        let internal =
            ApiHttpError::from_app(AppError::Io(std::io::Error::other("io failure")), None);
        let response = internal.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(
            response.headers().get("x-trace-id").is_some(),
            "trace id must be generated"
        );
    }

    #[test]
    fn max_request_body_bytes_converts_kb_to_bytes() {
        let mut cfg = Config::default();
        cfg.server.max_request_body_kb = 1;
        assert_eq!(max_request_body_bytes(&cfg), 1024);
    }

    #[tokio::test]
    async fn allow_protected_request_respects_rps_limit() {
        let state = make_state();
        let mut cfg = state.cfg.clone();
        cfg.server.protected_rate_limit_rps = 1;
        let state = ApiState {
            cfg,
            service: state.service.clone(),
            protected_request_timestamps: Arc::new(Mutex::new(VecDeque::new())),
            metrics: Arc::new(Mutex::new(ApiMetrics::default())),
        };

        assert!(allow_protected_request(&state).await);
        assert!(!allow_protected_request(&state).await);
    }

    #[tokio::test]
    async fn render_prometheus_metrics_contains_expected_lines() {
        let metrics = Arc::new(Mutex::new(ApiMetrics::default()));
        record_request_metrics(&metrics, &Method::GET, "/api/v1/health", 200, 4).await;
        record_request_metrics(&metrics, &Method::GET, "/api/v1/health", 503, 7).await;
        increment_auth_failure(&metrics).await;
        increment_rate_limited(&metrics).await;
        increment_token_created(&metrics).await;
        increment_token_revoked(&metrics).await;
        let text = render_prometheus_metrics(&metrics).await;
        assert!(text.contains("mia_http_requests_total 2"));
        assert!(text.contains("mia_http_errors_total 1"));
        assert!(text.contains("mia_auth_failures_total 1"));
        assert!(text.contains("mia_rate_limited_total 1"));
        assert!(text.contains("mia_token_created_total 1"));
        assert!(text.contains("mia_token_revoked_total 1"));
        assert!(text.contains("path=\"/api/v1/health\""));
    }

    #[test]
    fn readiness_checks_report_not_ready_when_database_is_missing() {
        let root = temp_dir("readiness-missing-db");
        let cfg = test_config(&root);
        let checks = compute_readiness_checks(&cfg);
        assert!(checks.config_loaded);
        assert!(!checks.database_connection);
        assert!(!checks.schema_migrations_present);
    }

    #[test]
    fn readiness_checks_report_ready_for_initialized_layout() {
        let root = temp_dir("readiness-ready");
        let cfg = test_config(&root);
        bootstrap::ensure_layout(&cfg).expect("ensure layout");
        let _storage = SqliteStorage::from_config(&cfg).expect("initialize storage and migrations");
        let checks = compute_readiness_checks(&cfg);
        assert!(checks.config_loaded);
        assert!(checks.database_connection);
        assert!(checks.schema_migrations_present);
    }
}
