use std::path::{Path, PathBuf};

use ::config as config_crate;
use serde::{Deserialize, Serialize};

use crate::error::AppError;

const CONFIG_FILE_NAME: &str = "mia-secret.toml";
const CONFIG_DIR_NAME: &str = "mia-secret";
const ENV_PREFIX: &str = "MIA_SECRET";
const DEFAULT_DATA_DIR: &str = "./data";
const DEFAULT_DATABASE_PATH: &str = "./data/secrets.db";
const DEFAULT_LOG_LEVEL: &str = "info";
const DEFAULT_HOST: &str = "127.0.0.1";
const DEFAULT_PORT: u16 = 3765;
const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 30;
const DEFAULT_TOKEN_HEADER: &str = "Authorization";
const DEFAULT_LOCK_TIMEOUT_SECS: u64 = 300;
const DEFAULT_MAX_FAILED_ATTEMPTS: u32 = 5;
const DEFAULT_MIN_MASTER_PASSWORD_LENGTH: u32 = 12;
const DEFAULT_ARGON2_MEMORY_KB: u32 = 65_536;
const DEFAULT_ARGON2_TIME_COST: u32 = 3;
const DEFAULT_ARGON2_PARALLELISM: u32 = 4;
const DEFAULT_OUTPUT_FORMAT: &str = "table";
const DEFAULT_MAX_BACKUPS: u32 = 10;

const MIN_ARGON2_MEMORY_KB: u32 = 65_536;
const MIN_ARGON2_TIME_COST: u32 = 3;
const MIN_ARGON2_PARALLELISM: u32 = 1;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Config {
    pub general: GeneralConfig,
    pub server: ServerConfig,
    pub security: SecurityConfig,
    pub crypto: CryptoConfig,
    pub storage: StorageConfig,
    pub cli: CliConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct GeneralConfig {
    pub data_dir: String,
    pub database_path: String,
    pub log_level: String,
    pub enable_file_logging: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub request_timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct SecurityConfig {
    pub token_header: String,
    pub lock_timeout_secs: u64,
    pub max_failed_attempts: u32,
    pub min_master_password_length: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct CryptoConfig {
    pub argon2_memory_kb: u32,
    pub argon2_time_cost: u32,
    pub argon2_parallelism: u32,
    pub encrypt_notes: bool,
    pub encrypt_custom_fields: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct StorageConfig {
    pub auto_migrate: bool,
    pub create_backup_before_write: bool,
    pub max_backups: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct CliConfig {
    pub output_format: String,
    pub interactive: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ConfigOverrides {
    pub host: Option<String>,
    pub port: Option<u16>,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            data_dir: DEFAULT_DATA_DIR.to_owned(),
            database_path: DEFAULT_DATABASE_PATH.to_owned(),
            log_level: DEFAULT_LOG_LEVEL.to_owned(),
            enable_file_logging: true,
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: DEFAULT_HOST.to_owned(),
            port: DEFAULT_PORT,
            request_timeout_secs: DEFAULT_REQUEST_TIMEOUT_SECS,
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            token_header: DEFAULT_TOKEN_HEADER.to_owned(),
            lock_timeout_secs: DEFAULT_LOCK_TIMEOUT_SECS,
            max_failed_attempts: DEFAULT_MAX_FAILED_ATTEMPTS,
            min_master_password_length: DEFAULT_MIN_MASTER_PASSWORD_LENGTH,
        }
    }
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            argon2_memory_kb: DEFAULT_ARGON2_MEMORY_KB,
            argon2_time_cost: DEFAULT_ARGON2_TIME_COST,
            argon2_parallelism: DEFAULT_ARGON2_PARALLELISM,
            encrypt_notes: true,
            encrypt_custom_fields: true,
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            auto_migrate: true,
            create_backup_before_write: true,
            max_backups: DEFAULT_MAX_BACKUPS,
        }
    }
}

impl Default for CliConfig {
    fn default() -> Self {
        Self {
            output_format: DEFAULT_OUTPUT_FORMAT.to_owned(),
            interactive: true,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<(), AppError> {
        validate_loopback_host(&self.server.host)?;

        if self.server.request_timeout_secs == 0 {
            return Err(AppError::Validation(
                "server.request_timeout_secs must be greater than 0".to_owned(),
            ));
        }

        if self.security.lock_timeout_secs == 0 {
            return Err(AppError::Validation(
                "security.lock_timeout_secs must be greater than 0".to_owned(),
            ));
        }

        if self.crypto.argon2_memory_kb < MIN_ARGON2_MEMORY_KB {
            return Err(AppError::Validation(format!(
                "crypto.argon2_memory_kb must be at least {}",
                MIN_ARGON2_MEMORY_KB
            )));
        }

        if self.crypto.argon2_time_cost < MIN_ARGON2_TIME_COST {
            return Err(AppError::Validation(format!(
                "crypto.argon2_time_cost must be at least {}",
                MIN_ARGON2_TIME_COST
            )));
        }

        if self.crypto.argon2_parallelism < MIN_ARGON2_PARALLELISM {
            return Err(AppError::Validation(format!(
                "crypto.argon2_parallelism must be at least {}",
                MIN_ARGON2_PARALLELISM
            )));
        }

        if self.general.data_dir.trim().is_empty() {
            return Err(AppError::Validation(
                "general.data_dir must not be empty".to_owned(),
            ));
        }

        if self.general.database_path.trim().is_empty() {
            return Err(AppError::Validation(
                "general.database_path must not be empty".to_owned(),
            ));
        }

        Ok(())
    }
}

pub fn resolve_config_path(path: Option<PathBuf>) -> PathBuf {
    if let Some(path) = path {
        return path;
    }

    let local_path = PathBuf::from(CONFIG_FILE_NAME);
    if local_path.exists() {
        return local_path;
    }

    if let Some(config_dir) = dirs::config_dir() {
        let preferred = config_dir.join(CONFIG_DIR_NAME).join(CONFIG_FILE_NAME);
        if preferred.exists() {
            return preferred;
        }
    }

    local_path
}

pub fn load(path: &Path, overrides: ConfigOverrides) -> Result<Config, AppError> {
    let raw = config_crate::Config::builder()
        .add_source(config_crate::File::from(path).required(false))
        .add_source(
            config_crate::Environment::with_prefix(ENV_PREFIX)
                .separator("__")
                .try_parsing(true),
        )
        .build()
        .map_err(|err| AppError::Config(err.to_string()))?;

    let mut cfg: Config = raw
        .try_deserialize()
        .map_err(|err| AppError::Config(err.to_string()))?;

    if let Some(host) = overrides.host {
        cfg.server.host = host;
    }

    if let Some(port) = overrides.port {
        cfg.server.port = port;
    }

    cfg.validate()?;
    Ok(cfg)
}

pub fn write_default_if_missing(path: &Path) -> Result<(), AppError> {
    if path.exists() {
        return Ok(());
    }

    write_default(path, false)
}

pub fn write_default(path: &Path, force: bool) -> Result<(), AppError> {
    if path.exists() && !force {
        return Err(AppError::Config(format!(
            "config already exists at {}",
            path.display()
        )));
    }

    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }

    let rendered = toml::to_string_pretty(&Config::default())
        .map_err(|err| AppError::Config(format!("failed to serialize default config: {err}")))?;

    std::fs::write(path, rendered)?;
    Ok(())
}

fn validate_loopback_host(host: &str) -> Result<(), AppError> {
    if host.eq_ignore_ascii_case("localhost") {
        return Ok(());
    }

    if let Ok(addr) = host.parse::<std::net::IpAddr>()
        && addr.is_loopback()
    {
        return Ok(());
    }

    Err(AppError::Validation(format!(
        "server.host must be a loopback address, got {host}"
    )))
}
