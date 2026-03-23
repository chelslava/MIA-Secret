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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(name: &str) -> PathBuf {
        let unique = format!(
            "mia-secret-config-test-{name}-{}-{}",
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

    #[test]
    fn validate_accepts_default_and_localhost() {
        let mut cfg = Config::default();
        cfg.server.host = "localhost".to_owned();
        cfg.validate().expect("localhost should be accepted");
    }

    #[test]
    fn validate_rejects_invalid_values() {
        let mut cfg = Config::default();
        cfg.server.request_timeout_secs = 0;
        assert!(matches!(cfg.validate(), Err(AppError::Validation(_))));

        cfg = Config::default();
        cfg.security.lock_timeout_secs = 0;
        assert!(matches!(cfg.validate(), Err(AppError::Validation(_))));

        cfg = Config::default();
        cfg.crypto.argon2_memory_kb = MIN_ARGON2_MEMORY_KB - 1;
        assert!(matches!(cfg.validate(), Err(AppError::Validation(_))));

        cfg = Config::default();
        cfg.crypto.argon2_time_cost = MIN_ARGON2_TIME_COST - 1;
        assert!(matches!(cfg.validate(), Err(AppError::Validation(_))));

        cfg = Config::default();
        cfg.crypto.argon2_parallelism = MIN_ARGON2_PARALLELISM - 1;
        assert!(matches!(cfg.validate(), Err(AppError::Validation(_))));

        cfg = Config::default();
        cfg.general.data_dir = " ".to_owned();
        assert!(matches!(cfg.validate(), Err(AppError::Validation(_))));

        cfg = Config::default();
        cfg.general.database_path = " ".to_owned();
        assert!(matches!(cfg.validate(), Err(AppError::Validation(_))));
    }

    #[test]
    fn validate_rejects_non_loopback_host() {
        let mut cfg = Config::default();
        cfg.server.host = "192.168.1.10".to_owned();
        assert!(matches!(cfg.validate(), Err(AppError::Validation(_))));
    }

    #[test]
    fn resolve_config_path_prefers_explicit_path() {
        let explicit = PathBuf::from("custom-config.toml");
        let resolved = resolve_config_path(Some(explicit.clone()));
        assert_eq!(resolved, explicit);
    }

    #[test]
    fn write_default_if_missing_and_force_behaviour() {
        let root = temp_dir("write-default");
        let path = root.join("config").join("mia-secret.toml");

        write_default_if_missing(&path).expect("write missing default");
        assert!(path.exists());
        let first = fs::read_to_string(&path).expect("read created config");
        assert!(first.contains("[general]"));

        let err = write_default(&path, false).expect_err("should fail without force");
        assert!(matches!(err, AppError::Config(message) if message.contains("already exists")));

        write_default(&path, true).expect("force overwrite config");
        let second = fs::read_to_string(&path).expect("read overwritten config");
        assert!(!second.trim().is_empty());

        fs::remove_dir_all(root).expect("cleanup temp dir");
    }

    #[test]
    fn load_applies_cli_overrides() {
        let root = temp_dir("load-overrides");
        let path = root.join("mia-secret.toml");
        fs::write(
            &path,
            r#"
[server]
host = "127.0.0.1"
port = 1111
request_timeout_secs = 15

[general]
data_dir = "./data"
database_path = "./data/secrets.db"
"#,
        )
        .expect("write config file");

        let cfg = load(
            &path,
            ConfigOverrides {
                host: Some("localhost".to_owned()),
                port: Some(4321),
            },
        )
        .expect("load config with overrides");

        assert_eq!(cfg.server.host, "localhost");
        assert_eq!(cfg.server.port, 4321);

        fs::remove_dir_all(root).expect("cleanup temp dir");
    }

    #[test]
    fn load_missing_file_falls_back_to_defaults() {
        let root = temp_dir("missing-file");
        let path = root.join("does-not-exist.toml");
        let cfg = load(&path, ConfigOverrides::default()).expect("load defaults");
        assert_eq!(cfg.server.host, DEFAULT_HOST);
        assert_eq!(cfg.server.port, DEFAULT_PORT);
        fs::remove_dir_all(root).expect("cleanup temp dir");
    }
}
