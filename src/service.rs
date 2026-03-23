use std::collections::HashSet;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use rand::TryRngCore;
use rusqlite::Transaction;
use serde_json::Value;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::crypto::CryptoService;
use crate::domain::{
    CreateSecretRequest, CreateTokenRequest, Secret, SecretRecord, Token, TokenCreationResult,
    TokenRecord, UpdateSecretRequest,
};
use crate::error::AppError;
use crate::storage::SqliteStorage;

const ALLOWED_SCOPES: &[&str] = &[
    "secrets.read",
    "secrets.write",
    "tokens.manage",
    "secrets.delete",
    "secrets.list",
    "config.read",
    "service.health",
];

#[derive(Debug, Clone)]
pub struct AppService {
    storage: Arc<SqliteStorage>,
    crypto: CryptoService,
}

#[derive(Debug, Clone)]
pub struct ImportSecretRequest {
    pub path: String,
    pub resource: Option<String>,
    pub login: Option<String>,
    pub password: String,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub tags: Option<Vec<String>>,
}

#[derive(Debug, Clone, Copy)]
pub enum ImportDuplicateStrategy {
    Skip,
    Update,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportOutcome {
    Imported,
    Updated,
    Skipped,
}

impl AppService {
    pub fn new(storage: Arc<SqliteStorage>, crypto: CryptoService) -> Self {
        Self { storage, crypto }
    }

    pub fn has_any_tokens(&self) -> Result<bool, AppError> {
        self.storage.has_any_tokens()
    }

    pub fn create_secret(&self, req: CreateSecretRequest) -> Result<Secret, AppError> {
        let path = required_trim(req.path, "path")?;
        let password = required_trim(req.password, "password")?;
        if self.storage.get_secret_by_path(&path)?.is_some() {
            return Err(AppError::Conflict(format!(
                "secret path already exists: {path}"
            )));
        }

        let notes_encrypted = maybe_encrypt_text(
            &self.crypto,
            req.notes.as_deref(),
            self.crypto.encrypt_notes,
        )?;
        let custom_fields_encrypted = maybe_encrypt_json(
            &self.crypto,
            req.custom_fields.as_ref(),
            self.crypto.encrypt_custom_fields,
        )?;
        let now = now_unix();
        let record = SecretRecord {
            id: Uuid::new_v4(),
            path,
            resource: optional_trim(req.resource),
            login: optional_trim(req.login),
            password_encrypted: self.crypto.encrypt_string(&password)?,
            url: optional_trim(req.url),
            notes_encrypted,
            tags: normalize_tags(req.tags.unwrap_or_default())?,
            custom_fields_encrypted,
            created_at: now,
            updated_at: now,
        };
        self.storage.insert_secret(&record)?;
        self.to_secret(record)
    }

    pub fn list_secrets(&self) -> Result<Vec<Secret>, AppError> {
        self.storage
            .list_secrets()?
            .into_iter()
            .map(|record| self.to_secret(record))
            .collect()
    }

    pub fn get_secret(&self, id: Uuid) -> Result<Secret, AppError> {
        let record = self
            .storage
            .get_secret_by_id(id)?
            .ok_or_else(|| AppError::NotFound(format!("secret not found: {id}")))?;
        self.to_secret(record)
    }

    pub fn get_secret_by_path(&self, path: &str) -> Result<Secret, AppError> {
        let path = required_trim(path.to_owned(), "path")?;
        let record = self
            .storage
            .get_secret_by_path(&path)?
            .ok_or_else(|| AppError::NotFound(format!("secret not found by path: {path}")))?;
        self.to_secret(record)
    }

    pub fn update_secret(&self, id: Uuid, req: UpdateSecretRequest) -> Result<Secret, AppError> {
        let mut record = self
            .storage
            .get_secret_by_id(id)?
            .ok_or_else(|| AppError::NotFound(format!("secret not found: {id}")))?;

        if let Some(path) = req.path {
            let normalized = required_trim(path, "path")?;
            if normalized != record.path && self.storage.get_secret_by_path(&normalized)?.is_some()
            {
                return Err(AppError::Conflict(format!(
                    "secret path already exists: {normalized}"
                )));
            }
            record.path = normalized;
        }
        if let Some(resource) = req.resource {
            record.resource = optional_trim(Some(resource));
        }
        if let Some(login) = req.login {
            record.login = optional_trim(Some(login));
        }
        if let Some(password) = req.password {
            record.password_encrypted = self
                .crypto
                .encrypt_string(&required_trim(password, "password")?)?;
        }
        if let Some(url) = req.url {
            record.url = optional_trim(Some(url));
        }
        if let Some(notes) = req.notes {
            record.notes_encrypted = maybe_encrypt_text(
                &self.crypto,
                optional_trim(Some(notes)).as_deref(),
                self.crypto.encrypt_notes,
            )?;
        }
        if let Some(tags) = req.tags {
            record.tags = normalize_tags(tags)?;
        }
        if let Some(custom_fields) = req.custom_fields {
            record.custom_fields_encrypted = maybe_encrypt_json(
                &self.crypto,
                Some(&custom_fields),
                self.crypto.encrypt_custom_fields,
            )?;
        }
        record.updated_at = now_unix();
        self.storage.update_secret(&record)?;
        self.to_secret(record)
    }

    pub fn delete_secret(&self, id: Uuid) -> Result<(), AppError> {
        self.storage.delete_secret(id)
    }

    pub fn create_token(&self, req: CreateTokenRequest) -> Result<TokenCreationResult, AppError> {
        let name = required_trim(req.name, "name")?;
        let scopes = normalize_scopes(req.scopes)?;
        let now = now_unix();
        if let Some(expires_at) = req.expires_at
            && expires_at <= now
        {
            return Err(AppError::Validation(
                "expires_at must be in the future".to_owned(),
            ));
        }
        let token_plain = generate_plain_token()?;
        let token_hash = self.crypto.hash_token(&token_plain);
        let record = TokenRecord {
            id: Uuid::new_v4(),
            name,
            token_hash,
            scopes,
            created_at: now,
            expires_at: req.expires_at,
            revoked_at: None,
            last_used_at: None,
        };
        self.storage.insert_token(&record)?;
        Ok(TokenCreationResult {
            token: token_plain,
            record: to_public_token(record),
        })
    }

    pub fn list_tokens(&self) -> Result<Vec<Token>, AppError> {
        Ok(self
            .storage
            .list_tokens()?
            .into_iter()
            .map(to_public_token)
            .collect())
    }

    pub fn revoke_token(&self, id: Uuid) -> Result<Token, AppError> {
        let mut token = self
            .storage
            .get_token_by_id(id)?
            .ok_or_else(|| AppError::NotFound(format!("token not found: {id}")))?;
        if token.revoked_at.is_none() {
            token.revoked_at = Some(now_unix());
            self.storage.update_token(&token)?;
        }
        Ok(to_public_token(token))
    }

    pub fn authorize(&self, token: &str, required_scope: &str) -> Result<Token, AppError> {
        let token = token.trim();
        if token.is_empty() {
            return Err(AppError::Unauthorized("empty token".to_owned()));
        }
        let token_hash = self.crypto.hash_token(token);
        let mut record = self
            .storage
            .get_token_by_hash(&token_hash)?
            .ok_or_else(|| AppError::Unauthorized("invalid token".to_owned()))?;
        let now = now_unix();
        if record.revoked_at.is_some() {
            return Err(AppError::Unauthorized("token revoked".to_owned()));
        }
        if let Some(expires_at) = record.expires_at
            && expires_at <= now
        {
            return Err(AppError::Unauthorized("token expired".to_owned()));
        }
        if !record.scopes.iter().any(|scope| scope == required_scope) {
            return Err(AppError::Forbidden(format!(
                "missing required scope: {required_scope}"
            )));
        }
        record.last_used_at = Some(now);
        self.storage.update_token(&record)?;
        Ok(to_public_token(record))
    }

    pub fn run_import_tx<T>(
        &self,
        op: impl FnOnce(&Transaction<'_>) -> Result<T, AppError>,
    ) -> Result<T, AppError> {
        self.storage.run_import_tx(op)
    }

    pub fn import_secret_tx(
        &self,
        tx: &Transaction<'_>,
        req: ImportSecretRequest,
        strategy: ImportDuplicateStrategy,
    ) -> Result<ImportOutcome, AppError> {
        let path = required_trim(req.path, "path")?;
        let password = required_trim(req.password, "password")?;
        let existing = self.storage.get_secret_by_path_tx(tx, &path)?;
        let now = now_unix();

        if let Some(mut record) = existing {
            if matches!(strategy, ImportDuplicateStrategy::Skip) {
                return Ok(ImportOutcome::Skipped);
            }

            record.path = path;
            if let Some(resource) = req.resource {
                record.resource = optional_trim(Some(resource));
            }
            if let Some(login) = req.login {
                record.login = optional_trim(Some(login));
            }
            record.password_encrypted = self.crypto.encrypt_string(&password)?;
            if let Some(url) = req.url {
                record.url = optional_trim(Some(url));
            }
            if let Some(notes) = req.notes {
                record.notes_encrypted = maybe_encrypt_text(
                    &self.crypto,
                    optional_trim(Some(notes)).as_deref(),
                    self.crypto.encrypt_notes,
                )?;
            }
            if let Some(tags) = req.tags {
                record.tags = normalize_tags(tags)?;
            }
            record.updated_at = now;
            self.storage.update_secret_tx(tx, &record)?;
            return Ok(ImportOutcome::Updated);
        }

        let record = SecretRecord {
            id: Uuid::new_v4(),
            path,
            resource: optional_trim(req.resource),
            login: optional_trim(req.login),
            password_encrypted: self.crypto.encrypt_string(&password)?,
            url: optional_trim(req.url),
            notes_encrypted: maybe_encrypt_text(
                &self.crypto,
                optional_trim(req.notes).as_deref(),
                self.crypto.encrypt_notes,
            )?,
            tags: normalize_tags(req.tags.unwrap_or_default())?,
            custom_fields_encrypted: None,
            created_at: now,
            updated_at: now,
        };
        self.storage.insert_secret_tx(tx, &record)?;
        Ok(ImportOutcome::Imported)
    }

    fn to_secret(&self, record: SecretRecord) -> Result<Secret, AppError> {
        let password = self.crypto.decrypt_string(&record.password_encrypted)?;
        let notes = match record.notes_encrypted {
            Some(value) => Some(self.crypto.decrypt_auto(&value)?),
            None => None,
        };
        let custom_fields = match record.custom_fields_encrypted {
            Some(value) => Some(decrypt_or_parse_json(&self.crypto, &value)?),
            None => None,
        };
        Ok(Secret {
            id: record.id,
            path: record.path,
            resource: record.resource,
            login: record.login,
            password,
            url: record.url,
            notes,
            tags: record.tags,
            custom_fields,
            created_at: record.created_at,
            updated_at: record.updated_at,
        })
    }
}

fn to_public_token(record: TokenRecord) -> Token {
    Token {
        id: record.id,
        name: record.name,
        scopes: record.scopes,
        created_at: record.created_at,
        expires_at: record.expires_at,
        revoked_at: record.revoked_at,
        last_used_at: record.last_used_at,
    }
}

fn required_trim(value: String, field: &str) -> Result<String, AppError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(AppError::Validation(format!("{field} is required")));
    }
    Ok(trimmed.to_owned())
}

fn optional_trim(value: Option<String>) -> Option<String> {
    value.and_then(|candidate| {
        let trimmed = candidate.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_owned())
        }
    })
}

fn normalize_tags(values: Vec<String>) -> Result<Vec<String>, AppError> {
    let mut unique = HashSet::new();
    let mut result = Vec::new();
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(AppError::Validation(
                "tags cannot contain empty values".to_owned(),
            ));
        }
        if unique.insert(trimmed.to_owned()) {
            result.push(trimmed.to_owned());
        }
    }
    Ok(result)
}

fn normalize_scopes(values: Vec<String>) -> Result<Vec<String>, AppError> {
    let scopes = normalize_tags(values)?;
    for scope in &scopes {
        if !ALLOWED_SCOPES
            .iter()
            .any(|allowed| allowed == &scope.as_str())
        {
            return Err(AppError::Validation(format!("unsupported scope: {scope}")));
        }
    }
    Ok(scopes)
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn generate_plain_token() -> Result<String, AppError> {
    let mut buf = [0u8; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut buf)
        .map_err(|e| AppError::Crypto(format!("token generation failed: {e}")))?;
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf);
    buf.zeroize();
    Ok(token)
}

fn maybe_encrypt_text(
    crypto: &CryptoService,
    value: Option<&str>,
    encrypt: bool,
) -> Result<Option<String>, AppError> {
    match value {
        Some(text) if encrypt => Ok(Some(crypto.encrypt_string(text)?)),
        Some(text) => Ok(Some(text.to_owned())),
        None => Ok(None),
    }
}

fn maybe_encrypt_json(
    crypto: &CryptoService,
    value: Option<&Value>,
    encrypt: bool,
) -> Result<Option<String>, AppError> {
    match value {
        Some(json) if encrypt => {
            let raw = serde_json::to_string(json)
                .map_err(|e| AppError::Serialization(format!("custom fields serialize: {e}")))?;
            Ok(Some(crypto.encrypt_string(&raw)?))
        }
        Some(json) => serde_json::to_string(json)
            .map(Some)
            .map_err(|e| AppError::Serialization(format!("custom fields serialize: {e}"))),
        None => Ok(None),
    }
}

fn decrypt_or_parse_json(crypto: &CryptoService, value: &str) -> Result<Value, AppError> {
    let raw = if value.starts_with("v1:") {
        crypto.decrypt_string(value)?
    } else {
        value.to_owned()
    };
    serde_json::from_str(&raw)
        .map_err(|e| AppError::Serialization(format!("custom fields parse: {e}")))
}
