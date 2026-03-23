use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Secret {
    pub id: Uuid,
    pub path: String,
    pub resource: Option<String>,
    pub login: Option<String>,
    pub password: String,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub tags: Vec<String>,
    pub custom_fields: Option<Value>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretRecord {
    pub id: Uuid,
    pub path: String,
    pub resource: Option<String>,
    pub login: Option<String>,
    pub password_encrypted: String,
    pub url: Option<String>,
    pub notes_encrypted: Option<String>,
    pub tags: Vec<String>,
    pub custom_fields_encrypted: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSecretRequest {
    pub path: String,
    pub resource: Option<String>,
    pub login: Option<String>,
    pub password: String,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub tags: Option<Vec<String>>,
    pub custom_fields: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdateSecretRequest {
    pub path: Option<String>,
    pub resource: Option<String>,
    pub login: Option<String>,
    pub password: Option<String>,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub tags: Option<Vec<String>>,
    pub custom_fields: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    pub id: Uuid,
    pub name: String,
    pub scopes: Vec<String>,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub revoked_at: Option<i64>,
    pub last_used_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRecord {
    pub id: Uuid,
    pub name: String,
    pub token_hash: String,
    pub scopes: Vec<String>,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub revoked_at: Option<i64>,
    pub last_used_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTokenRequest {
    pub name: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenCreationResult {
    pub token: String,
    pub record: Token,
}
