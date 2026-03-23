use std::fs;
use std::path::Path;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use hkdf::Hkdf;
use rand::TryRngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::config::{Config, CryptoConfig};
use crate::error::AppError;

const MASTER_KEY_FILE_NAME: &str = "master.key";
const MASTER_KEY_LEN: usize = 32;
const DERIVED_KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const CIPHERTEXT_PREFIX: &str = "v1:";
const ROOT_SALT: &[u8] = b"mia-secret/root-key/v1";
const ENC_INFO: &[u8] = b"mia-secret/aes-256-gcm/v1";
const TOKEN_INFO: &[u8] = b"mia-secret/token-hash/v1";

#[derive(Debug, Clone)]
pub struct CryptoService {
    encryption_key: [u8; DERIVED_KEY_LEN],
    token_hash_key: [u8; DERIVED_KEY_LEN],
    pub encrypt_notes: bool,
    pub encrypt_custom_fields: bool,
}

impl Drop for CryptoService {
    fn drop(&mut self) {
        self.encryption_key.zeroize();
        self.token_hash_key.zeroize();
    }
}

impl CryptoService {
    pub fn from_config(cfg: &Config) -> Result<Self, AppError> {
        let master_key_path = Path::new(&cfg.general.data_dir).join(MASTER_KEY_FILE_NAME);
        let master_key = fs::read(master_key_path)?;
        Self::from_master_key(&master_key, &cfg.crypto)
    }

    pub fn from_master_key(master_key: &[u8], cfg: &CryptoConfig) -> Result<Self, AppError> {
        if master_key.len() != MASTER_KEY_LEN {
            return Err(AppError::Crypto(format!(
                "master.key must be {MASTER_KEY_LEN} bytes"
            )));
        }

        let params = Params::new(
            cfg.argon2_memory_kb,
            cfg.argon2_time_cost,
            cfg.argon2_parallelism,
            Some(DERIVED_KEY_LEN),
        )
        .map_err(|e| AppError::Crypto(format!("invalid argon2 params: {e}")))?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut root_key = [0u8; DERIVED_KEY_LEN];
        argon2
            .hash_password_into(master_key, ROOT_SALT, &mut root_key)
            .map_err(|e| AppError::Crypto(format!("argon2 derivation failed: {e}")))?;

        let hkdf = Hkdf::<Sha256>::new(Some(master_key), &root_key);
        let mut encryption_key = [0u8; DERIVED_KEY_LEN];
        let mut token_hash_key = [0u8; DERIVED_KEY_LEN];
        hkdf.expand(ENC_INFO, &mut encryption_key)
            .map_err(|_| AppError::Crypto("hkdf expand failed for encryption key".to_owned()))?;
        hkdf.expand(TOKEN_INFO, &mut token_hash_key)
            .map_err(|_| AppError::Crypto("hkdf expand failed for token key".to_owned()))?;
        root_key.zeroize();

        Ok(Self {
            encryption_key,
            token_hash_key,
            encrypt_notes: cfg.encrypt_notes,
            encrypt_custom_fields: cfg.encrypt_custom_fields,
        })
    }

    pub fn encrypt_string(&self, plaintext: &str) -> Result<String, AppError> {
        let cipher = Aes256Gcm::new_from_slice(&self.encryption_key)
            .map_err(|e| AppError::Crypto(format!("invalid key: {e}")))?;
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::rngs::OsRng
            .try_fill_bytes(&mut nonce_bytes)
            .map_err(|e| AppError::Crypto(format!("nonce generation failed: {e}")))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|_| AppError::Crypto("encryption failed".to_owned()))?;

        let mut combined = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        combined.extend_from_slice(&nonce_bytes);
        combined.extend_from_slice(&ciphertext);
        Ok(format!(
            "{CIPHERTEXT_PREFIX}{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(combined)
        ))
    }

    pub fn decrypt_string(&self, value: &str) -> Result<String, AppError> {
        let encoded = value
            .strip_prefix(CIPHERTEXT_PREFIX)
            .ok_or_else(|| AppError::Crypto("unsupported ciphertext format".to_owned()))?;
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|e| AppError::Crypto(format!("ciphertext decode failed: {e}")))?;
        if decoded.len() <= NONCE_LEN {
            return Err(AppError::Crypto("ciphertext payload too short".to_owned()));
        }
        let (nonce_bytes, ciphertext) = decoded.split_at(NONCE_LEN);
        let cipher = Aes256Gcm::new_from_slice(&self.encryption_key)
            .map_err(|e| AppError::Crypto(format!("invalid key: {e}")))?;
        let plain = cipher
            .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
            .map_err(|_| AppError::Crypto("decryption failed".to_owned()))?;
        String::from_utf8(plain).map_err(|e| AppError::Crypto(format!("utf8 decode failed: {e}")))
    }

    pub fn decrypt_auto(&self, value: &str) -> Result<String, AppError> {
        if value.starts_with(CIPHERTEXT_PREFIX) {
            self.decrypt_string(value)
        } else {
            Ok(value.to_owned())
        }
    }

    pub fn hash_token(&self, token: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.token_hash_key);
        hasher.update(token.as_bytes());
        let digest = hasher.finalize();
        format!(
            "{CIPHERTEXT_PREFIX}{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
        )
    }
}
