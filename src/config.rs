use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub host: String,
    pub port: u16,
    pub database_url: String,
    pub webauthn_rp_id: String,
    pub webauthn_origin: String,
    pub webauthn_rp_name: String,
    pub challenge_timeout_seconds: u64,
}

impl AppConfig {
    pub fn from_env() -> Result<Self, env::VarError> {
        Ok(Self {
            host: env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
            port: env::var("PORT")
                .unwrap_or_else(|_| "8080".to_string())
                .parse()
                .unwrap_or(8080),
            database_url: env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgres://postgres:password@localhost/fido2_server".to_string()),
            webauthn_rp_id: env::var("WEBAUTHN_RP_ID")
                .unwrap_or_else(|_| "localhost".to_string()),
            webauthn_origin: env::var("WEBAUTHN_ORIGIN")
                .unwrap_or_else(|_| "http://localhost:8080".to_string()),
            webauthn_rp_name: env::var("WEBAUTHN_RP_NAME")
                .unwrap_or_else(|_| "FIDO2 Test Server".to_string()),
            challenge_timeout_seconds: env::var("CHALLENGE_TIMEOUT_SECONDS")
                .unwrap_or_else(|_| "300".to_string())
                .parse()
                .unwrap_or(300),
        })
    }
}

#[cfg(test)]
impl AppConfig {
    pub fn test_config() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 0, // Let the OS choose a free port for tests
            database_url: "postgres://test:test@localhost/fido2_test".to_string(),
            webauthn_rp_id: "localhost".to_string(),
            webauthn_origin: "http://localhost:8080".to_string(),
            webauthn_rp_name: "FIDO2 Test Server".to_string(),
            challenge_timeout_seconds: 30,
        }
    }
}