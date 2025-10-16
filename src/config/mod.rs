//! Application configuration

use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub webauthn: WebAuthnConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnConfig {
    pub rp_id: String,
    pub rp_name: String,
    pub rp_origin: String,
}

impl AppConfig {
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            server: ServerConfig {
                host: env::var("SERVER_HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
                port: env::var("SERVER_PORT")
                    .unwrap_or_else(|_| "8080".to_string())
                    .parse()?,
            },
            database: DatabaseConfig {
                url: env::var("DATABASE_URL")
                    .unwrap_or_else(|_| "postgres://localhost/fido2".to_string()),
                max_connections: env::var("DB_MAX_CONNECTIONS")
                    .unwrap_or_else(|_| "15".to_string())
                    .parse()?,
            },
            webauthn: WebAuthnConfig {
                rp_id: env::var("WEBAUTHN_RP_ID")
                    .unwrap_or_else(|_| "localhost".to_string()),
                rp_name: env::var("WEBAUTHN_RP_NAME")
                    .unwrap_or_else(|_| "FIDO2 Server".to_string()),
                rp_origin: env::var("WEBAUTHN_RP_ORIGIN")
                    .unwrap_or_else(|_| "http://localhost:8080".to_string()),
            },
        })
    }

    #[cfg(test)]
    pub fn test_config() -> Self {
        Self {
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 0,
            },
            database: DatabaseConfig {
                url: "postgres://localhost/fido2_test".to_string(),
                max_connections: 5,
            },
            webauthn: WebAuthnConfig {
                rp_id: "localhost".to_string(),
                rp_name: "Test FIDO2 Server".to_string(),
                rp_origin: "http://localhost:8080".to_string(),
            },
        }
    }
}