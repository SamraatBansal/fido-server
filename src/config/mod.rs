//! Configuration management for the FIDO Server

use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
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
    pub rp_name: String,
    pub rp_id: String,
    pub rp_origin: String,
    pub timeout: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: env::var("FIDO_SERVER_HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
                port: env::var("FIDO_SERVER_PORT")
                    .unwrap_or_else(|_| "8080".to_string())
                    .parse()
                    .unwrap_or(8080),
            },
            database: DatabaseConfig {
                url: env::var("DATABASE_URL")
                    .unwrap_or_else(|_| "postgres://localhost/fido_server".to_string()),
                max_connections: env::var("DB_MAX_CONNECTIONS")
                    .unwrap_or_else(|_| "10".to_string())
                    .parse()
                    .unwrap_or(10),
            },
            webauthn: WebAuthnConfig {
                rp_name: env::var("RP_NAME").unwrap_or_else(|_| "Example Corporation".to_string()),
                rp_id: env::var("RP_ID").unwrap_or_else(|_| "localhost".to_string()),
                rp_origin: env::var("RP_ORIGIN")
                    .unwrap_or_else(|_| "http://localhost:8080".to_string()),
                timeout: env::var("WEBAUTHN_TIMEOUT")
                    .unwrap_or_else(|_| "60000".to_string())
                    .parse()
                    .unwrap_or(60000),
            },
        }
    }
}

impl Config {
    pub fn from_env() -> Self {
        Self::default()
    }
}