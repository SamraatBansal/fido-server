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
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: "0.0.0.0".to_string(),
                port: 8080,
            },
            database: DatabaseConfig {
                url: "postgres://localhost/fido_server".to_string(),
                max_connections: 15,
            },
            webauthn: WebAuthnConfig {
                rp_name: "Example Corporation".to_string(),
                rp_id: "localhost".to_string(),
                rp_origin: "http://localhost:3000".to_string(),
            },
        }
    }
}

impl Config {
    pub fn from_env() -> Result<Self, config::ConfigError> {
        let settings = Config::default();
        
        // Override with environment variables
        let server_host = env::var("SERVER_HOST").ok();
        let server_port = env::var("SERVER_PORT").ok();
        let database_url = env::var("DATABASE_URL").ok();
        let webauthn_rp_name = env::var("WEBAUTHN_RP_NAME").ok();
        let webauthn_rp_id = env::var("WEBAUTHN_RP_ID").ok();
        let webauthn_rp_origin = env::var("WEBAUTHN_RP_ORIGIN").ok();

        Ok(Config {
            server: ServerConfig {
                host: server_host.unwrap_or_else(|| settings.server.host.clone()),
                port: server_port
                    .and_then(|p| p.parse().ok())
                    .unwrap_or(settings.server.port),
            },
            database: DatabaseConfig {
                url: database_url.unwrap_or_else(|| settings.database.url.clone()),
                max_connections: settings.database.max_connections,
            },
            webauthn: WebAuthnConfig {
                rp_name: webauthn_rp_name.unwrap_or_else(|| settings.webauthn.rp_name.clone()),
                rp_id: webauthn_rp_id.unwrap_or_else(|| settings.webauthn.rp_id.clone()),
                rp_origin: webauthn_rp_origin.unwrap_or_else(|| settings.webauthn.rp_origin.clone()),
            },
        })
    }
}