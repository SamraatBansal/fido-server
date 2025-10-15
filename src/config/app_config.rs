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
    pub timeout: u32,
}

impl AppConfig {
    pub fn from_env() -> Result<Self, config::ConfigError> {
        let mut cfg = config::Config::builder();

        // Set defaults
        cfg = cfg
            .set_default("server.host", "127.0.0.1")?
            .set_default("server.port", 8080)?
            .set_default("database.max_connections", 10)?
            .set_default("webauthn.rp_name", "FIDO2 WebAuthn Server")?
            .set_default("webauthn.timeout", 60000)?;

        // Override with environment variables
        if let Ok(host) = env::var("SERVER_HOST") {
            cfg = cfg.set_override("server.host", host)?;
        }
        
        if let Ok(port) = env::var("SERVER_PORT") {
            cfg = cfg.set_override("server.port", port)?;
        }

        if let Ok(db_url) = env::var("DATABASE_URL") {
            cfg = cfg.set_override("database.url", db_url)?;
        } else {
            cfg = cfg.set_default("database.url", "postgres://localhost/fido2_webauthn")?;
        }

        if let Ok(rp_id) = env::var("WEBAUTHN_RP_ID") {
            cfg = cfg.set_override("webauthn.rp_id", rp_id)?;
        } else {
            cfg = cfg.set_default("webauthn.rp_id", "localhost")?;
        }

        if let Ok(rp_origin) = env::var("WEBAUTHN_RP_ORIGIN") {
            cfg = cfg.set_override("webauthn.rp_origin", rp_origin)?;
        } else {
            cfg = cfg.set_default("webauthn.rp_origin", "http://localhost:8080")?;
        }

        cfg.build()?.try_deserialize()
    }
}