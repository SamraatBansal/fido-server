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
        let mut settings = config::Config::default();
        
        // Start with default configuration
        settings.merge(config::Config::try_from(&Config::default())?)?;
        
        // Override with environment variables
        if let Ok(host) = env::var("SERVER_HOST") {
            settings.set("server.host", host)?;
        }
        
        if let Ok(port) = env::var("SERVER_PORT") {
            settings.set("server.port", port.parse::<u16>().unwrap_or(8080))?;
        }
        
        if let Ok(database_url) = env::var("DATABASE_URL") {
            settings.set("database.url", database_url)?;
        }
        
        if let Ok(rp_name) = env::var("WEBAUTHN_RP_NAME") {
            settings.set("webauthn.rp_name", rp_name)?;
        }
        
        if let Ok(rp_id) = env::var("WEBAUTHN_RP_ID") {
            settings.set("webauthn.rp_id", rp_id)?;
        }
        
        if let Ok(rp_origin) = env::var("WEBAUTHN_RP_ORIGIN") {
            settings.set("webauthn.rp_origin", rp_origin)?;
        }
        
        settings.try_into()
    }
}