use serde::{Deserialize, Serialize};
use std::env;
use url::Url;
use webauthn_rs::prelude::*;

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
    pub workers: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub min_connections: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnConfig {
    pub rp_id: String,
    pub rp_name: String,
    pub rp_origin: Url,
    pub challenge_timeout_ms: u32,
}

impl AppConfig {
    pub fn from_env() -> Result<Self, config::ConfigError> {
        let mut settings = config::Config::builder();

        // Load from environment variables
        settings = settings
            .add_source(config::Environment::with_prefix("FIDO_SERVER").separator("__"))
            .add_source(config::File::with_name("config/default").required(false))
            .add_source(config::File::with_name("config/local").required(false));

        let config = settings.build()?;
        
        let app_config: AppConfig = config.try_deserialize()?;
        Ok(app_config)
    }

    pub fn test_config() -> Self {
        Self {
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 8080,
                workers: Some(1),
            },
            database: DatabaseConfig {
                url: env::var("TEST_DATABASE_URL")
                    .unwrap_or_else(|_| "postgres://test:test@localhost/fido_test".to_string()),
                max_connections: 5,
                min_connections: 1,
            },
            webauthn: WebAuthnConfig {
                rp_id: "localhost".to_string(),
                rp_name: "FIDO Test Server".to_string(),
                rp_origin: Url::parse("http://localhost:3000").unwrap(),
                challenge_timeout_ms: 300000, // 5 minutes
            },
        }
    }

    pub fn default_config() -> Self {
        Self {
            server: ServerConfig {
                host: env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
                port: env::var("PORT")
                    .unwrap_or_else(|_| "8080".to_string())
                    .parse()
                    .unwrap_or(8080),
                workers: env::var("WORKERS")
                    .ok()
                    .and_then(|w| w.parse().ok()),
            },
            database: DatabaseConfig {
                url: env::var("DATABASE_URL")
                    .unwrap_or_else(|_| "postgres://fido:fido@localhost/fido_server".to_string()),
                max_connections: env::var("DB_MAX_CONNECTIONS")
                    .unwrap_or_else(|_| "10".to_string())
                    .parse()
                    .unwrap_or(10),
                min_connections: env::var("DB_MIN_CONNECTIONS")
                    .unwrap_or_else(|_| "1".to_string())
                    .parse()
                    .unwrap_or(1),
            },
            webauthn: WebAuthnConfig {
                rp_id: env::var("RP_ID").unwrap_or_else(|_| "localhost".to_string()),
                rp_name: env::var("RP_NAME").unwrap_or_else(|_| "FIDO Server".to_string()),
                rp_origin: env::var("RP_ORIGIN")
                    .unwrap_or_else(|_| "http://localhost:3000".to_string())
                    .parse()
                    .expect("Invalid RP_ORIGIN URL"),
                challenge_timeout_ms: env::var("CHALLENGE_TIMEOUT_MS")
                    .unwrap_or_else(|_| "300000".to_string())
                    .parse()
                    .unwrap_or(300000),
            },
        }
    }

    pub fn create_webauthn(&self) -> Result<Webauthn, webauthn_rs::error::WebauthnError> {
        WebauthnBuilder::new(&self.webauthn.rp_id, &self.webauthn.rp_origin)?
            .rp_name(&self.webauthn.rp_name)
            .build()
    }
}