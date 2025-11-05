use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use url::Url;

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub webauthn: WebAuthnConfig,
    pub security: SecurityConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub shutdown_timeout: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub min_connections: u32,
    pub acquire_timeout_secs: u64,
    pub idle_timeout_secs: u64,
    pub max_lifetime_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WebAuthnConfig {
    pub rp_id: String,
    pub rp_name: String,
    pub rp_origin: Url,
    pub timeout_ms: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SecurityConfig {
    pub allowed_origins: Vec<String>,
    pub rate_limit: RateLimitConfig,
    pub cors_enabled: bool,
    pub strict_origin_validation: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RateLimitConfig {
    pub max_requests: u32,
    pub window_seconds: u64,
    pub burst_size: u32,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 3000,
                shutdown_timeout: 30,
            },
            database: DatabaseConfig {
                url: "postgresql://postgres:password@localhost/fido2_rp".to_string(),
                max_connections: 10,
                min_connections: 1,
                acquire_timeout_secs: 30,
                idle_timeout_secs: 600,
                max_lifetime_secs: 1800,
            },
            webauthn: WebAuthnConfig {
                rp_id: "localhost".to_string(),
                rp_name: "FIDO2 Relying Party".to_string(),
                rp_origin: Url::parse("http://localhost:3000").unwrap(),
                timeout_ms: 60000,
            },
            security: SecurityConfig {
                allowed_origins: vec![
                    "http://localhost:3000".to_string(),
                    "https://localhost:3000".to_string(),
                ],
                rate_limit: RateLimitConfig {
                    max_requests: 10,
                    window_seconds: 60,
                    burst_size: 20,
                },
                cors_enabled: true,
                strict_origin_validation: true,
            },
        }
    }
}

impl AppConfig {
    pub fn load() -> Result<Self, config::ConfigError> {
        dotenvy::dotenv().ok();

        let mut settings = config::Config::builder()
            .add_source(config::Environment::with_prefix("FIDO2").separator("__"));

        if std::env::var("FIDO2_CONFIG_FILE").is_ok() {
            let config_file = std::env::var("FIDO2_CONFIG_FILE").unwrap();
            settings = settings.add_source(config::File::with_name(&config_file));
        }

        let config = settings.build()?;
        let mut app_config: AppConfig = config.try_deserialize().unwrap_or_default();

        if let Ok(db_url) = std::env::var("DATABASE_URL") {
            app_config.database.url = db_url;
        }

        Ok(app_config)
    }

    pub fn allowed_origins_set(&self) -> HashSet<String> {
        self.security.allowed_origins.iter().cloned().collect()
    }
}