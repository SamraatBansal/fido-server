use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub webauthn: WebAuthnConfig,
    pub security: SecurityConfig,
    pub redis: RedisConfig,
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
    pub rp_origin: String,
    pub timeout: u32,
    pub attestation_preference: String,
    pub user_verification: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub session_timeout_seconds: u64,
    pub max_sessions_per_user: u32,
    pub rate_limit_requests_per_minute: u32,
    pub enable_csrf_protection: bool,
    pub enable_security_headers: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisConfig {
    pub url: String,
    pub pool_size: u32,
    pub session_prefix: String,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 8080,
                workers: None,
            },
            database: DatabaseConfig {
                url: "postgresql://localhost/fido_server".to_string(),
                max_connections: 15,
                min_connections: 5,
            },
            webauthn: WebAuthnConfig {
                rp_id: "localhost".to_string(),
                rp_name: "FIDO Server".to_string(),
                rp_origin: "http://localhost:8080".to_string(),
                timeout: 60000,
                attestation_preference: "direct".to_string(),
                user_verification: "preferred".to_string(),
            },
            security: SecurityConfig {
                session_timeout_seconds: 300,
                max_sessions_per_user: 5,
                rate_limit_requests_per_minute: 60,
                enable_csrf_protection: true,
                enable_security_headers: true,
            },
            redis: RedisConfig {
                url: "redis://localhost:6379".to_string(),
                pool_size: 10,
                session_prefix: "fido:".to_string(),
            },
        }
    }
}

impl AppConfig {
    pub fn from_env() -> Result<Self, config::ConfigError> {
        let mut settings = config::Config::default();
        
        // Start with default configuration
        settings.merge(config::Config::try_from(&AppConfig::default())?)?;
        
        // Override with environment variables
        settings.merge(config::Environment::with_prefix("FIDO"))?;
        
        settings.try_into()
    }

    pub fn load() -> Self {
        dotenv::dotenv().ok();
        
        match Self::from_env() {
            Ok(config) => config,
            Err(e) => {
                eprintln!("Failed to load configuration: {}", e);
                eprintln!("Using default configuration");
                AppConfig::default()
            }
        }
    }
}