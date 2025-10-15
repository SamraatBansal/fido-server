use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub webauthn: WebAuthnConfig,
    pub database: DatabaseConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub cors_origins: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnConfig {
    pub rp_name: String,
    pub rp_id: String,
    pub rp_origin: String,
    pub challenge_timeout_ms: u64,
    pub default_timeout_ms: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 8080,
                cors_origins: vec!["http://localhost:3000".to_string()],
            },
            webauthn: WebAuthnConfig {
                rp_name: "Example Corporation".to_string(),
                rp_id: "example.com".to_string(),
                rp_origin: "http://localhost:3000".to_string(),
                challenge_timeout_ms: 300000, // 5 minutes
                default_timeout_ms: 60000,    // 1 minute
            },
            database: DatabaseConfig {
                url: "postgres://postgres:password@localhost/fido2_test".to_string(),
                max_connections: 10,
            },
        }
    }
}

impl AppConfig {
    pub fn from_env() -> Self {
        // In a real implementation, this would read from environment variables
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AppConfig::default();
        
        assert_eq!(config.server.host, "127.0.0.1");
        assert_eq!(config.server.port, 8080);
        assert_eq!(config.webauthn.rp_name, "Example Corporation");
        assert_eq!(config.webauthn.rp_id, "example.com");
        assert_eq!(config.webauthn.challenge_timeout_ms, 300000);
    }

    #[test]
    fn test_from_env() {
        let config = AppConfig::from_env();
        
        // Should return default config for now
        assert_eq!(config.server.host, "127.0.0.1");
        assert_eq!(config.webauthn.rp_name, "Example Corporation");
    }
}