//! Application settings

use serde::{Deserialize, Serialize};

/// Application configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    /// Server configuration
    pub server: ServerConfig,
    /// WebAuthn configuration
    pub webauthn: WebAuthnConfig,
    /// Database configuration
    pub database: DatabaseConfig,
}

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Host to bind to
    pub host: String,
    /// Port to bind to
    pub port: u16,
}

/// WebAuthn configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnConfig {
    /// Relying Party ID
    pub rp_id: String,
    /// Relying Party origin
    pub rp_origin: String,
    /// Relying Party name
    pub rp_name: String,
}

/// Database configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    /// Database URL
    pub url: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 8080,
            },
            webauthn: WebAuthnConfig {
                rp_id: "localhost".to_string(),
                rp_origin: "http://localhost:8080".to_string(),
                rp_name: "FIDO Server".to_string(),
            },
            database: DatabaseConfig {
                url: "postgres://localhost/fido_server_test".to_string(),
            },
        }
    }
}

impl Settings {
    /// Load settings from environment and config files
    pub fn load() -> Result<Self, config::ConfigError> {
        let settings = config::Config::builder()
            .add_source(config::Environment::with_prefix("FIDO"))
            .build()?;

        let mut result: Settings = settings.try_deserialize().unwrap_or_default();
        
        // Override with environment variables if present
        if let Ok(host) = std::env::var("FIDO_SERVER_HOST") {
            result.server.host = host;
        }
        if let Ok(port) = std::env::var("FIDO_SERVER_PORT") {
            if let Ok(port) = port.parse() {
                result.server.port = port;
            }
        }
        if let Ok(rp_id) = std::env::var("FIDO_WEBAUTHN_RP_ID") {
            result.webauthn.rp_id = rp_id;
        }
        if let Ok(rp_origin) = std::env::var("FIDO_WEBAUTHN_RP_ORIGIN") {
            result.webauthn.rp_origin = rp_origin;
        }
        if let Ok(rp_name) = std::env::var("FIDO_WEBAUTHN_RP_NAME") {
            result.webauthn.rp_name = rp_name;
        }
        if let Ok(db_url) = std::env::var("FIDO_DATABASE_URL") {
            result.database.url = db_url;
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_settings() {
        let settings = Settings::default();
        assert_eq!(settings.server.host, "127.0.0.1");
        assert_eq!(settings.server.port, 8080);
        assert_eq!(settings.webauthn.rp_id, "localhost");
    }

    #[test]
    fn test_load_settings() {
        let settings = Settings::load();
        assert!(settings.is_ok());
    }
}