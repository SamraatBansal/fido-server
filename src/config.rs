use serde::{Deserialize, Serialize};
use std::env;
use url::Url;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub webauthn: WebAuthnConfig,
    pub security: SecurityConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    pub port: u16,
    pub host: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WebAuthnConfig {
    pub rp_id: String,
    pub rp_name: String,
    pub rp_origin: Url,
    pub timeout_ms: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecurityConfig {
    pub challenge_timeout_minutes: i64,
    pub max_credentials_per_user: usize,
}

impl AppConfig {
    pub fn load() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let port = env::var("PORT")
            .unwrap_or_else(|_| "3000".to_string())
            .parse()?;
        
        let host = env::var("HOST")
            .unwrap_or_else(|_| "localhost".to_string());
        
        let rp_id = env::var("RP_ID")
            .unwrap_or_else(|_| "localhost".to_string());
        
        let rp_name = env::var("RP_NAME")
            .unwrap_or_else(|_| "FIDO2 WebAuthn Demo".to_string());
        
        let origin = env::var("RP_ORIGIN")
            .unwrap_or_else(|_| format!("http://{}:{}", host, port));
        
        let rp_origin = Url::parse(&origin)?;

        Ok(Self {
            server: ServerConfig { port, host },
            webauthn: WebAuthnConfig {
                rp_id,
                rp_name,
                rp_origin,
                timeout_ms: 60000, // 60 seconds
            },
            security: SecurityConfig {
                challenge_timeout_minutes: 5,
                max_credentials_per_user: 10,
            },
        })
    }
}