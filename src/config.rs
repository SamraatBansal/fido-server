use serde::Deserialize;
use std::env;
use url::Url;
use webauthn_rs::prelude::*;

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub database_url: String,
    pub server_host: String,
    pub server_port: u16,
    pub webauthn: WebAuthnConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WebAuthnConfig {
    pub rp_id: String,
    pub rp_name: String,
    pub rp_origin: String,
}

impl AppConfig {
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        dotenvy::dotenv().ok();
        
        let database_url = env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://fido_user:fido_password@localhost/fido_db".to_string());
        
        let server_host = env::var("SERVER_HOST")
            .unwrap_or_else(|_| "127.0.0.1".to_string());
        
        let server_port = env::var("SERVER_PORT")
            .unwrap_or_else(|_| "8080".to_string())
            .parse()
            .unwrap_or(8080);
        
        let rp_id = env::var("WEBAUTHN_RP_ID")
            .unwrap_or_else(|_| "localhost".to_string());
        
        let rp_name = env::var("WEBAUTHN_RP_NAME")
            .unwrap_or_else(|_| "FIDO2 Test Server".to_string());
        
        let rp_origin = env::var("WEBAUTHN_RP_ORIGIN")
            .unwrap_or_else(|_| "http://localhost:8080".to_string());
        
        Ok(AppConfig {
            database_url,
            server_host,
            server_port,
            webauthn: WebAuthnConfig {
                rp_id,
                rp_name,
                rp_origin,
            },
        })
    }
}

impl WebAuthnConfig {
    pub fn build_webauthn(&self) -> Result<Webauthn, WebauthnError> {
        let rp_origin = Url::parse(&self.rp_origin)
            .map_err(|e| WebauthnError::Configuration(format!("Invalid RP origin: {}", e)))?;
        
        WebauthnBuilder::new(&self.rp_id, &rp_origin)?
            .rp_name(&self.rp_name)
            .build()
    }
}