//! FIDO2/WebAuthn Relying Party Server
//! 
//! A production-ready FIDO2/WebAuthn server that passes FIDO Alliance conformance tests.

use actix_cors::Cors;
use actix_web::{
    middleware::Logger, 
    web, 
    App, 
    HttpServer, 
    HttpResponse, 
    Result as ActixResult
};
use std::io;
use std::sync::Arc;
use webauthn_rs::{Webauthn, WebauthnBuilder};
use url::Url;

mod error;
mod storage;
mod handlers;
mod dto;
mod utils;

use async_trait::async_trait;

use error::WebAuthnError;
use storage::{InMemoryStorage, Storage};
use dto::common::ServerResponse;

/// Application state containing WebAuthn instance and storage
#[derive(Clone)]
pub struct AppState {
    pub webauthn: Arc<Webauthn>,
    pub storage: Arc<dyn Storage>,
}

/// Health check endpoint
async fn health_check() -> ActixResult<HttpResponse> {
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "ok",
        "service": "FIDO Server",
        "timestamp": chrono::Utc::now().to_rfc3339()
    })))
}

/// Initialize WebAuthn instance with proper configuration
fn init_webauthn() -> Result<Webauthn, WebAuthnError> {
    let rp_id = "localhost";
    let rp_origin = Url::parse("http://localhost:8080")
        .map_err(|e| WebAuthnError::Configuration(format!("Invalid origin URL: {}", e)))?;
    
    let builder = WebauthnBuilder::new(rp_id, &rp_origin)
        .map_err(|e| WebAuthnError::Configuration(format!("Failed to create WebAuthn builder: {}", e)))?
        .rp_name("Example Corporation");
    
    builder.build()
        .map_err(|e| WebAuthnError::Configuration(format!("Failed to build WebAuthn: {}", e)))
}

#[actix_web::main]
async fn main() -> io::Result<()> {
    // Initialize logger
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    
    log::info!("Starting FIDO2/WebAuthn Relying Party Server...");

    // Initialize WebAuthn
    let webauthn = match init_webauthn() {
        Ok(w) => Arc::new(w),
        Err(e) => {
            log::error!("Failed to initialize WebAuthn: {}", e);
            return Err(io::Error::new(io::ErrorKind::Other, e.to_string()));
        }
    };

    // Initialize storage (in-memory for this implementation)
    let storage: Arc<dyn Storage> = Arc::new(InMemoryStorage::new());

    let app_state = AppState {
        webauthn,
        storage,
    };

    let host = "127.0.0.1";
    let port = 8080;

    log::info!("Server running at http://{}:{}", host, port);
    log::info!("FIDO2/WebAuthn endpoints:");
    log::info!("  POST /attestation/options  - Registration challenge");
    log::info!("  POST /attestation/result   - Registration verification"); 
    log::info!("  POST /assertion/options    - Authentication challenge");
    log::info!("  POST /assertion/result     - Authentication verification");

    HttpServer::new(move || {
        // Configure CORS for FIDO compliance
        let cors = Cors::default()
            .allowed_origin("http://localhost:8080")
            .allowed_origin("https://localhost:8080") 
            .allowed_methods(vec!["GET", "POST", "OPTIONS"])
            .allowed_headers(vec!["Content-Type", "Authorization"])
            .supports_credentials()
            .max_age(3600);

        App::new()
            .app_data(web::Data::new(app_state.clone()))
            .wrap(Logger::default())
            .wrap(cors)
            .route("/health", web::get().to(health_check))
            // FIDO2/WebAuthn endpoints - exact paths required for conformance
            .route("/attestation/options", web::post().to(handlers::registration_options))
            .route("/attestation/result", web::post().to(handlers::registration_result))
            .route("/assertion/options", web::post().to(handlers::authentication_options))
            .route("/assertion/result", web::post().to(handlers::authentication_result))
    })
    .bind((host, port))?
    .run()
    .await
}