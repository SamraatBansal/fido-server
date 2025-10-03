use axum::Router;
use std::net::SocketAddr;
use tower_http::trace::TraceLayer;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod config;
mod error;
mod handlers;
mod models;
mod services;
mod storage;
mod webauthn;

use config::Config;
use error::AppError;

#[tokio::main]
async fn main() -> Result<(), AppError> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "fido_server=debug,tower_http=debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load configuration
    let config = Config::from_env()?;
    info!("Starting FIDO2/WebAuthn server on {}", config.server_addr);

    // Create WebAuthn instance
    let webauthn = webauthn::create_webauthn_instance(&config)?;

    // Create storage backend
    let storage = storage::create_storage(&config).await?;

    // Create services
    let auth_service = services::AuthService::new(webauthn, storage);
    let credential_service = services::CredentialService::new(storage.clone());
    let mapping_service = services::MappingService::new(storage);

    // Create router
    let app = Router::new()
        .nest("/registration", handlers::registration::routes(auth_service.clone()))
        .nest("/authentication", handlers::authentication::routes(auth_service.clone()))
        .nest("/credential", handlers::credential::routes(credential_service))
        .nest("/mapping", handlers::mapping::routes(mapping_service))
        .layer(TraceLayer::new_for_http())
        .layer(tower_http::cors::CorsLayer::permissive());

    // Start server
    let listener = tokio::net::TcpListener::bind(config.server_addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}