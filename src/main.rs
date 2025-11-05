use axum::{
    response::{IntoResponse, Json},
    routing::post,
    Router,
};
use chrono::Utc;
use std::sync::Arc;
use tokio::signal;
use tower_http::cors::CorsLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod config;
mod error;
mod handlers;
mod models;
mod services;
mod storage;

use config::AppConfig;
use error::AppResult;
use handlers::{attestation, assertion};
use services::{challenge::ChallengeService, credential::CredentialService, user::UserService, webauthn::WebAuthnService};
use storage::memory::MemoryStorage;

#[derive(Clone)]
pub struct AppState {
    pub webauthn_service: Arc<WebAuthnService>,
    pub user_service: Arc<UserService>,
    pub credential_service: Arc<CredentialService>,
    pub challenge_service: Arc<ChallengeService>,
}

async fn health_check() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ok",
        "timestamp": Utc::now().to_rfc3339()
    }))
}

#[tokio::main]
async fn main() -> AppResult<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "fido2_minimal=debug,tower_http=debug,webauthn_rs=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load configuration
    let config = AppConfig::load()?;
    tracing::info!("Starting FIDO2 WebAuthn Relying Party server on port {}", config.server.port);

    // Initialize storage (using in-memory for now, can be swapped for PostgreSQL)
    let storage = Arc::new(MemoryStorage::new());

    // Initialize services
    let webauthn_service = Arc::new(WebAuthnService::new(&config)?);
    let user_service = Arc::new(UserService::new(storage.clone()));
    let credential_service = Arc::new(CredentialService::new(storage.clone()));
    let challenge_service = Arc::new(ChallengeService::new(storage.clone()));

    let app_state = AppState {
        webauthn_service,
        user_service,
        credential_service,
        challenge_service,
    };

    // Build application
    let app = Router::new()
        .route("/health", axum::routing::get(health_check))
        .route("/attestation/options", post(attestation::options))
        .route("/attestation/result", post(attestation::result))
        .route("/assertion/options", post(assertion::options))
        .route("/assertion/result", post(assertion::result))
        .layer(CorsLayer::permissive())
        .with_state(app_state);

    // Start server
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", config.server.port))
        .await?;
    
    tracing::info!("Server listening on http://0.0.0.0:{}", config.server.port);
    
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    tracing::info!("Shutdown signal received");
}