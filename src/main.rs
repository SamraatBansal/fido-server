use axum::{
    routing::{get, post, delete},
    Router,
    response::Json,
    extract::State,
    http::StatusCode,
};
use std::sync::Arc;
use tower::ServiceBuilder;
use tower_http::{
    cors::CorsLayer,
    trace::TraceLayer,
    timeout::TimeoutLayer,
    compression::CompressionLayer,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use std::time::Duration;

mod config;
mod handlers;
mod models;
mod services;
mod storage;
mod security;
mod errors;

use config::AppConfig;
use errors::AppError;

/// Application state shared across handlers
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub webauthn_service: Arc<services::WebAuthnService>,
    pub storage: Arc<dyn storage::Storage>,
    pub challenge_service: Arc<services::ChallengeService>,
    pub origin_validator: Arc<security::OriginValidator>,
    pub rate_limiter: Arc<security::RateLimiter>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "fido2_relying_party=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer().json())
        .init();

    tracing::info!("Starting FIDO2/WebAuthn Relying Party Server");

    // Load configuration
    let config = Arc::new(AppConfig::load()?);
    tracing::info!("Configuration loaded successfully");

    // Initialize storage
    let storage = storage::create_storage(&config).await?;
    tracing::info!("Storage initialized");

    // Run database migrations
    storage.migrate().await?;
    tracing::info!("Database migrations completed");

    // Initialize services
    let webauthn_service = Arc::new(services::WebAuthnService::new(&config)?);
    let challenge_service = Arc::new(services::ChallengeService::new(storage.clone()));
    let origin_validator = Arc::new(security::OriginValidator::new(config.allowed_origins.clone())?);
    let rate_limiter = Arc::new(security::RateLimiter::new(config.rate_limit.clone()));

    // Create application state
    let app_state = AppState {
        config: config.clone(),
        webauthn_service,
        storage,
        challenge_service,
        origin_validator,
        rate_limiter,
    };

    // Build the application router
    let app = create_app(app_state);

    // Start the server
    let listener = tokio::net::TcpListener::bind(&config.server.bind_address).await?;
    tracing::info!("Server listening on {}", config.server.bind_address);

    axum::serve(listener, app).await?;

    Ok(())
}

fn create_app(state: AppState) -> Router {
    Router::new()
        // Health check endpoint
        .route("/health", get(health_check))
        
        // WebAuthn attestation (registration) endpoints
        .route(
            "/webauthn/attestation/options/:user_id",
            get(handlers::attestation::get_attestation_options),
        )
        .route(
            "/webauthn/attestation/result/:user_id",
            post(handlers::attestation::post_attestation_result),
        )
        
        // WebAuthn assertion (authentication) endpoints
        .route(
            "/webauthn/assertion/options/:user_id",
            get(handlers::assertion::get_assertion_options),
        )
        .route(
            "/webauthn/assertion/result/:user_id",
            post(handlers::assertion::post_assertion_result),
        )
        
        // Credential management endpoints
        .route(
            "/webauthn/credentials/:user_id",
            get(handlers::credentials::get_user_credentials),
        )
        .route(
            "/webauthn/credentials/:credential_id",
            delete(handlers::credentials::delete_credential),
        )
        
        // Apply middleware
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(CompressionLayer::new())
                .layer(TimeoutLayer::new(Duration::from_secs(30)))
                .layer(CorsLayer::permissive()) // Configure properly for production
                .layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    security::rate_limit_middleware,
                ))
                .layer(axum::middleware::from_fn_with_state(
                    state.clone(),
                    security::security_headers_middleware,
                )),
        )
        .with_state(state)
}

async fn health_check() -> Result<Json<serde_json::Value>, AppError> {
    Ok(Json(serde_json::json!({
        "status": "healthy",
        "timestamp": time::OffsetDateTime::now_utc(),
        "version": env!("CARGO_PKG_VERSION")
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum_test::TestServer;

    #[tokio::test]
    async fn test_health_check() {
        let config = Arc::new(AppConfig::default());
        let storage = Arc::new(storage::InMemoryStorage::new());
        let webauthn_service = Arc::new(services::WebAuthnService::new(&config).unwrap());
        let challenge_service = Arc::new(services::ChallengeService::new(storage.clone()));
        let origin_validator = Arc::new(security::OriginValidator::new(vec!["https://localhost:3000".to_string()]).unwrap());
        let rate_limiter = Arc::new(security::RateLimiter::new(Default::default()));

        let app_state = AppState {
            config,
            webauthn_service,
            storage,
            challenge_service,
            origin_validator,
            rate_limiter,
        };

        let app = create_app(app_state);
        let server = TestServer::new(app).unwrap();

        let response = server.get("/health").await;
        assert_eq!(response.status_code(), StatusCode::OK);

        let body: serde_json::Value = response.json();
        assert_eq!(body["status"], "healthy");
    }
}