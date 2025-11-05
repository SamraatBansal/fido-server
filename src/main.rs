use axum::{
    routing::{get, post},
    Router,
};
use fido2_relying_party::{
    config::AppConfig,
    controllers::{
        attestation::{get_attestation_options, post_attestation_result, AppState as AttestationState},
        assertion::{get_assertion_options, post_assertion_result, AppState as AssertionState},
    },
    db::Database,
    db::repositories::{ChallengeRepository, CredentialRepository, UserRepository},
    middleware::{cors_layer, logging_layer, security_headers},
    services::{ChallengeService, CredentialService, UserService, WebAuthnService},
    AppError,
};
use std::sync::Arc;
use tokio::signal;
use tower::ServiceBuilder;
use tower_http::timeout::TimeoutLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Clone)]
pub struct AppState {
    pub webauthn_service: Arc<WebAuthnService>,
    pub user_service: Arc<UserService>,
    pub credential_service: Arc<CredentialService>,
    pub challenge_service: Arc<ChallengeService>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "fido2_relying_party=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load configuration
    let config = AppConfig::load()?;
    tracing::info!("Loaded configuration for RP: {}", config.webauthn.rp_name);

    // Initialize database
    let database = Database::new(&config.database).await?;
    tracing::info!("Database connected and migrations applied");

    // Initialize repositories
    let user_repo = UserRepository::new(database.pool().clone());
    let credential_repo = CredentialRepository::new(database.pool().clone());
    let challenge_repo = ChallengeRepository::new(database.pool().clone());

    // Initialize services
    let webauthn_service = Arc::new(WebAuthnService::new(&config.webauthn)?);
    let user_service = Arc::new(UserService::new(user_repo));
    let credential_service = Arc::new(CredentialService::new(credential_repo));
    let challenge_service = Arc::new(ChallengeService::new(challenge_repo, 5)); // 5 minute TTL

    // Create application state
    let app_state = AppState {
        webauthn_service: webauthn_service.clone(),
        user_service: user_service.clone(),
        credential_service: credential_service.clone(),
        challenge_service: challenge_service.clone(),
    };

    // Build the application router
    let app = Router::new()
        // Registration endpoints
        .route("/attestation/options", post(get_attestation_options))
        .route("/attestation/result", post(post_attestation_result))
        // Authentication endpoints
        .route("/assertion/options", post(get_assertion_options))
        .route("/assertion/result", post(post_assertion_result))
        // Health check
        .route("/health", get(health_check))
        // State
        .with_state(app_state)
        // Middleware layers
        .layer(
            ServiceBuilder::new()
                .layer(TimeoutLayer::new(std::time::Duration::from_secs(30)))
                .layer(cors_layer(&config.security))
                .layer(logging_layer())
                .map_response(security_headers),
        );

    // Start server
    let addr = format!("{}:{}", config.server.host, config.server.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("FIDO2 Relying Party server listening on {}", addr);

    // Start background cleanup task
    let cleanup_service = challenge_service.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300)); // 5 minutes
        loop {
            interval.tick().await;
            if let Err(e) = cleanup_service.cleanup_expired_challenges().await {
                tracing::error!("Failed to cleanup expired challenges: {}", e);
            }
        }
    });

    // Start server with graceful shutdown
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn health_check() -> Result<axum::Json<serde_json::Value>, AppError> {
    Ok(axum::Json(serde_json::json!({
        "status": "ok",
        "service": "fido2-relying-party",
        "timestamp": chrono::Utc::now().to_rfc3339()
    })))
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

    tracing::info!("Shutdown signal received, starting graceful shutdown");
}