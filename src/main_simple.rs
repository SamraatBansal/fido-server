use axum::{
    extract::State,
    http::HeaderMap,
    routing::post,
    Json, Router,
};
use fido2_relying_party::{
    config::AppConfig,
    error::{AppError, Result},
    middleware::{cors_layer, logging_layer, security_headers},
    schema::{
        ServerPublicKeyCredential, ServerPublicKeyCredentialCreationOptionsRequest,
        ServerPublicKeyCredentialCreationOptionsResponse, ServerPublicKeyCredentialGetOptionsRequest,
        ServerPublicKeyCredentialGetOptionsResponse, ServerResponse,
    },
    services::simple::SimpleWebAuthnService,
    storage::MemoryStore,
};
use std::sync::Arc;
use tokio::signal;
use tower::ServiceBuilder;
use tower_http::timeout::TimeoutLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Clone)]
pub struct AppState {
    pub webauthn_service: Arc<SimpleWebAuthnService>,
}

#[tokio::main]
async fn main() -> Result<Box<dyn std::error::Error>, Box<dyn std::error::Error>> {
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

    // Initialize memory store
    let store = Arc::new(MemoryStore::new());

    // Initialize WebAuthn service
    let webauthn_service = Arc::new(SimpleWebAuthnService::new(
        &config.webauthn.rp_id,
        &config.webauthn.rp_origin,
        &config.webauthn.rp_name,
        config.webauthn.timeout_ms,
        store.clone(),
    )?);

    // Create application state
    let app_state = AppState { webauthn_service };

    // Build the application router
    let app = Router::new()
        // Registration endpoints
        .route("/attestation/options", post(post_attestation_options))
        .route("/attestation/result", post(post_attestation_result))
        // Authentication endpoints
        .route("/assertion/options", post(post_assertion_options))
        .route("/assertion/result", post(post_assertion_result))
        // Health check
        .route("/health", axum::routing::get(health_check))
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
    let cleanup_store = store.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300)); // 5 minutes
        loop {
            interval.tick().await;
            let cleaned = cleanup_store.cleanup_expired_challenges();
            if cleaned > 0 {
                tracing::info!("Cleaned up {} expired challenges", cleaned);
            }
        }
    });

    // Start server with graceful shutdown
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn post_attestation_options(
    State(state): State<AppState>,
    _headers: HeaderMap,
    Json(request): Json<ServerPublicKeyCredentialCreationOptionsRequest>,
) -> Result<Json<ServerPublicKeyCredentialCreationOptionsResponse>> {
    let response = state.webauthn_service.handle_attestation_options(request).await?;
    Ok(Json(response))
}

async fn post_attestation_result(
    State(state): State<AppState>,
    _headers: HeaderMap,
    Json(credential): Json<ServerPublicKeyCredential>,
) -> Result<Json<ServerResponse>> {
    let response = state.webauthn_service.handle_attestation_result(credential).await?;
    Ok(Json(response))
}

async fn post_assertion_options(
    State(state): State<AppState>,
    _headers: HeaderMap,
    Json(request): Json<ServerPublicKeyCredentialGetOptionsRequest>,
) -> Result<Json<ServerPublicKeyCredentialGetOptionsResponse>> {
    let response = state.webauthn_service.handle_assertion_options(request).await?;
    Ok(Json(response))
}

async fn post_assertion_result(
    State(state): State<AppState>,
    _headers: HeaderMap,
    Json(credential): Json<ServerPublicKeyCredential>,
) -> Result<Json<ServerResponse>> {
    let response = state.webauthn_service.handle_assertion_result(credential).await?;
    Ok(Json(response))
}

async fn health_check() -> Result<Json<serde_json::Value>> {
    Ok(Json(serde_json::json!({
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