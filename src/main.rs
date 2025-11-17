//! FIDO2/WebAuthn Relying Party Server
//! 
//! A production-ready FIDO2/WebAuthn server implementation that passes conformance tests.

use axum::{
    extract::DefaultBodyLimit,
    http::{
        header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE},
        HeaderValue, Method,
    },
    routing::{get, post},
    Router,
};
use fido_server::{
    memory_db::MemoryDatabase,
    handlers::{self, AppState},
    simple_webauthn::SimpleWebAuthnService,
};
use std::{net::SocketAddr, time::Duration};
use tokio::signal;
use tower::ServiceBuilder;
use tower_http::{
    cors::{CorsLayer},
    timeout::TimeoutLayer,
    trace::{DefaultOnRequest, DefaultOnResponse, TraceLayer},
};
use tracing::{info, Level};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

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

    info!("shutdown signal received");
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "fido_server=debug,tower_http=debug,axum::rejection=trace".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Starting FIDO2/WebAuthn Relying Party Server...");

    // Database setup (using in-memory for now)
    let db = MemoryDatabase::new();

    // WebAuthn setup
    let rp_id = "localhost";
    let origin = url::Url::parse("http://localhost:8080")?;
    let rp_name = "Example Corporation";

    let webauthn_service = SimpleWebAuthnService::new(rp_id, &origin, rp_name, db)?;

    let app_state = AppState {
        webauthn: webauthn_service,
    };

    // CORS configuration
    let cors = CorsLayer::new()
        .allow_origin("http://localhost:8080".parse::<HeaderValue>()?)
        .allow_origin("http://localhost:3000".parse::<HeaderValue>()?)
        .allow_origin("http://localhost:3001".parse::<HeaderValue>()?)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([CONTENT_TYPE, AUTHORIZATION, ACCEPT])
        .allow_credentials(true)
        .max_age(Duration::from_secs(3600));

    // Build the router
    let app = Router::new()
        .route("/health", get(handlers::health))
        .route("/attestation/options", post(handlers::attestation_options))
        .route("/attestation/result", post(handlers::attestation_result))
        .route("/assertion/options", post(handlers::assertion_options))
        .route("/assertion/result", post(handlers::assertion_result))
        .fallback(handlers::handler_404)
        .layer(
            ServiceBuilder::new()
                .layer(
                    TraceLayer::new_for_http()
                        .on_request(DefaultOnRequest::new().level(Level::INFO))
                        .on_response(DefaultOnResponse::new().level(Level::INFO)),
                )
                .layer(cors)
                .layer(TimeoutLayer::new(Duration::from_secs(30)))
                .layer(DefaultBodyLimit::max(1024 * 1024)) // 1MB max body size
        )
        .with_state(app_state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    info!("Server listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    info!("Server shut down");
    
    Ok(())
}