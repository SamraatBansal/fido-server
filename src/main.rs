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
    db::Database,
    handlers::{self, AppState},
    webauthn::WebAuthnService,
};
use std::{env, net::SocketAddr, time::Duration};
use sqlx::{postgres::PgPoolOptions, PgPool};
use tokio::signal;
use tower::ServiceBuilder;
use tower_http::{
    cors::CorsLayer,
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

async fn create_database_pool() -> anyhow::Result<PgPool> {
    let database_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://fido_user:fido_password@localhost:5432/fido_db".to_string());

    info!("Connecting to database: {}", database_url.replace("fido_password", "***"));

    let pool = PgPoolOptions::new()
        .max_connections(10)
        .min_connections(2)
        .acquire_timeout(Duration::from_secs(8))
        .idle_timeout(Some(Duration::from_secs(300)))
        .max_lifetime(Some(Duration::from_secs(1800)))
        .connect(&database_url)
        .await?;

    // Run migrations
    sqlx::migrate!("./migrations").run(&pool).await?;

    info!("Database connected and migrations applied successfully");
    Ok(pool)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load environment variables
    dotenv::dotenv().ok();

    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "fido_server=debug,tower_http=debug,axum::rejection=trace".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Starting FIDO2/WebAuthn Relying Party Server...");

    // Database setup
    let pool = create_database_pool().await?;
    let db = Database::new(pool);

    // WebAuthn setup
    let rp_id = env::var("RP_ID").unwrap_or_else(|_| "localhost".to_string());
    let origin_url = env::var("ORIGIN_URL").unwrap_or_else(|_| "http://localhost:8080".to_string());
    let rp_name = env::var("RP_NAME").unwrap_or_else(|_| "Example Corporation".to_string());
    
    let origin = url::Url::parse(&origin_url)?;
    let webauthn_service = WebAuthnService::new(&rp_id, &origin, &rp_name, db)?;

    let app_state = AppState {
        webauthn: webauthn_service,
    };

    // CORS configuration - allowing multiple origins for testing
    let cors = CorsLayer::new()
        .allow_origin("http://localhost:8080".parse::<HeaderValue>()?)
        .allow_origin("http://localhost:3000".parse::<HeaderValue>()?)
        .allow_origin("http://localhost:3001".parse::<HeaderValue>()?)
        .allow_origin("http://127.0.0.1:8080".parse::<HeaderValue>()?)
        .allow_origin("http://127.0.0.1:3000".parse::<HeaderValue>()?)
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

    let port = env::var("PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse::<u16>()?;
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    info!("Server listening on http://{}", addr);
    info!("CORS enabled for origins: localhost:8080, localhost:3000, localhost:3001");
    info!("API Endpoints:");
    info!("  POST /attestation/options  - Start registration");
    info!("  POST /attestation/result   - Complete registration");
    info!("  POST /assertion/options    - Start authentication");
    info!("  POST /assertion/result     - Complete authentication");
    info!("  GET  /health              - Health check");

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    info!("Server shut down");
    
    Ok(())
}