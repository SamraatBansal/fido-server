use anyhow::Result;
use axum::{
    http::{header, Method, StatusCode},
    response::Json,
    routing::{get, post},
    Router,
};
use serde_json::{json, Value};
use std::net::SocketAddr;
use tower::ServiceBuilder;
use tower_http::{
    cors::{Any, CorsLayer},
    limit::RequestBodyLimitLayer,
    timeout::TimeoutLayer,
    trace::TraceLayer,
};
use tracing::{info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod api;
mod error;
mod models;
mod security;
mod storage;
mod webauthn;

use crate::{
    api::{authentication, registration},
    storage::{postgres::PostgresStorage, traits::Storage, memory::MemoryStorage},
    webauthn::config::WebAuthnConfig,
};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "fido_server3=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Starting FIDO Server3 - WebAuthn Relying Party Server");

    // Load configuration
    let config = load_config()?;
    
    // Initialize storage
    let storage: Box<dyn Storage> = if config.use_postgres {
        info!("Initializing PostgreSQL storage");
        Box::new(PostgresStorage::new(&config.database_url).await?)
    } else {
        warn!("Using in-memory storage - not suitable for production!");
        Box::new(MemoryStorage::new())
    };

    // Initialize WebAuthn configuration
    let webauthn_config = WebAuthnConfig::new(
        &config.rp_id,
        &config.rp_name,
        &config.rp_origin,
    )?;

    // Create application state
    let app_state = AppState {
        storage,
        webauthn_config,
        config: config.clone(),
    };

    // Build the application router
    let app = create_router(app_state);

    // Start the server
    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    info!("Server listening on {}", addr);
    
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

#[derive(Clone)]
pub struct AppState {
    pub storage: Box<dyn Storage>,
    pub webauthn_config: WebAuthnConfig,
    pub config: Config,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub port: u16,
    pub rp_id: String,
    pub rp_name: String,
    pub rp_origin: String,
    pub database_url: String,
    pub use_postgres: bool,
    pub challenge_timeout_seconds: u64,
    pub max_credentials_per_user: usize,
}

fn create_router(state: AppState) -> Router {
    Router::new()
        // Health check endpoint
        .route("/health", get(health_check))
        
        // WebAuthn registration endpoints
        .route("/webauthn/register/begin", post(registration::begin_registration))
        .route("/webauthn/register/complete", post(registration::complete_registration))
        
        // WebAuthn authentication endpoints
        .route("/webauthn/authenticate/begin", post(authentication::begin_authentication))
        .route("/webauthn/authenticate/complete", post(authentication::complete_authentication))
        
        // User management endpoints
        .route("/users/:username/credentials", get(api::get_user_credentials))
        .route("/users/:username/credentials/:credential_id", post(api::delete_credential))
        
        // Add middleware
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(TimeoutLayer::new(std::time::Duration::from_secs(30)))
                .layer(RequestBodyLimitLayer::new(1024 * 1024)) // 1MB limit
                .layer(
                    CorsLayer::new()
                        .allow_origin(Any)
                        .allow_methods([Method::GET, Method::POST, Method::DELETE])
                        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
                        .max_age(std::time::Duration::from_secs(3600))
                )
        )
        .with_state(state)
}

async fn health_check() -> Result<Json<Value>, StatusCode> {
    Ok(Json(json!({
        "status": "healthy",
        "service": "FIDO Server3",
        "version": env!("CARGO_PKG_VERSION"),
        "timestamp": chrono::Utc::now().to_rfc3339()
    })))
}

fn load_config() -> Result<Config> {
    dotenvy::dotenv().ok();
    
    Ok(Config {
        port: std::env::var("PORT")
            .unwrap_or_else(|_| "3000".to_string())
            .parse()?,
        rp_id: std::env::var("RP_ID")
            .unwrap_or_else(|_| "localhost".to_string()),
        rp_name: std::env::var("RP_NAME")
            .unwrap_or_else(|_| "FIDO Server3".to_string()),
        rp_origin: std::env::var("RP_ORIGIN")
            .unwrap_or_else(|_| "https://localhost:3000".to_string()),
        database_url: std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://localhost/fido_server3".to_string()),
        use_postgres: std::env::var("USE_POSTGRES")
            .unwrap_or_else(|_| "false".to_string())
            .parse()
            .unwrap_or(false),
        challenge_timeout_seconds: std::env::var("CHALLENGE_TIMEOUT_SECONDS")
            .unwrap_or_else(|_| "300".to_string())
            .parse()
            .unwrap_or(300),
        max_credentials_per_user: std::env::var("MAX_CREDENTIALS_PER_USER")
            .unwrap_or_else(|_| "10".to_string())
            .parse()
            .unwrap_or(10),
    })
}