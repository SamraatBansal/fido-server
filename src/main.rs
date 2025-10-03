use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use std::net::SocketAddr;
use tower_http::cors::CorsLayer;
use tracing::{info, error};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod auth;
mod config;
mod credential;
mod error;
mod mapping;
mod models;
mod storage;
mod webauthn;

use crate::config::Config;
use crate::error::AppError;
use crate::storage::Storage;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "fido_server=debug,tower_http=debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = Config::from_env()?;
    let storage = Storage::new(&config.database_url).await?;

    let app_state = AppState { storage };

    let app = Router::new()
        .route("/health", get(health_check))
        .nest("/registration", registration_routes())
        .nest("/authentication", authentication_routes())
        .nest("/credential", credential_routes())
        .nest("/mapping", mapping_routes())
        .layer(CorsLayer::permissive())
        .with_state(app_state);

    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    info!("Starting FIDO2 server on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

#[derive(Clone)]
struct AppState {
    storage: Storage,
}

async fn health_check() -> Result<Json<serde_json::Value>, AppError> {
    Ok(Json(serde_json::json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now()
    })))
}

fn registration_routes() -> Router<AppState> {
    Router::new()
        .route("/start", post(auth::registration_start))
        .route("/finish", post(auth::registration_finish))
}

fn authentication_routes() -> Router<AppState> {
    Router::new()
        .route("/start", post(auth::authentication_start))
        .route("/finish", post(auth::authentication_finish))
}

fn credential_routes() -> Router<AppState> {
    Router::new()
        .route("/:user_id", get(credential::list_credentials))
        .route("/revoke", post(credential::revoke_credential))
        .route("/update", post(credential::update_credential))
}

fn mapping_routes() -> Router<AppState> {
    Router::new()
        .route("/create", post(mapping::create_mapping))
        .route("/:id", get(mapping::get_mapping))
        .route("/:id", axum::routing::delete(mapping::delete_mapping))
        .route("/by-credential/:cred_id", get(mapping::get_mapping_by_credential))
}