use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde_json::Value;
use std::net::SocketAddr;
use tower_http::trace::TraceLayer;
use tracing::{info, Level};
use tracing_subscriber;

mod auth;
mod config;
mod credential;
mod error;
mod mapping;
mod storage;
mod webauthn;

use fido_server::{AppState, Config, AppError};
use storage::Storage;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .init();

    let config = Config::from_env()?;
    let storage = Storage::new(&config.database_url).await?;

    let app_state = AppState { storage, config };

    let app = Router::new()
        .route("/health", get(health_check))
        .nest("/registration", registration_routes())
        .nest("/authentication", authentication_routes())
        .nest("/credential", credential_routes())
        .nest("/mapping", mapping_routes())
        .layer(TraceLayer::new_for_http())
        .with_state(app_state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    info!("Starting FIDO2 server on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}



async fn health_check() -> Result<Json<Value>, AppError> {
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