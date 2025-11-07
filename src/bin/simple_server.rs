//! Simple FIDO Server with in-memory storage

use actix_cors::Cors;
use actix_web::{middleware::Logger, web, App, HttpServer, HttpResponse, Result, middleware::ErrorHandler, http::StatusCode};
use std::sync::Arc;

use fido_server::{
    config::Settings,
    services::SimpleWebAuthnService,
    schemas::{request::*, response::*},
    error::AppError,
};

pub struct SimpleAppState {
    pub webauthn_service: SimpleWebAuthnService,
}

// Registration endpoints
async fn begin_registration(
    data: web::Data<SimpleAppState>,
    req: web::Json<RegistrationBeginRequest>,
) -> Result<HttpResponse, AppError> {
    let webauthn_service = &data.webauthn_service;
    
    let response = webauthn_service
        .begin_registration(req.into_inner())
        .await?;
    
    Ok(HttpResponse::Ok().json(response))
}

async fn complete_registration(
    data: web::Data<SimpleAppState>,
    req: web::Json<RegistrationCompleteRequest>,
) -> Result<HttpResponse, AppError> {
    let webauthn_service = &data.webauthn_service;
    
    let response = webauthn_service
        .complete_registration(req.into_inner())
        .await?;
    
    Ok(HttpResponse::Ok().json(response))
}

// Authentication endpoints
async fn begin_authentication(
    data: web::Data<SimpleAppState>,
    req: web::Json<AuthenticationBeginRequest>,
) -> Result<HttpResponse, AppError> {
    let webauthn_service = &data.webauthn_service;
    
    let response = webauthn_service
        .begin_authentication(req.into_inner())
        .await?;
    
    Ok(HttpResponse::Ok().json(response))
}

async fn complete_authentication(
    data: web::Data<SimpleAppState>,
    req: web::Json<AuthenticationCompleteRequest>,
) -> Result<HttpResponse, AppError> {
    let webauthn_service = &data.webauthn_service;
    
    let response = webauthn_service
        .complete_authentication(req.into_inner())
        .await?;
    
    Ok(HttpResponse::Ok().json(response))
}

// Health check endpoint
async fn health_check() -> Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "ok",
        "service": "FIDO Simple Server",
        "version": "0.1.0"
    })))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize logger
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    log::info!("Starting Simple FIDO Server...");

    // Load configuration
    let settings = Settings::new().expect("Failed to load configuration");
    
    let host = &settings.server.host;
    let port = settings.server.port;

    // Initialize WebAuthn service
    let webauthn_service = SimpleWebAuthnService::new(&settings.webauthn)
        .expect("Failed to create WebAuthn service");

    log::info!("Server running at http://{}:{}", host, port);

    HttpServer::new(move || {
        // Configure CORS
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .max_age(3600);

        // Create application state
        let app_state = SimpleAppState {
            webauthn_service: webauthn_service.clone(),
        };

        App::new()
            .app_data(web::Data::new(app_state))
            .wrap(Logger::default())
            .wrap(cors)
            .route("/health", web::get().to(health_check))
            .route("/attestation/options", web::post().to(begin_registration))
            .route("/attestation/result", web::post().to(complete_registration))
            .route("/assertion/options", web::post().to(begin_authentication))
            .route("/assertion/result", web::post().to(complete_authentication))
    })
    .bind((host.as_str(), port))?
    .run()
    .await
}