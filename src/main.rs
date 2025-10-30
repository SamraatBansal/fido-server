use actix_web::{web, HttpRequest, HttpResponse, HttpServer, App, Result, middleware};
use actix_cors::Cors;
use std::sync::Arc;

mod config;
mod controllers;
mod db;
mod error;
mod middleware as app_middleware;
mod models;
mod repositories;
mod routes;
mod schema;
mod services;
mod utils;
mod dtos;

use controllers::WebAuthnController;
use services::{WebAuthnService, WebAuthnServiceImpl};
use repositories::{PostgresUserRepository, PostgresCredentialRepository, PostgresChallengeRepository};
use db::establish_connection_pool;
use error::AppError;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    // Initialize database connection pool
    let pool = establish_connection_pool()
        .expect("Failed to create database connection pool");
    
    // Run migrations
    db::run_migrations(&pool)
        .expect("Failed to run database migrations");

    let pool = Arc::new(pool);

    // Initialize repositories
    let user_repo = Arc::new(PostgresUserRepository::new(pool.clone()));
    let credential_repo = Arc::new(PostgresCredentialRepository::new(pool.clone()));
    let challenge_repo = Arc::new(PostgresChallengeRepository::new(pool.clone()));

    // Initialize WebAuthn service
    let webauthn_service = Arc::new(WebAuthnServiceImpl::new(
        user_repo.clone(),
        credential_repo.clone(),
        challenge_repo.clone(),
        "Example Corporation".to_string(),
        "localhost".to_string(),
        "http://localhost:3000".to_string(),
    ).expect("Failed to create WebAuthn service"));

    // Initialize controller
    let webauthn_controller = web::Data::new(WebAuthnController::new(webauthn_service.clone()));

    // Start HTTP server
    HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .max_age(3600);

        App::new()
            .app_data(webauthn_controller.clone())
            .wrap(cors)
            .wrap(middleware::Logger::default())
            .configure(|cfg| controllers::configure_standard_routes(cfg, webauthn_controller.clone()))
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await
}