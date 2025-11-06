//! Simple FIDO Server Main Entry Point (without database)

use actix_cors::Cors;
use actix_web::{middleware::Logger, web, App, HttpServer, HttpResponse, Result as ActixResult};
use serde_json::json;
use std::io;

use fido_server::dto::*;

/// Health check endpoint
async fn health_check() -> ActixResult<HttpResponse> {
    Ok(HttpResponse::Ok().json(json!({
        "status": "ok",
        "service": "FIDO Server",
        "timestamp": chrono::Utc::now().to_rfc3339()
    })))
}

/// Dummy registration options endpoint
async fn registration_options(
    request: web::Json<ServerPublicKeyCredentialCreationOptionsRequest>,
) -> ActixResult<HttpResponse> {
    let response = ServerPublicKeyCredentialCreationOptionsResponse {
        server_response: ServerResponse::ok(),
        rp: fido_server::dto::registration::PublicKeyCredentialRpEntity {
            id: Some("localhost".to_string()),
            name: "Example Corporation".to_string(),
        },
        user: ServerPublicKeyCredentialUserEntity {
            id: "U3932ee31vKEC0JtJMIQ".to_string(),
            name: request.username.clone(),
            display_name: request.display_name.clone(),
        },
        challenge: "uhUjPNlZfvn7onwuhNdsLPkkE5Fv-lUN".to_string(),
        pub_key_cred_params: vec![
            fido_server::dto::registration::PublicKeyCredentialParameters {
                type_: "public-key".to_string(),
                alg: -7,
            }
        ],
        timeout: Some(10000),
        exclude_credentials: vec![],
        authenticator_selection: request.authenticator_selection.clone(),
        attestation: request.attestation.clone(),
        extensions: None,
    };

    Ok(HttpResponse::Ok().json(response))
}

/// Dummy registration result endpoint
async fn registration_result(
    _request: web::Json<RegistrationResultRequest>,
) -> ActixResult<HttpResponse> {
    Ok(HttpResponse::Ok().json(ServerResponse::ok()))
}

/// Dummy authentication options endpoint
async fn authentication_options(
    request: web::Json<ServerPublicKeyCredentialGetOptionsRequest>,
) -> ActixResult<HttpResponse> {
    let response = ServerPublicKeyCredentialGetOptionsResponse {
        server_response: ServerResponse::ok(),
        challenge: "6283u0svT-YIF3pSolzkQHStwkJCaLKx".to_string(),
        timeout: Some(20000),
        rp_id: Some("localhost".to_string()),
        allow_credentials: vec![],
        user_verification: request.user_verification.clone(),
        extensions: None,
    };

    Ok(HttpResponse::Ok().json(response))
}

/// Dummy authentication result endpoint
async fn authentication_result(
    _request: web::Json<AuthenticationResultRequest>,
) -> ActixResult<HttpResponse> {
    Ok(HttpResponse::Ok().json(ServerResponse::ok()))
}

#[actix_web::main]
async fn main() -> io::Result<()> {
    // Initialize logger
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    
    log::info!("Starting FIDO Server in demo mode (no database)...");

    let host = "127.0.0.1";
    let port = 8080;

    log::info!("Server running at http://{}:{}", host, port);

    HttpServer::new(move || {
        // Configure CORS
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .supports_credentials()
            .max_age(3600);

        App::new()
            .wrap(Logger::default())
            .wrap(cors)
            .route("/health", web::get().to(health_check))
            .route("/attestation/options", web::post().to(registration_options))
            .route("/attestation/result", web::post().to(registration_result))
            .route("/assertion/options", web::post().to(authentication_options))
            .route("/assertion/result", web::post().to(authentication_result))
    })
    .bind((host, port))?
    .run()
    .await
}