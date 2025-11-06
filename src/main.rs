use actix_cors::Cors;
use actix_web::{middleware::Logger, web, App, HttpServer};
use std::env;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use fido2_webauthn_server::conformance_service::ConformanceWebAuthnService;
use fido2_webauthn_server::conformance_handlers::*;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load environment variables
    dotenv::dotenv().ok();

    // Initialize WebAuthn service with memory storage
    let rp_id = env::var("RP_ID").unwrap_or_else(|_| "localhost".to_string());
    let rp_name = env::var("RP_NAME").unwrap_or_else(|_| "FIDO2 WebAuthn Server".to_string());
    let rp_origin = env::var("RP_ORIGIN").unwrap_or_else(|_| "http://localhost:8080".to_string());

    let webauthn_service = match ConformanceWebAuthnService::new(&rp_id, &rp_name, &rp_origin) {
        Ok(service) => service,
        Err(e) => {
            tracing::error!("Failed to initialize WebAuthn service: {}", e);
            std::process::exit(1);
        }
    };

    let bind_address = env::var("BIND_ADDRESS").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    
    tracing::info!("Starting FIDO2 WebAuthn server on {}", bind_address);
    tracing::info!("RP ID: {}", rp_id);
    tracing::info!("RP Origin: {}", rp_origin);
    tracing::info!("Using in-memory storage - no database required");

    HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .supports_credentials();

        // Configure JSON error handling for FIDO conformance
        let json_config = web::JsonConfig::default()
            .limit(4096)
            .error_handler(|err, _req| {
                let error_message = if err.to_string().contains("missing field") {
                    let err_str = err.to_string();
                    if let Some(start) = err_str.find("missing field `") {
                        if let Some(end) = err_str[start + 15..].find("`") {
                            let field_name = &err_str[start + 15..start + 15 + end];
                            format!("Missing required field: {}", field_name)
                        } else {
                            "Missing required field".to_string()
                        }
                    } else {
                        "Missing required field".to_string()
                    }
                } else {
                    "Invalid JSON format".to_string()
                };

                let response = actix_web::HttpResponse::BadRequest().json(
                    serde_json::json!({
                        "status": "failed",
                        "errorMessage": error_message
                    })
                );
                actix_web::error::InternalError::from_response(err, response).into()
            });

        App::new()
            .app_data(web::Data::new(webauthn_service.clone()))
            .app_data(json_config)
            .wrap(cors)
            .wrap(Logger::default())
            .service(
                web::scope("/attestation")
                    .route("/options", web::post().to(start_registration))
                    .route("/result", web::post().to(finish_registration)),
            )
            .service(
                web::scope("/assertion")
                    .route("/options", web::post().to(start_authentication))
                    .route("/result", web::post().to(finish_authentication)),
            )
            .route("/health", web::get().to(health_check))
    })
    .bind(&bind_address)?
    .run()
    .await
}