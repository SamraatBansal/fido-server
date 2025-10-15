use actix_web::{web, App, HttpServer, middleware::Logger};
use actix_cors::Cors;
use fido2_webauthn_server::{handlers::*, services::WebAuthnService, config::AppConfig};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    
    let config = AppConfig::from_env();
    let webauthn_service = web::Data::new(WebAuthnService::new());
    
    println!("Starting FIDO2 WebAuthn server on {}:{}", config.server.host, config.server.port);
    
    HttpServer::new(move || {
        let cors = Cors::default()
            .allowed_origin_fn(|origin, _req_head| {
                config.server.cors_origins.iter().any(|allowed| {
                    origin.as_bytes() == allowed.as_bytes()
                })
            })
            .allowed_methods(vec!["GET", "POST", "OPTIONS"])
            .allowed_headers(vec!["Content-Type", "Authorization"])
            .max_age(3600);

        App::new()
            .app_data(webauthn_service.clone())
            .wrap(cors)
            .wrap(Logger::default())
            .route("/attestation/options", web::post().to(attestation_options))
            .route("/attestation/result", web::post().to(attestation_result))
            .route("/assertion/options", web::post().to(assertion_options))
            .route("/assertion/result", web::post().to(assertion_result))
    })
    .bind(format!("{}:{}", config.server.host, config.server.port))?
    .run()
    .await
}