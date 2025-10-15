use actix_web::{web, App, HttpServer, middleware::Logger};
use fido2_webauthn_server::{config::AppConfig, handlers};
use tracing_subscriber;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize logging
    tracing_subscriber::init();

    let config = AppConfig::from_env();
    let bind_address = format!("{}:{}", config.host, config.port);

    println!("Starting FIDO2 WebAuthn Server on {}", bind_address);

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(config.clone()))
            .wrap(Logger::default())
            .wrap(actix_cors::Cors::permissive())
            .service(
                web::scope("/api/v1")
                    .service(handlers::attestation_options)
                    .service(handlers::attestation_result)
                    .service(handlers::assertion_options)
                    .service(handlers::assertion_result)
            )
            .service(
                web::scope("")
                    .service(handlers::attestation_options_legacy)
                    .service(handlers::attestation_result_legacy)
                    .service(handlers::assertion_options_legacy)
                    .service(handlers::assertion_result_legacy)
            )
    })
    .bind(&bind_address)?
    .run()
    .await
}