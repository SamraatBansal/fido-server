//! FIDO Server Main Entry Point

use actix_cors::Cors;
use actix_web::{middleware::Logger, web, App, HttpServer};
use std::io;
use std::sync::Arc;

use fido_server::config::Settings;
use fido_server::controllers::WebAuthnController;
use fido_server::services::ServiceFactory;

#[actix_web::main]
async fn main() -> io::Result<()> {
    // Initialize logger
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    log::info!("Starting FIDO Server...");

    // Load configuration
    let settings = Settings::new().expect("Failed to load configuration");
    
    // Create WebAuthn service
    let webauthn_service = ServiceFactory::create_webauthn_service(&settings)
        .await
        .expect("Failed to create WebAuthn service");
    
    let webauthn_controller = Arc::new(WebAuthnController::new(webauthn_service));

    let host = &settings.server.host;
    let port = settings.server.port;

    log::info!("Server running at http://{}:{}", host, port);

    HttpServer::new(move || {
        // Configure CORS
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .max_age(3600);

        App::new()
            .wrap(Logger::default())
            .wrap(cors)
            .app_data(web::Data::new(webauthn_controller.clone()))
            .configure(fido_server::routes::api::configure)
    })
    .bind((host, port))?
    .run()
    .await
}
