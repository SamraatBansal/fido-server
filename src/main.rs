use actix_web::{web, App, HttpServer, middleware::Logger};
use fido2_conformance_tests::{config::Settings, routes};
use tracing_subscriber;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize logging
    tracing_subscriber::init();

    // Load configuration
    let settings = Settings::new().expect("Failed to load configuration");

    // Start HTTP server
    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .configure(routes::configure)
    })
    .bind(format!("{}:{}", settings.server.host, settings.server.port))?
    .run()
    .await
}