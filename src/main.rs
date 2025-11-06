//! FIDO Server Main Entry Point

use actix_cors::Cors;
use actix_web::{middleware::Logger, web, App, HttpServer};
use std::io;

use fido_server::{
    config::Settings,
    db::connection::establish_connection,
    services::{FidoService, UserService},
};

#[actix_web::main]
async fn main() -> io::Result<()> {
    // Initialize logger
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    
    log::info!("Starting FIDO Server...");

    // Load configuration
    let settings = Settings::new().expect("Failed to load configuration");
    
    let host = settings.server.host.clone();
    let port = settings.server.port;

    // Initialize database connection pool
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| settings.database.url.clone());
    
    let pool = establish_connection(&database_url)
        .expect("Failed to create connection pool");

    // Initialize services
    let user_service = UserService::new(pool.clone());
    let fido_service = FidoService::new(&settings.webauthn, pool.clone(), user_service)
        .expect("Failed to initialize FIDO service");

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
            .app_data(web::Data::new(fido_service.clone()))
            .wrap(Logger::default())
            .wrap(cors)
            .configure(fido_server::routes::api::configure)
    })
    .bind((host, port))?
    .run()
    .await
}
