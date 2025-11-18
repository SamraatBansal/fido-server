//! FIDO Server Main Entry Point

use actix_cors::Cors;
use actix_web::{middleware::Logger, web, App, HttpServer};
use std::io;
use std::sync::Arc;
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};

use fido_server::{
    config::Settings,
    db::establish_connection,
    services::{FidoService, UserService},
};

const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");

#[actix_web::main]
async fn main() -> io::Result<()> {
    // Load environment variables
    dotenv::dotenv().ok();
    
    // Initialize logger
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    log::info!("Starting FIDO Server...");

    // Load configuration
    let settings = Settings::new()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

    // Initialize database connection pool
    let db_pool = establish_connection(&settings.database.url, settings.database.max_pool_size)
        .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, e.to_string()))?;
    
    let db_pool = Arc::new(db_pool);

    // Run migrations
    {
        let mut conn = db_pool.get()
            .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, e.to_string()))?;
        
        conn.run_pending_migrations(MIGRATIONS)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        
        log::info!("Database migrations completed successfully");
    }

    // Initialize services
    let fido_service = FidoService::new(&settings.webauthn, db_pool.clone())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let user_service = UserService::new(db_pool.clone());

    let host = settings.server.host.clone();
    let port = settings.server.port;

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
            .app_data(web::Data::new(user_service.clone()))
            .wrap(Logger::default())
            .wrap(cors)
            .configure(fido_server::routes::api::configure)
    })
    .bind((host, port))?
    .run()
    .await
}
