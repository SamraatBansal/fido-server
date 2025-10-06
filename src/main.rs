//! FIDO Server Main Entry Point

use actix_web::{middleware::Logger, App, HttpServer, web};
use std::io;
use fido_server::{config::load_config, db::init_pool, error::AppError};

#[actix_web::main]
async fn main() -> io::Result<()> {
    // Initialize logger
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    log::info!("Starting FIDO Server...");

    // Load configuration
    let config = load_config().map_err(|e| {
        log::error!("Failed to load configuration: {}", e);
        io::Error::new(io::ErrorKind::Other, "Configuration error")
    })?;

    // Initialize database connection pool
    let pool = init_pool(&config.database.url, config.database.max_connections)
        .map_err(|e| {
            log::error!("Failed to initialize database pool: {}", e);
            io::Error::new(io::ErrorKind::Other, "Database connection error")
        })?;

    // Run database migrations
    if let Err(e) = fido_server::db::run_migrations(&pool) {
        log::error!("Failed to run database migrations: {}", e);
        return Err(io::Error::new(io::ErrorKind::Other, "Migration error"));
    }

    log::info!("Database initialized successfully");

    let host = config.server.host.clone();
    let port = config.server.port;

    log::info!("Server running at http://{}:{}", host, port);

    // Start background task to clean up expired challenges
    let cleanup_pool = pool.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(300)); // Every 5 minutes
        loop {
            interval.tick().await;
            if let Ok(mut conn) = cleanup_pool.get() {
                if let Err(e) = fido_server::services::FidoService::new(config.webauthn.clone())
                    .unwrap()
                    .cleanup_expired_challenges(&mut conn).await
                {
                    log::warn!("Failed to cleanup expired challenges: {}", e);
                }
            }
        }
    });

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .wrap(Logger::default())
            .configure(fido_server::routes::api::configure)
    })
    .bind((host, port))?
    .run()
    .await
}
