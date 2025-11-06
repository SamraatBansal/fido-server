use actix_cors::Cors;
use actix_web::{middleware::Logger, web, App, HttpServer};
use fido2_webauthn_server::{handlers, AppConfig, DatabaseService, WebAuthnService};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    // Load configuration
    let config = AppConfig::from_env().expect("Failed to load configuration");
    log::info!("Configuration loaded: {:?}", config);

    // Create database pool
    let pool = fido2_webauthn_server::create_pool(&config.database_url)
        .await
        .expect("Failed to create database pool");
    log::info!("Database pool created");

    // Create database service
    let database_service = DatabaseService::new(pool);

    // Create WebAuthn instance
    let webauthn = config
        .webauthn
        .build_webauthn()
        .expect("Failed to create WebAuthn instance");
    log::info!("WebAuthn instance created");

    // Create WebAuthn service
    let webauthn_service = WebAuthnService::new(webauthn, database_service);

    let bind_address = format!("{}:{}", config.server_host, config.server_port);
    log::info!("Starting server at http://{}", bind_address);

    HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .max_age(3600);

        App::new()
            .app_data(web::Data::new(webauthn_service.clone()))
            .wrap(cors)
            .wrap(Logger::default())
            .service(
                web::scope("/attestation")
                    .route("/options", web::post().to(handlers::start_registration))
                    .route("/result", web::post().to(handlers::finish_registration)),
            )
            .service(
                web::scope("/assertion")
                    .route("/options", web::post().to(handlers::start_authentication))
                    .route("/result", web::post().to(handlers::finish_authentication)),
            )
            .route("/health", web::get().to(handlers::health_check))
    })
    .bind(&bind_address)?
    .run()
    .await
}