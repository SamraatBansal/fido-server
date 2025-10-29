//! FIDO Server Main Entry Point

use actix_cors::Cors;
use actix_web::{middleware::Logger, web, App, HttpServer};
use std::io;


use fido_server::config::Config;
use fido_server::controllers::WebAuthnController;
use fido_server::db::{Database};
use fido_server::db::repository::{PgCredentialRepository, PgChallengeRepository, PgUserRepository};
use fido_server::services::webauthn::{WebAuthnServiceImpl};
use fido_server::routes::api;

#[actix_web::main]
async fn main() -> io::Result<()> {
    // Initialize logger
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    log::info!("Starting FIDO Server...");

    // Load configuration
    let config = Config::from_env();
    log::info!("Configuration loaded: {:?}", config);

    // Initialize database connection pool
    let database = Database::new(&config.database.url, config.database.max_connections)
        .expect("Failed to initialize database connection pool");

    // Run database migrations
    log::info!("Running database migrations...");
    let conn = database.get_connection().expect("Failed to get database connection for migrations");
    diesel_migrations::embed_migrations!("migrations");
    embedded_migrations::run(&conn).expect("Failed to run database migrations");

    // Initialize repositories
    let user_repo = PgUserRepository::new(database.get_connection().expect("Failed to get connection"));
    let credential_repo = PgCredentialRepository::new(database.get_connection().expect("Failed to get connection"));
    let challenge_repo = PgChallengeRepository::new(database.get_connection().expect("Failed to get connection"));

    // Initialize WebAuthn service
    let webauthn_service = WebAuthnServiceImpl::new(
        config.webauthn.clone(),
        user_repo,
        credential_repo,
        challenge_repo,
    ).expect("Failed to initialize WebAuthn service");

    // Initialize controller
    let webauthn_controller = web::Data::new(WebAuthnController::new(webauthn_service));

    let host = config.server.host.clone();
    let port = config.server.port;

    log::info!("Server running at http://{}:{}", host, port);

    HttpServer::new(move || {
        // Configure CORS
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .max_age(3600);

        App::new()
            .app_data(webauthn_controller.clone())
            .wrap(Logger::default())
            .wrap(cors)
            .service(
                web::scope("/attestation")
                    .route("/options", web::post().to({
                        let controller = webauthn_controller.clone();
                        move |req| {
                            let controller = controller.clone();
                            async move { controller.attestation_options(req).await }
                        }
                    }))
                    .route("/result", web::post().to({
                        let controller = webauthn_controller.clone();
                        move |req| {
                            let controller = controller.clone();
                            async move { controller.attestation_result(req).await }
                        }
                    }))
            )
            .service(
                web::scope("/assertion")
                    .route("/options", web::post().to({
                        let controller = webauthn_controller.clone();
                        move |req| {
                            let controller = controller.clone();
                            async move { controller.assertion_options(req).await }
                        }
                    }))
                    .route("/result", web::post().to({
                        let controller = webauthn_controller.clone();
                        move |req| {
                            let controller = controller.clone();
                            async move { controller.assertion_result(req).await }
                        }
                    }))
            )
            .configure(api::configure_api)
    })
    .bind((host, port))?
    .run()
    .await
}
