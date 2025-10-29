//! Common test utilities

use actix_web::{test, web, App};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde_json::json;
use uuid::Uuid;

use fido_server::config::{Config, WebAuthnConfig};
use fido_server::controllers::WebAuthnController;
use fido_server::db::{Database, PgCredentialRepository, PgChallengeRepository, PgUserRepository};
use fido_server::services::webauthn::{WebAuthnServiceImpl, WebAuthnService};
use fido_server::routes::api;

pub struct TestApp {
    pub app: impl actix_web::dev::Service<
        actix_web::dev::ServiceRequest,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
}

impl TestApp {
    pub async fn new() -> Self {
        // Use test database
        let database_url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://localhost/fido_server_test".to_string());
        
        // Initialize test database
        let database = Database::new(&database_url, 5).expect("Failed to initialize test database");
        
        // Clean up database before each test
        {
            let conn = database.get_connection().expect("Failed to get connection");
            diesel_migrations::embed_migrations!("migrations");
            fido_server::migrations::MIGRATIONS.run(&conn).expect("Failed to run migrations");
        }

        // Initialize repositories
        let user_repo = PgUserRepository::new(database.get_connection().expect("Failed to get connection"));
        let credential_repo = PgCredentialRepository::new(database.get_connection().expect("Failed to get connection"));
        let challenge_repo = PgChallengeRepository::new(database.get_connection().expect("Failed to get connection"));

        // Initialize WebAuthn service
        let webauthn_config = WebAuthnConfig {
            rp_name: "Test Corporation".to_string(),
            rp_id: "localhost".to_string(),
            rp_origin: "http://localhost:8080".to_string(),
            timeout: 60000,
        };

        let webauthn_service = WebAuthnServiceImpl::new(
            webauthn_config,
            user_repo,
            credential_repo,
            challenge_repo,
        ).expect("Failed to initialize WebAuthn service");

        let webauthn_controller = web::Data::new(WebAuthnController::new(webauthn_service));

        let app = test::init_service(
            App::new()
                .app_data(webauthn_controller.clone())
                .configure(|cfg| api::configure(cfg, webauthn_controller.clone()))
                .configure(api::configure_api)
        )
        .await;

        Self { app }
    }
}

pub fn create_registration_request(username: &str, display_name: &str) -> serde_json::Value {
    json!({
        "username": username,
        "displayName": display_name,
        "authenticatorSelection": {
            "requireResidentKey": false,
            "authenticatorAttachment": "cross-platform",
            "userVerification": "preferred"
        },
        "attestation": "direct"
    })
}

pub fn create_authentication_request(username: &str) -> serde_json::Value {
    json!({
        "username": username,
        "userVerification": "required"
    })
}

pub fn base64_encode(data: &[u8]) -> String {
    BASE64.encode(data)
}

pub fn generate_mock_client_data_json(challenge: &str, origin: &str, type_: &str) -> String {
    let client_data = json!({
        "challenge": challenge,
        "origin": origin,
        "type": type_
    });
    BASE64.encode(client_data.to_string().as_bytes())
}