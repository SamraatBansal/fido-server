//! Common test utilities

use actix_web::{test, App};
use std::sync::Arc;
use uuid::Uuid;
use fido_server::{
    config::{Config, WebAuthnConfig, SecurityConfig},
    controllers::{RegistrationController, AuthenticationController, HealthController},
    db::repositories::mocks::{MockUserRepository, MockCredentialRepository, MockChallengeRepository},
    services::{WebAuthnService, UserService, CredentialService, SecurityService},
    middleware::{CorsMiddleware, RateLimitMiddleware, SecurityHeadersMiddleware, RequestValidationMiddleware},
};

/// Create test configuration
pub fn create_test_config() -> Config {
    Config {
        server: fido_server::config::ServerConfig {
            host: "127.0.0.1".to_string(),
            port: 8080,
            workers: Some(1),
        },
        database: fido_server::config::DatabaseConfig {
            url: "postgres://localhost/test".to_string(),
            max_connections: Some(5),
            min_connections: Some(1),
            connection_timeout: Some(30),
        },
        webauthn: WebAuthnConfig {
            rp_name: "Test FIDO Server".to_string(),
            rp_id: "localhost".to_string(),
            rp_origin: "http://localhost:8080".to_string(),
            timeout: Some(60000),
            attestation_preference: webauthn_rs::proto::AttestationConveyancePreference::Direct,
        },
        security: SecurityConfig {
            challenge_expiry_seconds: 300,
            max_concurrent_requests: 100,
            rate_limit_requests_per_minute: 60,
            cors_origins: vec!["http://localhost:3000".to_string()],
        },
    }
}

/// Create test services with mock repositories
pub async fn create_test_services() -> (WebAuthnService, UserService, CredentialService, SecurityService) {
    let config = create_test_config();
    let user_repo = Arc::new(MockUserRepository::new());
    let credential_repo = Arc::new(MockCredentialRepository::new());
    let challenge_repo = Arc::new(MockChallengeRepository::new());

    let webauthn_service = WebAuthnService::new(
        config.webauthn.clone(),
        user_repo.clone(),
        credential_repo.clone(),
        challenge_repo.clone(),
    ).unwrap();

    let user_service = UserService::new(user_repo);
    let credential_service = CredentialService::new(credential_repo);
    let security_service = SecurityService::new(challenge_repo);

    (webauthn_service, user_service, credential_service, security_service)
}

/// Create test app with all services
pub async fn create_test_app() -> impl actix_web::dev::Service<
    actix_web::dev::ServiceRequest,
    Response = actix_web::dev::ServiceResponse,
    Error = actix_web::Error,
> {
    let (webauthn_service, _, _, _) = create_test_services().await;
    let config = create_test_config();

    let registration_controller = Arc::new(RegistrationController::new(Arc::new(webauthn_service.clone())));
    let authentication_controller = Arc::new(AuthenticationController::new(Arc::new(webauthn_service)));
    let health_controller = Arc::new(HealthController::new(None));

    test::init_service(
        App::new()
            .wrap(CorsMiddleware::configure(&config.security))
            .wrap(RateLimitMiddleware::new(config.security.rate_limit_requests_per_minute))
            .wrap(SecurityHeadersMiddleware)
            .wrap(RequestValidationMiddleware)
            .configure(|cfg| {
                fido_server::controllers::registration::configure(cfg, registration_controller);
                fido_server::controllers::authentication::configure(cfg, authentication_controller);
                fido_server::controllers::health::configure(cfg, health_controller);
            })
    ).await
}

/// Generate a random test username
pub fn generate_test_username() -> String {
    format!("testuser_{}", Uuid::new_v4().to_string().replace("-", "")[..8].to_string())
}

/// Generate a random test display name
pub fn generate_test_display_name() -> String {
    format!("Test User {}", Uuid::new_v4().to_string().replace("-", "")[..8].to_string())
}