//! Common test utilities and helpers

use actix_web::{test, App, web};
use fido2_webauthn_server::{
    services::WebAuthnService,
    routes::api,
    schema::*,
};
use serde_json::json;

/// Create a test application with all services configured
pub async fn create_test_app() -> impl actix_web::dev::Service<
    actix_web::dev::ServiceRequest,
    Response = actix_web::dev::ServiceResponse,
    Error = actix_web::Error,
> {
    let webauthn_service = WebAuthnService::new("localhost", "Test RP", "http://localhost:8080")
        .expect("Failed to create WebAuthn service");

    test::init_service(
        App::new()
            .app_data(web::Data::new(webauthn_service))
            .configure(api::configure)
    ).await
}

/// Create a test WebAuthn service
pub fn create_test_webauthn_service() -> WebAuthnService {
    WebAuthnService::new("localhost", "Test RP", "http://localhost:8080")
        .expect("Failed to create WebAuthn service")
}

/// Helper to make POST requests with JSON payload
pub async fn post_json<T: serde::Serialize>(
    app: &impl actix_web::dev::Service<
        actix_web::dev::ServiceRequest,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    path: &str,
    body: T,
) -> actix_web::dev::ServiceResponse {
    let req = test::TestRequest::post()
        .uri(path)
        .set_json(&body)
        .to_request();
    
    test::call_service(app, req).await
}

/// Helper to extract JSON from response
pub async fn read_body_json<T: serde::de::DeserializeOwned>(
    resp: actix_web::dev::ServiceResponse,
) -> T {
    test::read_body_json(resp).await
}