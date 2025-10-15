pub mod fixtures;
pub mod test_server;
pub mod database;
pub mod security_helpers;

use fido2_webauthn_server::models::*;
use fido2_webauthn_server::services::WebAuthnService;
use actix_web::{web, App, test};

pub async fn create_test_app() -> test::TestServer {
    let webauthn_service = web::Data::new(WebAuthnService::new());
    
    test::start(move || {
        App::new()
            .app_data(webauthn_service.clone())
            .route("/attestation/options", web::post().to(fido2_webauthn_server::handlers::attestation_options))
            .route("/attestation/result", web::post().to(fido2_webauthn_server::handlers::attestation_result))
            .route("/assertion/options", web::post().to(fido2_webauthn_server::handlers::assertion_options))
            .route("/assertion/result", web::post().to(fido2_webauthn_server::handlers::assertion_result))
    })
}

pub fn assert_server_response_ok(response: &ServerResponse) {
    assert_eq!(response.status, "ok");
    assert_eq!(response.error_message, "");
}

pub fn assert_server_response_failed(response: &ServerResponse, expected_message: &str) {
    assert_eq!(response.status, "failed");
    assert!(response.error_message.contains(expected_message));
}