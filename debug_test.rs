use actix_web::{test, App, web::Data};
use fido_server::routes::api::configure;
use fido_server::services::{WebAuthnService, WebAuthnConfig};
use std::sync::Arc;

#[actix_web::main]
async fn main() {
    let webauthn_service = Arc::new(
        WebAuthnService::new(WebAuthnConfig::default())
            .expect("Failed to create WebAuthn service")
    );
    
    let app = test::init_service(
        App::new()
            .app_data(Data::new(webauthn_service))
            .configure(configure)
    ).await;

    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&serde_json::json!({
            "username": "johndoe@example.com",
            "displayName": "John Doe",
            "authenticatorSelection": {
                "requireResidentKey": false,
                "authenticatorAttachment": "cross-platform",
                "userVerification": "preferred"
            },
            "attestation": "direct"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    println!("Status: {}", resp.status());
    
    let body: serde_json::Value = test::read_body_json(resp).await;
    println!("Response: {}", serde_json::to_string_pretty(&body).unwrap());
}