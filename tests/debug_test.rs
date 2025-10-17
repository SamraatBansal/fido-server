//! Debug test to check what's happening

use actix_web::{test, App};
use fido_server::routes::api::configure;
use serde_json::json;

#[actix_web::test]
async fn test_debug_attestation_options() {
    let app = test::init_service(
        App::new().configure(configure)
    ).await;

    let registration_request = json!({
        "username": "johndoe@example.com",
        "displayName": "John Doe",
        "authenticatorSelection": {
            "requireResidentKey": false,
            "authenticatorAttachment": "cross-platform",
            "userVerification": "preferred"
        },
        "attestation": "direct"
    });

    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&registration_request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    let status = resp.status();
    println!("Response status: {}", status);
    println!("Response headers: {:?}", resp.headers());
    
    let body = test::read_body(resp).await;
    println!("Response body: {}", String::from_utf8_lossy(&body));
    
    assert!(status.is_success());
}