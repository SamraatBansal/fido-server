//! Test attestation result endpoint

use actix_web::{test, App};
use fido_server::routes::api::configure;
use fido_server::domain::models::*;

#[actix_web::test]
async fn test_attestation_result_simple() {
    let app = test::init_service(
        App::new().configure(configure)
    ).await;

    let attestation_result = ServerPublicKeyCredential {
        id: "test_credential_id".to_string(),
        r#type: "public-key".to_string(),
        response: ServerAuthenticatorResponse::Attestation(ServerAuthenticatorAttestationResponse {
            client_data_json: "eyJ0eXN0Ijoid2ViYXV0aG4uY3JlYXRlIn0=".to_string(),
            attestation_object: "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAQ".to_string(),
        }),
        get_client_extension_results: None,
    };

    let req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&attestation_result)
        .to_request();

    let resp = test::call_service(&app, req).await;
    let status = resp.status();
    println!("Response status: {}", status);
    
    let body = test::read_body(resp).await;
    println!("Response body: {}", String::from_utf8_lossy(&body));
    
    assert!(status.is_success());
}