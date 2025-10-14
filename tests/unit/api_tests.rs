//! Unit tests for FIDO2/WebAuthn API endpoints

use actix_web::{http::StatusCode, test, App};
use serde_json::json;
use fido_server::routes::api;

use crate::common::{
    TestDataFactory, ServerResponse, AttestationOptionsRequest, 
    AssertionOptionsRequest, AttestationResultRequest, AssertionResultRequest
};

/// Test application setup
async fn create_test_app() -> impl actix_web::dev::Service<
    actix_web::dev::ServiceRequest,
    Response = actix_web::dev::ServiceResponse,
    Error = actix_web::Error,
> {
    test::init_service(
        App::new().configure(api::configure)
    ).await
}

#[actix_web::test]
async fn test_attestation_options_valid_request() {
    let app = create_test_app().await;
    let req = TestDataFactory::valid_attestation_options_request();

    let req_body = json!({
        "username": req.username,
        "displayName": req.display_name,
        "attestation": req.attestation,
        "authenticatorSelection": req.authenticator_selection
    });

    let resp = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&req_body)
        .send_request(&app)
        .await;

    assert_eq!(resp.status(), StatusCode::OK);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(body.get("challenge").is_some());
    assert!(body.get("rp").is_some());
    assert!(body.get("user").is_some());
    assert!(body.get("pubKeyCredParams").is_some());
    assert!(body.get("timeout").is_some());
}

#[actix_web::test]
async fn test_attestation_options_missing_username() {
    let app = create_test_app().await;
    let req = TestDataFactory::invalid_attestation_options_request_missing_username();

    let req_body = json!({
        "username": req.username,
        "displayName": req.display_name,
        "attestation": req.attestation,
        "authenticatorSelection": req.authenticator_selection
    });

    let resp = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&req_body)
        .send_request(&app)
        .await;

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body: ServerResponse = test::read_body_json(resp).await;
    assert_eq!(body.status, "failed");
    assert!(!body.error_message.is_empty());
}

#[actix_web::test]
async fn test_attestation_options_missing_display_name() {
    let app = create_test_app().await;
    let mut req = TestDataFactory::valid_attestation_options_request();
    req.display_name = "".to_string();

    let req_body = json!({
        "username": req.username,
        "displayName": req.display_name,
        "attestation": req.attestation,
        "authenticatorSelection": req.authenticator_selection
    });

    let resp = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&req_body)
        .send_request(&app)
        .await;

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body: ServerResponse = test::read_body_json(resp).await;
    assert_eq!(body.status, "failed");
}

#[actix_web::test]
async fn test_attestation_options_invalid_attestation() {
    let app = create_test_app().await;
    let mut req = TestDataFactory::valid_attestation_options_request();
    req.attestation = Some("invalid".to_string());

    let req_body = json!({
        "username": req.username,
        "displayName": req.display_name,
        "attestation": req.attestation,
        "authenticatorSelection": req.authenticator_selection
    });

    let resp = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&req_body)
        .send_request(&app)
        .await;

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body: ServerResponse = test::read_body_json(resp).await;
    assert_eq!(body.status, "failed");
}

#[actix_web::test]
async fn test_attestation_options_invalid_authenticator_selection() {
    let app = create_test_app().await;
    let mut req = TestDataFactory::valid_attestation_options_request();
    req.authenticator_selection = Some(serde_json::from_value(json!({
        "authenticatorAttachment": "invalid",
        "requireResidentKey": false,
        "userVerification": "invalid"
    })).unwrap());

    let req_body = json!({
        "username": req.username,
        "displayName": req.display_name,
        "attestation": req.attestation,
        "authenticatorSelection": req.authenticator_selection
    });

    let resp = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&req_body)
        .send_request(&app)
        .await;

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body: ServerResponse = test::read_body_json(resp).await;
    assert_eq!(body.status, "failed");
}

#[actix_web::test]
async fn test_attestation_result_valid_request() {
    let app = create_test_app().await;
    let req = TestDataFactory::valid_attestation_result_request();

    let req_body = json!({
        "id": req.id,
        "rawId": req.raw_id,
        "response": {
            "attestationObject": req.response.attestation_object,
            "clientDataJSON": req.response.client_data_json
        },
        "type": req.credential_type
    });

    let resp = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&req_body)
        .send_request(&app)
        .await;

    assert_eq!(resp.status(), StatusCode::OK);

    let body: ServerResponse = test::read_body_json(resp).await;
    assert_eq!(body.status, "ok");
    assert_eq!(body.error_message, "");
}

#[actix_web::test]
async fn test_attestation_result_missing_id() {
    let app = create_test_app().await;
    let mut req = TestDataFactory::valid_attestation_result_request();
    req.id = "".to_string();

    let req_body = json!({
        "id": req.id,
        "rawId": req.raw_id,
        "response": {
            "attestationObject": req.response.attestation_object,
            "clientDataJSON": req.response.client_data_json
        },
        "type": req.credential_type
    });

    let resp = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&req_body)
        .send_request(&app)
        .await;

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body: ServerResponse = test::read_body_json(resp).await;
    assert_eq!(body.status, "failed");
}

#[actix_web::test]
async fn test_attestation_result_invalid_base64url() {
    let app = create_test_app().await;
    let req = TestDataFactory::invalid_attestation_result_request();

    let req_body = json!({
        "id": req.id,
        "rawId": req.raw_id,
        "response": {
            "attestationObject": req.response.attestation_object,
            "clientDataJSON": req.response.client_data_json
        },
        "type": req.credential_type
    });

    let resp = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&req_body)
        .send_request(&app)
        .await;

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body: ServerResponse = test::read_body_json(resp).await;
    assert_eq!(body.status, "failed");
}

#[actix_web::test]
async fn test_attestation_result_missing_attestation_object() {
    let app = create_test_app().await;
    let mut req = TestDataFactory::valid_attestation_result_request();
    req.response.attestation_object = "".to_string();

    let req_body = json!({
        "id": req.id,
        "rawId": req.raw_id,
        "response": {
            "attestationObject": req.response.attestation_object,
            "clientDataJSON": req.response.client_data_json
        },
        "type": req.credential_type
    });

    let resp = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&req_body)
        .send_request(&app)
        .await;

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body: ServerResponse = test::read_body_json(resp).await;
    assert_eq!(body.status, "failed");
}

#[actix_web::test]
async fn test_attestation_result_invalid_credential_type() {
    let app = create_test_app().await;
    let mut req = TestDataFactory::valid_attestation_result_request();
    req.credential_type = "invalid".to_string();

    let req_body = json!({
        "id": req.id,
        "rawId": req.raw_id,
        "response": {
            "attestationObject": req.response.attestation_object,
            "clientDataJSON": req.response.client_data_json
        },
        "type": req.credential_type
    });

    let resp = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&req_body)
        .send_request(&app)
        .await;

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body: ServerResponse = test::read_body_json(resp).await;
    assert_eq!(body.status, "failed");
}

#[actix_web::test]
async fn test_assertion_options_valid_request() {
    let app = create_test_app().await;
    let req = TestDataFactory::valid_assertion_options_request();

    let req_body = json!({
        "username": req.username,
        "userVerification": req.user_verification
    });

    let resp = test::TestRequest::post()
        .uri("/assertion/options")
        .set_json(&req_body)
        .send_request(&app)
        .await;

    assert_eq!(resp.status(), StatusCode::OK);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(body.get("challenge").is_some());
    assert!(body.get("rpId").is_some());
    assert!(body.get("allowCredentials").is_some());
    assert!(body.get("timeout").is_some());
    assert!(body.get("userVerification").is_some());
}

#[actix_web::test]
async fn test_assertion_options_missing_username() {
    let app = create_test_app().await;
    let mut req = TestDataFactory::valid_assertion_options_request();
    req.username = "".to_string();

    let req_body = json!({
        "username": req.username,
        "userVerification": req.user_verification
    });

    let resp = test::TestRequest::post()
        .uri("/assertion/options")
        .set_json(&req_body)
        .send_request(&app)
        .await;

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body: ServerResponse = test::read_body_json(resp).await;
    assert_eq!(body.status, "failed");
}

#[actix_web::test]
async fn test_assertion_options_invalid_user_verification() {
    let app = create_test_app().await;
    let mut req = TestDataFactory::valid_assertion_options_request();
    req.user_verification = Some("invalid".to_string());

    let req_body = json!({
        "username": req.username,
        "userVerification": req.user_verification
    });

    let resp = test::TestRequest::post()
        .uri("/assertion/options")
        .set_json(&req_body)
        .send_request(&app)
        .await;

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body: ServerResponse = test::read_body_json(resp).await;
    assert_eq!(body.status, "failed");
}

#[actix_web::test]
async fn test_assertion_result_valid_request() {
    let app = create_test_app().await;
    let req = TestDataFactory::valid_assertion_result_request();

    let req_body = json!({
        "id": req.id,
        "rawId": req.raw_id,
        "response": {
            "authenticatorData": req.response.authenticator_data,
            "clientDataJSON": req.response.client_data_json,
            "signature": req.response.signature,
            "userHandle": req.response.user_handle
        },
        "type": req.credential_type
    });

    let resp = test::TestRequest::post()
        .uri("/assertion/result")
        .set_json(&req_body)
        .send_request(&app)
        .await;

    assert_eq!(resp.status(), StatusCode::OK);

    let body: ServerResponse = test::read_body_json(resp).await;
    assert_eq!(body.status, "ok");
    assert_eq!(body.error_message, "");
}

#[actix_web::test]
async fn test_assertion_result_missing_authenticator_data() {
    let app = create_test_app().await;
    let mut req = TestDataFactory::valid_assertion_result_request();
    req.response.authenticator_data = "".to_string();

    let req_body = json!({
        "id": req.id,
        "rawId": req.raw_id,
        "response": {
            "authenticatorData": req.response.authenticator_data,
            "clientDataJSON": req.response.client_data_json,
            "signature": req.response.signature,
            "userHandle": req.response.user_handle
        },
        "type": req.credential_type
    });

    let resp = test::TestRequest::post()
        .uri("/assertion/result")
        .set_json(&req_body)
        .send_request(&app)
        .await;

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body: ServerResponse = test::read_body_json(resp).await;
    assert_eq!(body.status, "failed");
}

#[actix_web::test]
async fn test_assertion_result_missing_signature() {
    let app = create_test_app().await;
    let mut req = TestDataFactory::valid_assertion_result_request();
    req.response.signature = "".to_string();

    let req_body = json!({
        "id": req.id,
        "rawId": req.raw_id,
        "response": {
            "authenticatorData": req.response.authenticator_data,
            "clientDataJSON": req.response.client_data_json,
            "signature": req.response.signature,
            "userHandle": req.response.user_handle
        },
        "type": req.credential_type
    });

    let resp = test::TestRequest::post()
        .uri("/assertion/result")
        .set_json(&req_body)
        .send_request(&app)
        .await;

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body: ServerResponse = test::read_body_json(resp).await;
    assert_eq!(body.status, "failed");
}

#[actix_web::test]
async fn test_malformed_json_request() {
    let app = create_test_app().await;

    let resp = test::TestRequest::post()
        .uri("/attestation/options")
        .set_payload("invalid json".to_string())
        .insert_header(("content-type", "application/json"))
        .send_request(&app)
        .await;

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[actix_web::test]
async fn test_oversized_payload() {
    let app = create_test_app().await;
    let oversized = TestDataFactory::oversized_payload();

    let resp = test::TestRequest::post()
        .uri("/attestation/options")
        .set_payload(oversized)
        .insert_header(("content-type", "application/json"))
        .send_request(&app)
        .await;

    // Should either be rejected due to size limit or parsing error
    assert!(resp.status() == StatusCode::BAD_REQUEST || resp.status() == StatusCode::PAYLOAD_TOO_LARGE);
}

#[actix_web::test]
async fn test_empty_request_body() {
    let app = create_test_app().await;

    let resp = test::TestRequest::post()
        .uri("/attestation/options")
        .set_payload("{}".to_string())
        .insert_header(("content-type", "application/json"))
        .send_request(&app)
        .await;

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body: ServerResponse = test::read_body_json(resp).await;
    assert_eq!(body.status, "failed");
}

#[actix_web::test]
async fn test_response_schema_validation() {
    let app = create_test_app().await;
    let req = TestDataFactory::valid_attestation_options_request();

    let req_body = json!({
        "username": req.username,
        "displayName": req.display_name,
        "attestation": req.attestation,
        "authenticatorSelection": req.authenticator_selection
    });

    let resp = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&req_body)
        .send_request(&app)
        .await;

    assert_eq!(resp.status(), StatusCode::OK);

    let body: serde_json::Value = test::read_body_json(resp).await;
    
    // Validate required fields exist and have correct types
    assert!(body.get("challenge").unwrap().is_string());
    assert!(body.get("rp").unwrap().is_object());
    assert!(body.get("user").unwrap().is_object());
    assert!(body.get("pubKeyCredParams").unwrap().is_array());
    assert!(body.get("timeout").unwrap().is_number());
    
    // Validate nested structure
    let rp = body.get("rp").unwrap();
    assert!(rp.get("name").unwrap().is_string());
    assert!(rp.get("id").unwrap().is_string());
    
    let user = body.get("user").unwrap();
    assert!(user.get("id").unwrap().is_string());
    assert!(user.get("name").unwrap().is_string());
    assert!(user.get("displayName").unwrap().is_string());
}