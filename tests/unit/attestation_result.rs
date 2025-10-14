//! Unit tests for /attestation/result endpoint

use crate::common::{
    fixtures::*,
    helpers::{assert_json_structure, is_valid_base64url},
    TestResult,
};
use actix_web::{http::StatusCode, test, App};
use serde_json::json;

/// Test successful attestation result
#[actix_web::test]
async fn test_attestation_result_success() -> TestResult<()> {
    let app = test::init_service(
        App::new().configure(|cfg| {
            cfg.service(
                actix_web::web::resource("/attestation/result")
                    .route(actix_web::web::post().to(crate::routes::attestation_result)),
            );
        }),
    )
    .await;

    let request = create_valid_attestation_result_request();
    let req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body: serde_json::Value = test::read_body_json(resp).await;
    
    // Verify response structure
    assert_json_structure(&body, &["status", "errorMessage"])?;
    
    // Verify success response
    assert_eq!(body["status"], "ok");
    assert_eq!(body["errorMessage"], "");

    Ok(())
}

/// Test attestation result with missing credential ID
#[actix_web::test]
async fn test_attestation_result_missing_id() -> TestResult<()> {
    let app = test::init_service(
        App::new().configure(|cfg| {
            cfg.service(
                actix_web::web::resource("/attestation/result")
                    .route(actix_web::web::post().to(crate::routes::attestation_result)),
            );
        }),
    )
    .await;

    let mut request = create_valid_attestation_result_request();
    request.id = "".to_string();

    let req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "failed");
    assert!(body["errorMessage"].as_str().unwrap().contains("id"));

    Ok(())
}

/// Test attestation result with missing raw ID
#[actix_web::test]
async fn test_attestation_result_missing_raw_id() -> TestResult<()> {
    let app = test::init_service(
        App::new().configure(|cfg| {
            cfg.service(
                actix_web::web::resource("/attestation/result")
                    .route(actix_web::web::post().to(crate::routes::attestation_result)),
            );
        }),
    )
    .await;

    let mut request = create_valid_attestation_result_request();
    request.raw_id = "".to_string();

    let req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "failed");
    assert!(body["errorMessage"].as_str().unwrap().contains("rawId"));

    Ok(())
}

/// Test attestation result with missing client data JSON
#[actix_web::test]
async fn test_attestation_result_missing_client_data_json() -> TestResult<()> {
    let app = test::init_service(
        App::new().configure(|cfg| {
            cfg.service(
                actix_web::web::resource("/attestation/result")
                    .route(actix_web::web::post().to(crate::routes::attestation_result)),
            );
        }),
    )
    .await;

    let mut request = create_valid_attestation_result_request();
    request.response.client_data_json = "".to_string();

    let req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "failed");
    assert!(body["errorMessage"].as_str().unwrap().contains("clientDataJSON"));

    Ok(())
}

/// Test attestation result with missing attestation object
#[actix_web::test]
async fn test_attestation_result_missing_attestation_object() -> TestResult<()> {
    let app = test::init_service(
        App::new().configure(|cfg| {
            cfg.service(
                actix_web::web::resource("/attestation/result")
                    .route(actix_web::web::post().to(crate::routes::attestation_result)),
            );
        }),
    )
    .await;

    let mut request = create_valid_attestation_result_request();
    request.response.attestation_object = "".to_string();

    let req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "failed");
    assert!(body["errorMessage"].as_str().unwrap().contains("attestationObject"));

    Ok(())
}

/// Test attestation result with invalid base64url in client data JSON
#[actix_web::test]
async fn test_attestation_result_invalid_client_data_json_base64() -> TestResult<()> {
    let app = test::init_service(
        App::new().configure(|cfg| {
            cfg.service(
                actix_web::web::resource("/attestation/result")
                    .route(actix_web::web::post().to(crate::routes::attestation_result)),
            );
        }),
    )
    .await;

    let mut request = create_valid_attestation_result_request();
    request.response.client_data_json = invalid_base64url();

    let req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "failed");
    assert!(body["errorMessage"].as_str().unwrap().contains("clientDataJSON"));

    Ok(())
}

/// Test attestation result with invalid base64url in attestation object
#[actix_web::test]
async fn test_attestation_result_invalid_attestation_object_base64() -> TestResult<()> {
    let app = test::init_service(
        App::new().configure(|cfg| {
            cfg.service(
                actix_web::web::resource("/attestation/result")
                    .route(actix_web::web::post().to(crate::routes::attestation_result)),
            );
        }),
    )
    .await;

    let mut request = create_valid_attestation_result_request();
    request.response.attestation_object = invalid_base64url();

    let req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "failed");
    assert!(body["errorMessage"].as_str().unwrap().contains("attestationObject"));

    Ok(())
}

/// Test attestation result with wrong credential type
#[actix_web::test]
async fn test_attestation_result_wrong_type() -> TestResult<()> {
    let app = test::init_service(
        App::new().configure(|cfg| {
            cfg.service(
                actix_web::web::resource("/attestation/result")
                    .route(actix_web::web::post().to(crate::routes::attestation_result)),
            );
        }),
    )
    .await;

    let mut request = create_valid_attestation_result_request();
    request.cred_type = "wrong-type".to_string();

    let req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "failed");
    assert!(body["errorMessage"].as_str().unwrap().contains("type"));

    Ok(())
}

/// Test attestation result with malformed client data JSON
#[actix_web::test]
async fn test_attestation_result_malformed_client_data_json() -> TestResult<()> {
    let app = test::init_service(
        App::new().configure(|cfg| {
            cfg.service(
                actix_web::web::resource("/attestation/result")
                    .route(actix_web::web::post().to(crate::routes::attestation_result)),
            );
        }),
    )
    .await;

    let mut request = create_valid_attestation_result_request();
    // Valid base64url but invalid JSON when decoded
    request.response.client_data_json = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("{ invalid json }");

    let req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "failed");
    assert!(body["errorMessage"].as_str().unwrap().contains("clientDataJSON"));

    Ok(())
}

/// Test attestation result with missing challenge in client data
#[actix_web::test]
async fn test_attestation_result_missing_challenge_in_client_data() -> TestResult<()> {
    let app = test::init_service(
        App::new().configure(|cfg| {
            cfg.service(
                actix_web::web::resource("/attestation/result")
                    .route(actix_web::web::post().to(crate::routes::attestation_result)),
            );
        }),
    )
    .await;

    let mut request = create_valid_attestation_result_request();
    let client_data = json!({
        "origin": "https://example.com",
        "type": "webauthn.create",
        "clientExtensions": {}
        // Missing challenge
    });
    request.response.client_data_json = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(client_data.to_string().as_bytes());

    let req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "failed");
    assert!(body["errorMessage"].as_str().unwrap().contains("challenge"));

    Ok(())
}

/// Test attestation result with wrong type in client data
#[actix_web::test]
async fn test_attestation_result_wrong_type_in_client_data() -> TestResult<()> {
    let app = test::init_service(
        App::new().configure(|cfg| {
            cfg.service(
                actix_web::web::resource("/attestation/result")
                    .route(actix_web::web::post().to(crate::routes::attestation_result)),
            );
        }),
    )
    .await;

    let mut request = create_valid_attestation_result_request();
    let client_data = json!({
        "challenge": valid_challenge(),
        "origin": "https://example.com",
        "type": "webauthn.get", // Wrong type - should be "webauthn.create"
        "clientExtensions": {}
    });
    request.response.client_data_json = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(client_data.to_string().as_bytes());

    let req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "failed");
    assert!(body["errorMessage"].as_str().unwrap().contains("type"));

    Ok(())
}

/// Test attestation result with wrong origin in client data
#[actix_web::test]
async fn test_attestation_result_wrong_origin_in_client_data() -> TestResult<()> {
    let app = test::init_service(
        App::new().configure(|cfg| {
            cfg.service(
                actix_web::web::resource("/attestation/result")
                    .route(actix_web::web::post().to(crate::routes::attestation_result)),
            );
        }),
    )
    .await;

    let mut request = create_valid_attestation_result_request();
    let client_data = json!({
        "challenge": valid_challenge(),
        "origin": "https://evil.com", // Wrong origin
        "type": "webauthn.create",
        "clientExtensions": {}
    });
    request.response.client_data_json = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(client_data.to_string().as_bytes());

    let req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "failed");
    assert!(body["errorMessage"].as_str().unwrap().contains("origin"));

    Ok(())
}

/// Test attestation result with malformed JSON request
#[actix_web::test]
async fn test_attestation_result_malformed_json() -> TestResult<()> {
    let app = test::init_service(
        App::new().configure(|cfg| {
            cfg.service(
                actix_web::web::resource("/attestation/result")
                    .route(actix_web::web::post().to(crate::routes::attestation_result)),
            );
        }),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_payload("{ invalid json }")
        .insert_header(("content-type", "application/json"))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    Ok(())
}

/// Test attestation result with empty request body
#[actix_web::test]
async fn test_attestation_result_empty_body() -> TestResult<()> {
    let app = test::init_service(
        App::new().configure(|cfg| {
            cfg.service(
                actix_web::web::resource("/attestation/result")
                    .route(actix_web::web::post().to(crate::routes::attestation_result)),
            );
        }),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/attestation/result")
        .insert_header(("content-type", "application/json"))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    Ok(())
}

/// Test attestation result with oversized payload
#[actix_web::test]
async fn test_attestation_result_oversized_payload() -> TestResult<()> {
    let app = test::init_service(
        App::new().configure(|cfg| {
            cfg.service(
                actix_web::web::resource("/attestation/result")
                    .route(actix_web::web::post().to(crate::routes::attestation_result)),
            );
        }),
    )
    .await;

    let mut request = create_valid_attestation_result_request();
    // Create oversized attestation object
    request.response.attestation_object = "a".repeat(1_000_000);

    let req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    // Should either accept or reject with payload too large error
    assert!(resp.status() == StatusCode::OK || resp.status() == StatusCode::PAYLOAD_TOO_LARGE);

    Ok(())
}