//! Unit tests for /attestation/options endpoint

use crate::common::{
    fixtures::*,
    helpers::{assert_json_structure, is_valid_base64url},
    TestResult,
};
use actix_web::{http::StatusCode, test, App};
use serde_json::json;

/// Test successful attestation options request
#[actix_web::test]
async fn test_attestation_options_success() -> TestResult<()> {
    let app = test::init_service(
        App::new().configure(|cfg| {
            cfg.service(
                actix_web::web::resource("/attestation/options")
                    .route(actix_web::web::post().to(crate::routes::attestation_options)),
            );
        }),
    )
    .await;

    let request = create_valid_attestation_options_request();
    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body: serde_json::Value = test::read_body_json(resp).await;
    
    // Verify response structure
    assert_json_structure(&body, &["status", "rp", "user", "challenge", "pubKeyCredParams"])?;
    
    // Verify status is ok
    assert_eq!(body["status"], "ok");
    assert_eq!(body["errorMessage"], "");
    
    // Verify challenge is valid base64url and reasonable length
    let challenge = body["challenge"].as_str().unwrap();
    assert!(is_valid_base64url(challenge));
    assert!(challenge.len() >= 16); // Minimum 16 bytes when base64url encoded
    
    // Verify RP entity
    assert_eq!(body["rp"]["name"], "Example Corporation");
    assert_eq!(body["rp"]["id"], "example.com");
    
    // Verify user entity
    assert_eq!(body["user"]["name"], "alice@example.com");
    assert_eq!(body["user"]["displayName"], "Alice Smith");
    assert!(is_valid_base64url(body["user"]["id"].as_str().unwrap()));
    
    // Verify pubKeyCredParams
    let params = body["pubKeyCredParams"].as_array().unwrap();
    assert!(!params.is_empty());
    assert_eq!(params[0]["type"], "public-key");
    assert_eq!(params[0]["alg"], -7); // ES256
    
    // Verify timeout
    assert!(body["timeout"].as_u64().unwrap() > 0);
    
    // Verify attestation preference
    assert_eq!(body["attestation"], "direct");
    
    // Verify authenticatorSelection
    assert_eq!(body["authenticatorSelection"]["requireResidentKey"], false);
    assert_eq!(body["authenticatorSelection"]["authenticatorAttachment"], "cross-platform");
    assert_eq!(body["authenticatorSelection"]["userVerification"], "preferred");

    Ok(())
}

/// Test attestation options with missing username
#[actix_web::test]
async fn test_attestation_options_missing_username() -> TestResult<()> {
    let app = test::init_service(
        App::new().configure(|cfg| {
            cfg.service(
                actix_web::web::resource("/attestation/options")
                    .route(actix_web::web::post().to(crate::routes::attestation_options)),
            );
        }),
    )
    .await;

    let mut request = create_valid_attestation_options_request();
    request.username = "".to_string();

    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "failed");
    assert!(body["errorMessage"].as_str().unwrap().contains("username"));

    Ok(())
}

/// Test attestation options with missing display name
#[actix_web::test]
async fn test_attestation_options_missing_display_name() -> TestResult<()> {
    let app = test::init_service(
        App::new().configure(|cfg| {
            cfg.service(
                actix_web::web::resource("/attestation/options")
                    .route(actix_web::web::post().to(crate::routes::attestation_options)),
            );
        }),
    )
    .await;

    let mut request = create_valid_attestation_options_request();
    request.display_name = "".to_string();

    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "failed");
    assert!(body["errorMessage"].as_str().unwrap().contains("displayName"));

    Ok(())
}

/// Test attestation options with invalid attestation preference
#[actix_web::test]
async fn test_attestation_options_invalid_attestation() -> TestResult<()> {
    let app = test::init_service(
        App::new().configure(|cfg| {
            cfg.service(
                actix_web::web::resource("/attestation/options")
                    .route(actix_web::web::post().to(crate::routes::attestation_options)),
            );
        }),
    )
    .await;

    let mut request = create_valid_attestation_options_request();
    request.attestation = Some("invalid".to_string());

    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "failed");
    assert!(body["errorMessage"].as_str().unwrap().contains("attestation"));

    Ok(())
}

/// Test attestation options with invalid user verification
#[actix_web::test]
async fn test_attestation_options_invalid_user_verification() -> TestResult<()> {
    let app = test::init_service(
        App::new().configure(|cfg| {
            cfg.service(
                actix_web::web::resource("/attestation/options")
                    .route(actix_web::web::post().to(crate::routes::attestation_options)),
            );
        }),
    )
    .await;

    let mut request = create_valid_attestation_options_request();
    request.authenticator_selection.as_mut().unwrap().user_verification = Some("invalid".to_string());

    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "failed");
    assert!(body["errorMessage"].as_str().unwrap().contains("userVerification"));

    Ok(())
}

/// Test attestation options with invalid authenticator attachment
#[actix_web::test]
async fn test_attestation_options_invalid_authenticator_attachment() -> TestResult<()> {
    let app = test::init_service(
        App::new().configure(|cfg| {
            cfg.service(
                actix_web::web::resource("/attestation/options")
                    .route(actix_web::web::post().to(crate::routes::attestation_options)),
            );
        }),
    )
    .await;

    let mut request = create_valid_attestation_options_request();
    request.authenticator_selection.as_mut().unwrap().authenticator_attachment = Some("invalid".to_string());

    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "failed");
    assert!(body["errorMessage"].as_str().unwrap().contains("authenticatorAttachment"));

    Ok(())
}

/// Test attestation options with malformed JSON
#[actix_web::test]
async fn test_attestation_options_malformed_json() -> TestResult<()> {
    let app = test::init_service(
        App::new().configure(|cfg| {
            cfg.service(
                actix_web::web::resource("/attestation/options")
                    .route(actix_web::web::post().to(crate::routes::attestation_options)),
            );
        }),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_payload("{ invalid json }")
        .insert_header(("content-type", "application/json"))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    Ok(())
}

/// Test attestation options with empty request body
#[actix_web::test]
async fn test_attestation_options_empty_body() -> TestResult<()> {
    let app = test::init_service(
        App::new().configure(|cfg| {
            cfg.service(
                actix_web::web::resource("/attestation/options")
                    .route(actix_web::web::post().to(crate::routes::attestation_options)),
            );
        }),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .insert_header(("content-type", "application/json"))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    Ok(())
}

/// Test attestation options with oversized username
#[actix_web::test]
async fn test_attestation_options_oversized_username() -> TestResult<()> {
    let app = test::init_service(
        App::new().configure(|cfg| {
            cfg.service(
                actix_web::web::resource("/attestation/options")
                    .route(actix_web::web::post().to(crate::routes::attestation_options)),
            );
        }),
    )
    .await;

    let mut request = create_valid_attestation_options_request();
    request.username = "a".repeat(300); // Exceed reasonable limit

    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "failed");

    Ok(())
}

/// Test attestation options with special characters in username
#[actix_web::test]
async fn test_attestation_options_special_characters_username() -> TestResult<()> {
    let app = test::init_service(
        App::new().configure(|cfg| {
            cfg.service(
                actix_web::web::resource("/attestation/options")
                    .route(actix_web::web::post().to(crate::routes::attestation_options)),
            );
        }),
    )
    .await;

    let mut request = create_valid_attestation_options_request();
    request.username = "test+user@example.com".to_string();

    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "ok");

    Ok(())
}

/// Test attestation options with different attestation preferences
#[actix_web::test]
async fn test_attestation_options_different_attestation_preferences() -> TestResult<()> {
    let app = test::init_service(
        App::new().configure(|cfg| {
            cfg.service(
                actix_web::web::resource("/attestation/options")
                    .route(actix_web::web::post().to(crate::routes::attestation_options)),
            );
        }),
    )
    .await;

    let attestation_preferences = vec!["none", "indirect", "direct", "enterprise"];
    
    for preference in attestation_preferences {
        let mut request = create_valid_attestation_options_request();
        request.attestation = Some(preference.to_string());
        request.username = format!("user{}@example.com", preference); // Make unique

        let req = test::TestRequest::post()
            .uri("/attestation/options")
            .set_json(&request)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["status"], "ok");
        assert_eq!(body["attestation"], preference);
    }

    Ok(())
}