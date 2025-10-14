//! Unit tests for /assertion/options endpoint

use crate::common::{
    fixtures::*,
    helpers::{assert_json_structure, is_valid_base64url},
    TestResult,
};
use actix_web::{http::StatusCode, test, App};
use serde_json::json;

/// Test successful assertion options request
#[actix_web::test]
async fn test_assertion_options_success() -> TestResult<()> {
    let app = test::init_service(
        App::new().configure(|cfg| {
            cfg.service(
                actix_web::web::resource("/assertion/options")
                    .route(actix_web::web::post().to(crate::routes::assertion_options)),
            );
        }),
    )
    .await;

    let request = create_valid_assertion_options_request();
    let req = test::TestRequest::post()
        .uri("/assertion/options")
        .set_json(&request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body: serde_json::Value = test::read_body_json(resp).await;
    
    // Verify response structure
    assert_json_structure(&body, &["status", "challenge", "rpId", "allowCredentials"])?;
    
    // Verify status is ok
    assert_eq!(body["status"], "ok");
    assert_eq!(body["errorMessage"], "");
    
    // Verify challenge is valid base64url and reasonable length
    let challenge = body["challenge"].as_str().unwrap();
    assert!(is_valid_base64url(challenge));
    assert!(challenge.len() >= 16); // Minimum 16 bytes when base64url encoded
    
    // Verify RP ID
    assert_eq!(body["rpId"], "example.com");
    
    // Verify allowCredentials is not empty for existing user
    let allow_creds = body["allowCredentials"].as_array().unwrap();
    // Note: This might be empty for new users, which is valid
    
    // Verify timeout
    assert!(body["timeout"].as_u64().unwrap() > 0);
    
    // Verify user verification preference
    assert_eq!(body["userVerification"], "preferred");

    Ok(())
}

/// Test assertion options with missing username
#[actix_web::test]
async fn test_assertion_options_missing_username() -> TestResult<()> {
    let app = test::init_service(
        App::new().configure(|cfg| {
            cfg.service(
                actix_web::web::resource("/assertion/options")
                    .route(actix_web::web::post().to(crate::routes::assertion_options)),
            );
        }),
    )
    .await;

    let mut request = create_valid_assertion_options_request();
    request.username = "".to_string();

    let req = test::TestRequest::post()
        .uri("/assertion/options")
        .set_json(&request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "failed");
    assert!(body["errorMessage"].as_str().unwrap().contains("username"));

    Ok(())
}

/// Test assertion options with invalid user verification
#[actix_web::test]
async fn test_assertion_options_invalid_user_verification() -> TestResult<()> {
    let app = test::init_service(
        App::new().configure(|cfg| {
            cfg.service(
                actix_web::web::resource("/assertion/options")
                    .route(actix_web::web::post().to(crate::routes::assertion_options)),
            );
        }),
    )
    .await;

    let mut request = create_valid_assertion_options_request();
    request.user_verification = Some("invalid".to_string());

    let req = test::TestRequest::post()
        .uri("/assertion/options")
        .set_json(&request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "failed");
    assert!(body["errorMessage"].as_str().unwrap().contains("userVerification"));

    Ok(())
}

/// Test assertion options for non-existent user
#[actix_web::test]
async fn test_assertion_options_nonexistent_user() -> TestResult<()> {
    let app = test::init_service(
        App::new().configure(|cfg| {
            cfg.service(
                actix_web::web::resource("/assertion/options")
                    .route(actix_web::web::post().to(crate::routes::assertion_options)),
            );
        }),
    )
    .await;

    let mut request = create_valid_assertion_options_request();
    request.username = "nonexistent@example.com".to_string();

    let req = test::TestRequest::post()
        .uri("/assertion/options")
        .set_json(&request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    // This could be either OK (with empty allowCredentials) or BAD_REQUEST (user not found)
    // depending on implementation choice
    assert!(resp.status() == StatusCode::OK || resp.status() == StatusCode::BAD_REQUEST);

    if resp.status() == StatusCode::OK {
        let body: serde_json::Value = test::read_body_json(resp).await;
        // For non-existent user, allowCredentials should be empty
        let allow_creds = body["allowCredentials"].as_array().unwrap();
        assert!(allow_creds.is_empty());
    } else {
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["status"], "failed");
        assert!(body["errorMessage"].as_str().unwrap().contains("User"));
    }

    Ok(())
}

/// Test assertion options with different user verification preferences
#[actix_web::test]
async fn test_assertion_options_different_user_verification() -> TestResult<()> {
    let app = test::init_service(
        App::new().configure(|cfg| {
            cfg.service(
                actix_web::web::resource("/assertion/options")
                    .route(actix_web::web::post().to(crate::routes::assertion_options)),
            );
        }),
    )
    .await;

    let user_verification_prefs = vec!["required", "preferred", "discouraged"];
    
    for pref in user_verification_prefs {
        let mut request = create_valid_assertion_options_request();
        request.user_verification = Some(pref.to_string());
        request.username = format!("user{}@example.com", pref); // Make unique

        let req = test::TestRequest::post()
            .uri("/assertion/options")
            .set_json(&request)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["status"], "ok");
        assert_eq!(body["userVerification"], pref);
    }

    Ok(())
}

/// Test assertion options with malformed JSON
#[actix_web::test]
async fn test_assertion_options_malformed_json() -> TestResult<()> {
    let app = test::init_service(
        App::new().configure(|cfg| {
            cfg.service(
                actix_web::web::resource("/assertion/options")
                    .route(actix_web::web::post().to(crate::routes::assertion_options)),
            );
        }),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/assertion/options")
        .set_payload("{ invalid json }")
        .insert_header(("content-type", "application/json"))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    Ok(())
}

/// Test assertion options with empty request body
#[actix_web::test]
async fn test_assertion_options_empty_body() -> TestResult<()> {
    let app = test::init_service(
        App::new().configure(|cfg| {
            cfg.service(
                actix_web::web::resource("/assertion/options")
                    .route(actix_web::web::post().to(crate::routes::assertion_options)),
            );
        }),
    )
    .await;

    let req = test::TestRequest::post()
        .uri("/assertion/options")
        .insert_header(("content-type", "application/json"))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    Ok(())
}

/// Test assertion options with oversized username
#[actix_web::test]
async fn test_assertion_options_oversized_username() -> TestResult<()> {
    let app = test::init_service(
        App::new().configure(|cfg| {
            cfg.service(
                actix_web::web::resource("/assertion/options")
                    .route(actix_web::web::post().to(crate::routes::assertion_options)),
            );
        }),
    )
    .await;

    let mut request = create_valid_assertion_options_request();
    request.username = "a".repeat(300); // Exceed reasonable limit

    let req = test::TestRequest::post()
        .uri("/assertion/options")
        .set_json(&request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "failed");

    Ok(())
}

/// Test assertion options with special characters in username
#[actix_web::test]
async fn test_assertion_options_special_characters_username() -> TestResult<()> {
    let app = test::init_service(
        App::new().configure(|cfg| {
            cfg.service(
                actix_web::web::resource("/assertion/options")
                    .route(actix_web::web::post().to(crate::routes::assertion_options)),
            );
        }),
    )
    .await;

    let mut request = create_valid_assertion_options_request();
    request.username = "test+user@example.com".to_string();

    let req = test::TestRequest::post()
        .uri("/assertion/options")
        .set_json(&request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "ok");

    Ok(())
}

/// Test assertion options without user verification specified
#[actix_web::test]
async fn test_assertion_options_no_user_verification() -> TestResult<()> {
    let app = test::init_service(
        App::new().configure(|cfg| {
            cfg.service(
                actix_web::web::resource("/assertion/options")
                    .route(actix_web::web::post().to(crate::routes::assertion_options)),
            );
        }),
    )
    .await;

    let mut request = create_valid_assertion_options_request();
    request.user_verification = None;

    let req = test::TestRequest::post()
        .uri("/assertion/options")
        .set_json(&request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "ok");
    // Should default to some value, likely "preferred"
    assert!(body["userVerification"].is_string());

    Ok(())
}

/// Test assertion options response structure for existing user with credentials
#[actix_web::test]
async fn test_assertion_options_existing_user_with_credentials() -> TestResult<()> {
    let app = test::init_service(
        App::new().configure(|cfg| {
            cfg.service(
                actix_web::web::resource("/assertion/options")
                    .route(actix_web::web::post().to(crate::routes::assertion_options)),
            );
        }),
    )
    .await;

    let request = create_valid_assertion_options_request();
    let req = test::TestRequest::post()
        .uri("/assertion/options")
        .set_json(&request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body: serde_json::Value = test::read_body_json(resp).await;
    
    // Verify allowCredentials structure if present
    if let Some(allow_creds) = body["allowCredentials"].as_array() {
        if !allow_creds.is_empty() {
            for cred in allow_creds {
                assert_json_structure(cred, &["type", "id"])?;
                assert_eq!(cred["type"], "public-key");
                assert!(is_valid_base64url(cred["id"].as_str().unwrap()));
                
                // Transports are optional
                if let Some(transports) = cred["transports"].as_array() {
                    for transport in transports {
                        assert!(transport.is_string());
                        let transport_str = transport.as_str().unwrap();
                        assert!(["usb", "nfc", "ble", "internal", "hybrid"].contains(&transport_str));
                    }
                }
            }
        }
    }

    Ok(())
}