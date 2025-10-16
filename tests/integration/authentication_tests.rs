//! Authentication integration tests

use actix_web::{test, web, App};
use fido_server::routes::api::configure;
use fido_server::models::{
    ServerPublicKeyCredentialGetOptionsRequest,
    ServerPublicKeyCredentialAssertion,
    ServerAuthenticatorAssertionResponse,
};

#[actix_web::test]
async fn test_assertion_options_success() {
    let app = test::init_service(
        App::new().configure(configure)
    ).await;

    let req = test::TestRequest::post()
        .uri("/assertion/options")
        .set_json(&ServerPublicKeyCredentialGetOptionsRequest {
            username: "johndoe@example.com".to_string(),
            user_verification: Some("required".to_string()),
        })
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert_eq!(resp.status(), 200);
    
    let body: serde_json::Value = test::read_body_json(resp).await;
    
    // Verify response structure
    assert_eq!(body["status"], "ok");
    assert_eq!(body["errorMessage"], "");
    assert!(!body["challenge"].as_str().unwrap().is_empty());
    assert_eq!(body["timeout"], 20000);
    assert_eq!(body["rpId"], "example.com");
    assert!(body["allowCredentials"].as_array().unwrap().is_empty());
    assert_eq!(body["userVerification"], "required");
}

#[actix_web::test]
async fn test_assertion_options_default_user_verification() {
    let app = test::init_service(
        App::new().configure(configure)
    ).await;

    let req = test::TestRequest::post()
        .uri("/assertion/options")
        .set_json(&ServerPublicKeyCredentialGetOptionsRequest {
            username: "test@example.com".to_string(),
            user_verification: None,
        })
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert_eq!(resp.status(), 200);
    
    let body: serde_json::Value = test::read_body_json(resp).await;
    
    assert_eq!(body["status"], "ok");
    // userVerification should be None when not provided
    assert!(body["userVerification"].is_null() || body.as_object().unwrap().get("userVerification").is_none());
}

#[actix_web::test]
async fn test_assertion_result_success() {
    let app = test::init_service(
        App::new().configure(configure)
    ).await;

    let req = test::TestRequest::post()
        .uri("/assertion/result")
        .set_json(&ServerPublicKeyCredentialAssertion {
            id: "test-credential-id".to_string(),
            cred_type: "public-key".to_string(),
            response: ServerAuthenticatorAssertionResponse {
                authenticator_data: "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA".to_string(),
                signature: "MEUCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL".to_string(),
                user_handle: Some("".to_string()),
                client_data_json: "eyJ0ZXN0IjoidmFsdWUifQ==".to_string(),
            },
            get_client_extension_results: None,
        })
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert_eq!(resp.status(), 200);
    
    let body: serde_json::Value = test::read_body_json(resp).await;
    
    assert_eq!(body["status"], "ok");
    assert_eq!(body["errorMessage"], "");
}

#[actix_web::test]
async fn test_assertion_result_missing_credential_id() {
    let app = test::init_service(
        App::new().configure(configure)
    ).await;

    let mut assertion = ServerPublicKeyCredentialAssertion {
        id: "".to_string(), // Empty ID should cause error
        cred_type: "public-key".to_string(),
        response: ServerAuthenticatorAssertionResponse {
            authenticator_data: "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA".to_string(),
            signature: "MEUCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL".to_string(),
            user_handle: Some("".to_string()),
            client_data_json: "eyJ0ZXN0IjoidmFsdWUifQ==".to_string(),
        },
        get_client_extension_results: None,
    };

    let req = test::TestRequest::post()
        .uri("/assertion/result")
        .set_json(&assertion)
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert_eq!(resp.status(), 400);
    
    let body: serde_json::Value = test::read_body_json(resp).await;
    
    assert_eq!(body["status"], "failed");
    assert!(body["errorMessage"].as_str().unwrap().contains("Missing credential ID"));
}

#[actix_web::test]
async fn test_assertion_result_missing_client_data() {
    let app = test::init_service(
        App::new().configure(configure)
    ).await;

    let assertion = ServerPublicKeyCredentialAssertion {
        id: "test-credential-id".to_string(),
        cred_type: "public-key".to_string(),
        response: ServerAuthenticatorAssertionResponse {
            authenticator_data: "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA".to_string(),
            signature: "MEUCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL".to_string(),
            user_handle: Some("".to_string()),
            client_data_json: "".to_string(), // Empty client data should cause error
        },
        get_client_extension_results: None,
    };

    let req = test::TestRequest::post()
        .uri("/assertion/result")
        .set_json(&assertion)
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert_eq!(resp.status(), 400);
    
    let body: serde_json::Value = test::read_body_json(resp).await;
    
    assert_eq!(body["status"], "failed");
    assert!(body["errorMessage"].as_str().unwrap().contains("Missing clientDataJSON"));
}

#[actix_web::test]
async fn test_assertion_result_missing_authenticator_data() {
    let app = test::init_service(
        App::new().configure(configure)
    ).await;

    let assertion = ServerPublicKeyCredentialAssertion {
        id: "test-credential-id".to_string(),
        cred_type: "public-key".to_string(),
        response: ServerAuthenticatorAssertionResponse {
            authenticator_data: "".to_string(), // Empty authenticator data should cause error
            signature: "MEUCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL".to_string(),
            user_handle: Some("".to_string()),
            client_data_json: "eyJ0ZXN0IjoidmFsdWUifQ==".to_string(),
        },
        get_client_extension_results: None,
    };

    let req = test::TestRequest::post()
        .uri("/assertion/result")
        .set_json(&assertion)
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert_eq!(resp.status(), 400);
    
    let body: serde_json::Value = test::read_body_json(resp).await;
    
    assert_eq!(body["status"], "failed");
    assert!(body["errorMessage"].as_str().unwrap().contains("Missing authenticatorData"));
}

#[actix_web::test]
async fn test_assertion_result_missing_signature() {
    let app = test::init_service(
        App::new().configure(configure)
    ).await;

    let assertion = ServerPublicKeyCredentialAssertion {
        id: "test-credential-id".to_string(),
        cred_type: "public-key".to_string(),
        response: ServerAuthenticatorAssertionResponse {
            authenticator_data: "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA".to_string(),
            signature: "".to_string(), // Empty signature should cause error
            user_handle: Some("".to_string()),
            client_data_json: "eyJ0ZXN0IjoidmFsdWUifQ==".to_string(),
        },
        get_client_extension_results: None,
    };

    let req = test::TestRequest::post()
        .uri("/assertion/result")
        .set_json(&assertion)
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert_eq!(resp.status(), 400);
    
    let body: serde_json::Value = test::read_body_json(resp).await;
    
    assert_eq!(body["status"], "failed");
    assert!(body["errorMessage"].as_str().unwrap().contains("Missing signature"));
}