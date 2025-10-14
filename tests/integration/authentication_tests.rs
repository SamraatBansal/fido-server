//! Authentication integration tests

use actix_web::{test, App, http::StatusCode};
use serde_json::json;
use fido_server::routes::configure;

#[actix_web::test]
async fn test_assertion_options_success() {
    let app = test::init_service(
        App::new().configure(configure)
    ).await;

    let req = test::TestRequest::post()
        .uri("/assertion/options")
        .set_json(json!({
            "username": "johndoe@example.com",
            "userVerification": "required"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert_eq!(resp.status(), StatusCode::OK);
    
    let result: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(result["status"], "ok");
    assert!(result["challenge"].as_str().is_some());
    assert_eq!(result["userVerification"], "required");
    assert_eq!(result["rpId"], "example.com");
    assert!(result["allowCredentials"].as_array().is_some());
    assert!(result["timeout"].as_u64().is_some());
}

#[actix_web::test]
async fn test_assertion_options_user_not_found() {
    let app = test::init_service(
        App::new().configure(configure)
    ).await;

    let req = test::TestRequest::post()
        .uri("/assertion/options")
        .set_json(json!({
            "username": "nonexistent@example.com",
            "userVerification": "required"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    
    let result: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(result["status"], "failed");
    assert!(result["errorMessage"].as_str().unwrap().contains("User does not exist"));
}

#[actix_web::test]
async fn test_assertion_options_missing_username() {
    let app = test::init_service(
        App::new().configure(configure)
    ).await;

    let req = test::TestRequest::post()
        .uri("/assertion/options")
        .set_json(json!({
            "userVerification": "required"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    
    let result: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(result["status"], "failed");
    assert!(result["errorMessage"].as_str().unwrap().contains("username"));
}

#[actix_web::test]
async fn test_assertion_result_success() {
    let app = test::init_service(
        App::new().configure(configure)
    ).await;

    // First, get assertion options to establish a challenge
    let options_req = test::TestRequest::post()
        .uri("/assertion/options")
        .set_json(json!({
            "username": "johndoe@example.com",
            "userVerification": "required"
        }))
        .to_request();

    let options_resp = test::call_service(&app, options_req).await;
    let options_result: serde_json::Value = test::read_body_json(options_resp).await;
    let challenge = options_result["challenge"].as_str().unwrap();

    // Mock assertion response (this would normally come from an authenticator)
    let req = test::TestRequest::post()
        .uri("/assertion/result")
        .set_json(json!({
            "id": "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
            "response": {
                "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA",
                "signature": "MEYCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL",
                "userHandle": "",
                "clientDataJSON": format!("{{\"challenge\":\"{}\",\"origin\":\"http://localhost:3000\",\"type\":\"webauthn.get\"}}", challenge)
            },
            "getClientExtensionResults": {},
            "type": "public-key"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert_eq!(resp.status(), StatusCode::OK);
    
    let result: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(result["status"], "ok");
    assert_eq!(result["errorMessage"], "");
}

#[actix_web::test]
async fn test_assertion_result_invalid_challenge() {
    let app = test::init_service(
        App::new().configure(configure)
    ).await;

    let req = test::TestRequest::post()
        .uri("/assertion/result")
        .set_json(json!({
            "id": "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
            "response": {
                "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA",
                "signature": "MEYCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL",
                "userHandle": "",
                "clientDataJSON": "{\"challenge\":\"invalid_challenge\",\"origin\":\"http://localhost:3000\",\"type\":\"webauthn.get\"}"
            },
            "getClientExtensionResults": {},
            "type": "public-key"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    
    let result: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(result["status"], "failed");
    assert!(result["errorMessage"].as_str().unwrap().contains("challenge"));
}

#[actix_web::test]
async fn test_assertion_result_missing_fields() {
    let app = test::init_service(
        App::new().configure(configure)
    ).await;

    let req = test::TestRequest::post()
        .uri("/assertion/result")
        .set_json(json!({
            "id": "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
            "type": "public-key"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    
    let result: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(result["status"], "failed");
    assert!(result["errorMessage"].as_str().unwrap().contains("response"));
}

#[actix_web::test]
async fn test_assertion_result_invalid_signature() {
    let app = test::init_service(
        App::new().configure(configure)
    ).await;

    // First, get assertion options to establish a challenge
    let options_req = test::TestRequest::post()
        .uri("/assertion/options")
        .set_json(json!({
            "username": "johndoe@example.com",
            "userVerification": "required"
        }))
        .to_request();

    let options_resp = test::call_service(&app, options_req).await;
    let options_result: serde_json::Value = test::read_body_json(options_resp).await;
    let challenge = options_result["challenge"].as_str().unwrap();

    // Mock assertion response with invalid signature
    let req = test::TestRequest::post()
        .uri("/assertion/result")
        .set_json(json!({
            "id": "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
            "response": {
                "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA",
                "signature": "invalid_signature_data",
                "userHandle": "",
                "clientDataJSON": format!("{{\"challenge\":\"{}\",\"origin\":\"http://localhost:3000\",\"type\":\"webauthn.get\"}}", challenge)
            },
            "getClientExtensionResults": {},
            "type": "public-key"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    
    let result: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(result["status"], "failed");
    assert!(result["errorMessage"].as_str().unwrap().contains("signature"));
}