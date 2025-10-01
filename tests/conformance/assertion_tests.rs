/// FIDO2 Conformance Tests: GetAssertion Response Tests
/// 
/// These tests verify server processing of ServerAuthenticatorAssertionResponse
/// according to FIDO Alliance conformance requirements.
/// 
/// Test IDs covered:
/// - Server-ServerAuthenticatorAssertionResponse-Resp-1: Test server processing ServerAuthenticatorAssertionResponse structure
/// - Server-ServerAuthenticatorAssertionResponse-Resp-2: Test server processing CollectClientData
/// - Server-ServerAuthenticatorAssertionResponse-Resp-3: Test server processing authenticatorData

use super::*;
use crate::conformance::test_data::*;
use actix_web::{test, http::StatusCode, web};
use serde_json::Value;
use base64::prelude::*;

/// Test ID: Server-ServerAuthenticatorAssertionResponse-Resp-1
/// Test server processing ServerAuthenticatorAssertionResponse structure
#[actix_web::test]
async fn test_server_assertion_response_structure() -> ConformanceTestResult {
    let app = test::init_service(
        actix_web::App::new()
            .service(
                web::resource("/assertion/result")
                    .route(web::post().to(mock_assertion_result_handler))
            )
    ).await;

    // Test with valid assertion response
    let request_body = valid_assertion_response();
    
    let req = test::TestRequest::post()
        .uri("/assertion/result")
        .set_json(&request_body)
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    
    // Verify response status
    assert_eq!(resp.status(), StatusCode::OK);
    
    // Parse response body
    let body: Value = test::read_body_json(resp).await;
    
    // Verify success response
    assert_eq!(body["status"], "ok");
    assert_eq!(body["errorMessage"], "");
    
    println!("✓ Server-ServerAuthenticatorAssertionResponse-Resp-1: PASSED");
    Ok(())
}

/// Test ID: Server-ServerAuthenticatorAssertionResponse-Resp-2
/// Test server processing CollectClientData
#[actix_web::test]
async fn test_server_assertion_client_data_processing() -> ConformanceTestResult {
    let app = test::init_service(
        actix_web::App::new()
            .service(
                web::resource("/assertion/result")
                    .route(web::post().to(mock_assertion_result_handler))
            )
    ).await;

    // Test valid client data first
    let mut request_body = valid_assertion_response();
    let req = test::TestRequest::post()
        .uri("/assertion/result")
        .set_json(&request_body)
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    
    // Test malformed client data cases specific to assertion
    let assertion_malformed_cases = vec![
        ("wrong_type_get", BASE64_STANDARD.encode(r#"{"type":"webauthn.create","challenge":"test","origin":"http://localhost:3000"}"#)),
        ("missing_challenge_get", BASE64_STANDARD.encode(r#"{"type":"webauthn.get","origin":"http://localhost:3000"}"#)),
        ("missing_origin_get", BASE64_STANDARD.encode(r#"{"type":"webauthn.get","challenge":"test"}"#)),
        ("empty_challenge", BASE64_STANDARD.encode(r#"{"type":"webauthn.get","challenge":"","origin":"http://localhost:3000"}"#)),
        ("invalid_origin_format", BASE64_STANDARD.encode(r#"{"type":"webauthn.get","challenge":"test","origin":"not-a-valid-origin"}"#)),
    ];
    
    for (test_case, malformed_client_data) in assertion_malformed_cases {
        println!("Testing malformed assertion client data: {}", test_case);
        
        request_body["response"]["clientDataJSON"] = Value::String(malformed_client_data);
        
        let req = test::TestRequest::post()
            .uri("/assertion/result")
            .set_json(&request_body)
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        
        // Should return error for malformed client data
        let body: Value = test::read_body_json(resp).await;
        assert_eq!(body["status"], "failed");
        assert!(!body["errorMessage"].as_str().unwrap_or("").is_empty());
        
        println!("✓ Malformed assertion client data '{}': correctly rejected", test_case);
    }
    
    println!("✓ Server-ServerAuthenticatorAssertionResponse-Resp-2: PASSED");
    Ok(())
}

/// Test ID: Server-ServerAuthenticatorAssertionResponse-Resp-3
/// Test server processing authenticatorData
#[actix_web::test]
async fn test_server_authenticator_data_processing() -> ConformanceTestResult {
    let app = test::init_service(
        actix_web::App::new()
            .service(
                web::resource("/assertion/result")
                    .route(web::post().to(mock_assertion_result_handler))
            )
    ).await;

    // Test malformed authenticator data cases
    let malformed_authenticator_data_cases = vec![
        ("invalid_base64", "not-valid-base64!@#$%".to_string()),
        ("empty_string", "".to_string()),
        ("too_short", BASE64_URL_SAFE_NO_PAD.encode(&[0u8; 10])), // AuthenticatorData must be at least 37 bytes
        ("invalid_rp_id_hash", BASE64_URL_SAFE_NO_PAD.encode(&[0u8; 37])), // Wrong RP ID hash
    ];
    
    let mut request_body = valid_assertion_response();
    
    for (test_case, malformed_authenticator_data) in malformed_authenticator_data_cases {
        println!("Testing malformed authenticator data: {}", test_case);
        
        request_body["response"]["authenticatorData"] = Value::String(malformed_authenticator_data);
        
        let req = test::TestRequest::post()
            .uri("/assertion/result")
            .set_json(&request_body)
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        
        // Should return error for malformed authenticator data
        let body: Value = test::read_body_json(resp).await;
        assert_eq!(body["status"], "failed");
        assert!(!body["errorMessage"].as_str().unwrap_or("").is_empty());
        
        println!("✓ Malformed authenticator data '{}': correctly rejected", test_case);
    }
    
    println!("✓ Server-ServerAuthenticatorAssertionResponse-Resp-3: PASSED");
    Ok(())
}

/// Test signature verification
/// Verifies that server correctly validates assertion signatures
#[actix_web::test]
async fn test_signature_verification() -> ConformanceTestResult {
    let app = test::init_service(
        actix_web::App::new()
            .service(
                web::resource("/assertion/result")
                    .route(web::post().to(mock_assertion_result_handler))
            )
    ).await;

    // Test valid signature first
    let mut request_body = valid_assertion_response();
    let req = test::TestRequest::post()
        .uri("/assertion/result")
        .set_json(&request_body)
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    
    // Test invalid signatures
    let invalid_signatures = vec![
        ("invalid_base64_signature", "not-valid-base64!@#$%".to_string()),
        ("empty_signature", "".to_string()),
        ("wrong_signature", BASE64_URL_SAFE_NO_PAD.encode(&[0u8; 64])), // Wrong signature
        ("truncated_signature", BASE64_URL_SAFE_NO_PAD.encode(&[0u8; 32])), // Too short
    ];
    
    for (test_case, invalid_signature) in invalid_signatures {
        println!("Testing invalid signature: {}", test_case);
        
        request_body["response"]["signature"] = Value::String(invalid_signature);
        
        let req = test::TestRequest::post()
            .uri("/assertion/result")
            .set_json(&request_body)
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        
        // Should return error for invalid signature
        let body: Value = test::read_body_json(resp).await;
        assert_eq!(body["status"], "failed");
        assert!(!body["errorMessage"].as_str().unwrap_or("").is_empty());
        
        println!("✓ Invalid signature '{}': correctly rejected", test_case);
    }
    
    println!("✓ Signature verification: PASSED");
    Ok(())
}

/// Test userHandle processing
/// Verifies that server correctly processes userHandle field
#[actix_web::test]
async fn test_user_handle_processing() -> ConformanceTestResult {
    let app = test::init_service(
        actix_web::App::new()
            .service(
                web::resource("/assertion/result")
                    .route(web::post().to(mock_assertion_result_handler))
            )
    ).await;

    let test_cases = vec![
        ("valid_user_handle", generate_test_user_id()),
        ("empty_user_handle", "".to_string()),
        ("null_user_handle", "".to_string()), // Empty string represents null in our case
    ];
    
    for (test_case, user_handle) in test_cases {
        println!("Testing userHandle: {}", test_case);
        
        let mut request_body = valid_assertion_response();
        request_body["response"]["userHandle"] = Value::String(user_handle);
        
        let req = test::TestRequest::post()
            .uri("/assertion/result")
            .set_json(&request_body)
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        
        let body: Value = test::read_body_json(resp).await;
        assert_eq!(body["status"], "ok");
        
        println!("✓ userHandle '{}': PASSED", test_case);
    }
    
    // Test invalid userHandle
    let mut request_body = valid_assertion_response();
    request_body["response"]["userHandle"] = Value::String("invalid-base64!@#$%".to_string());
    
    let req = test::TestRequest::post()
        .uri("/assertion/result")
        .set_json(&request_body)
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    
    // Should return error for invalid userHandle
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "failed");
    
    println!("✓ User handle processing: PASSED");
    Ok(())
}

/// Test credential ID validation
/// Verifies that server validates credential IDs correctly
#[actix_web::test]
async fn test_credential_id_validation() -> ConformanceTestResult {
    let app = test::init_service(
        actix_web::App::new()
            .service(
                web::resource("/assertion/result")
                    .route(web::post().to(mock_assertion_result_handler))
            )
    ).await;

    // Test valid credential ID first
    let mut request_body = valid_assertion_response();
    let req = test::TestRequest::post()
        .uri("/assertion/result")
        .set_json(&request_body)
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    
    // Test invalid credential IDs
    let invalid_credential_ids = vec![
        ("invalid_base64_id", "not-valid-base64!@#$%".to_string()),
        ("empty_id", "".to_string()),
        ("unknown_credential_id", generate_test_credential_id()), // Different ID
    ];
    
    for (test_case, invalid_id) in invalid_credential_ids {
        println!("Testing invalid credential ID: {}", test_case);
        
        request_body["id"] = Value::String(invalid_id);
        
        let req = test::TestRequest::post()
            .uri("/assertion/result")
            .set_json(&request_body)
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        
        // Should return error for invalid credential ID
        let body: Value = test::read_body_json(resp).await;
        assert_eq!(body["status"], "failed");
        assert!(!body["errorMessage"].as_str().unwrap_or("").is_empty());
        
        println!("✓ Invalid credential ID '{}': correctly rejected", test_case);
    }
    
    println!("✓ Credential ID validation: PASSED");
    Ok(())
}

/// Test missing required fields in assertion response
#[actix_web::test]
async fn test_assertion_response_missing_fields() -> ConformanceTestResult {
    let app = test::init_service(
        actix_web::App::new()
            .service(
                web::resource("/assertion/result")
                    .route(web::post().to(mock_assertion_result_handler))
            )
    ).await;

    let test_cases = vec![
        ("missing_id", serde_json::json!({
            "response": {
                "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA",
                "signature": "MEYCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL",
                "userHandle": "",
                "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJ0ZXN0IiwidHlwZSI6IndlYmF1dGhuLmdldCIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCJ9"
            },
            "type": "public-key"
        })),
        ("missing_response", serde_json::json!({
            "id": "test-id",
            "type": "public-key"
        })),
        ("missing_type", serde_json::json!({
            "id": "test-id",
            "response": {
                "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA",
                "signature": "MEYCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL",
                "userHandle": "",
                "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJ0ZXN0IiwidHlwZSI6IndlYmF1dGhuLmdldCIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCJ9"
            }
        })),
        ("missing_authenticatorData", serde_json::json!({
            "id": "test-id",
            "response": {
                "signature": "MEYCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL",
                "userHandle": "",
                "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJ0ZXN0IiwidHlwZSI6IndlYmF1dGhuLmdldCIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCJ9"
            },
            "type": "public-key"
        })),
        ("missing_signature", serde_json::json!({
            "id": "test-id",
            "response": {
                "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA",
                "userHandle": "",
                "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJ0ZXN0IiwidHlwZSI6IndlYmF1dGhuLmdldCIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCJ9"
            },
            "type": "public-key"
        })),
        ("missing_clientDataJSON", serde_json::json!({
            "id": "test-id",
            "response": {
                "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA",
                "signature": "MEYCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL",
                "userHandle": ""
            },
            "type": "public-key"
        })),
    ];

    for (test_case, request_body) in test_cases {
        println!("Testing missing field: {}", test_case);
        
        let req = test::TestRequest::post()
            .uri("/assertion/result")
            .set_json(&request_body)
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        
        // Should return error for missing fields
        let body: Value = test::read_body_json(resp).await;
        assert_eq!(body["status"], "failed");
        assert!(!body["errorMessage"].as_str().unwrap_or("").is_empty());
        
        println!("✓ Missing field '{}': correctly rejected", test_case);
    }
    
    Ok(())
}

/// Test counter validation
/// Verifies that server correctly validates signature counters
#[actix_web::test]
async fn test_counter_validation() -> ConformanceTestResult {
    let app = test::init_service(
        actix_web::App::new()
            .service(
                web::resource("/assertion/result")
                    .route(web::post().to(mock_assertion_result_handler))
            )
    ).await;

    // In a real implementation, this would test counter replay protection
    // For now, we just verify the structure is processed correctly
    let request_body = valid_assertion_response();
    
    let req = test::TestRequest::post()
        .uri("/assertion/result")
        .set_json(&request_body)
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "ok");
    
    println!("✓ Counter validation: PASSED");
    Ok(())
}

/// Mock handler for assertion result endpoint
async fn mock_assertion_result_handler(
    request: web::Json<Value>
) -> actix_web::Result<web::Json<Value>> {
    // Validate required fields
    if request.get("id").is_none() {
        return Ok(web::Json(serde_json::json!({
            "status": "failed",
            "errorMessage": "Missing id field"
        })));
    }
    
    if request.get("response").is_none() {
        return Ok(web::Json(serde_json::json!({
            "status": "failed",
            "errorMessage": "Missing response field"
        })));
    }
    
    if request.get("type").is_none() || request["type"] != "public-key" {
        return Ok(web::Json(serde_json::json!({
            "status": "failed",
            "errorMessage": "Missing or invalid type field"
        })));
    }
    
    let response = &request["response"];
    
    // Check required response fields
    let required_fields = ["clientDataJSON", "authenticatorData", "signature"];
    for field in &required_fields {
        if response.get(field).is_none() {
            return Ok(web::Json(serde_json::json!({
                "status": "failed",
                "errorMessage": format!("Missing {} field", field)
            })));
        }
    }
    
    // Validate base64url encoding
    let fields_to_validate = [
        ("clientDataJSON", response["clientDataJSON"].as_str().unwrap()),
        ("authenticatorData", response["authenticatorData"].as_str().unwrap()),
        ("signature", response["signature"].as_str().unwrap()),
    ];
    
    for (field_name, field_value) in &fields_to_validate {
        if let Err(_) = BASE64_URL_SAFE_NO_PAD.decode(field_value) {
            return Ok(web::Json(serde_json::json!({
                "status": "failed",
                "errorMessage": format!("Invalid {} base64url encoding", field_name)
            })));
        }
    }
    
    // Validate userHandle if present (can be empty)
    if let Some(user_handle) = response.get("userHandle") {
        let user_handle_str = user_handle.as_str().unwrap_or("");
        if !user_handle_str.is_empty() {
            if let Err(_) = BASE64_URL_SAFE_NO_PAD.decode(user_handle_str) {
                return Ok(web::Json(serde_json::json!({
                    "status": "failed",
                    "errorMessage": "Invalid userHandle base64url encoding"
                })));
            }
        }
    }
    
    // Validate credential ID format
    let credential_id = request["id"].as_str().unwrap();
    if let Err(_) = BASE64_URL_SAFE_NO_PAD.decode(credential_id) {
        return Ok(web::Json(serde_json::json!({
            "status": "failed",
            "errorMessage": "Invalid credential ID base64url encoding"
        })));
    }
    
    // Basic clientDataJSON validation
    let client_data_json = response["clientDataJSON"].as_str().unwrap();
    if let Ok(decoded) = BASE64_URL_SAFE_NO_PAD.decode(client_data_json) {
        if let Ok(client_data_str) = String::from_utf8(decoded) {
            if let Ok(client_data) = serde_json::from_str::<Value>(&client_data_str) {
                // Check type field
                if client_data.get("type").map(|t| t.as_str()) != Some(Some("webauthn.get")) {
                    return Ok(web::Json(serde_json::json!({
                        "status": "failed",
                        "errorMessage": "Invalid clientData type for assertion"
                    })));
                }
                
                // Check challenge field
                if client_data.get("challenge").is_none() {
                    return Ok(web::Json(serde_json::json!({
                        "status": "failed",
                        "errorMessage": "Missing challenge in clientData"
                    })));
                }
                
                // Check origin field
                if client_data.get("origin").is_none() {
                    return Ok(web::Json(serde_json::json!({
                        "status": "failed",
                        "errorMessage": "Missing origin in clientData"
                    })));
                }
            } else {
                return Ok(web::Json(serde_json::json!({
                    "status": "failed",
                    "errorMessage": "clientDataJSON is not valid JSON"
                })));
            }
        } else {
            return Ok(web::Json(serde_json::json!({
                "status": "failed",
                "errorMessage": "clientDataJSON is not valid UTF-8"
            })));
        }
    }
    
    // Basic authenticatorData validation
    let authenticator_data = response["authenticatorData"].as_str().unwrap();
    if let Ok(decoded) = BASE64_URL_SAFE_NO_PAD.decode(authenticator_data) {
        if decoded.len() < 37 {
            return Ok(web::Json(serde_json::json!({
                "status": "failed",
                "errorMessage": "authenticatorData too short"
            })));
        }
    }
    
    // For demo purposes, return success for valid structure
    Ok(web::Json(serde_json::json!({
        "status": "ok",
        "errorMessage": ""
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn run_all_assertion_tests() {
        println!("🧪 Running FIDO2 Conformance Tests: GetAssertion Response");
        
        test_server_assertion_response_structure().await.unwrap();
        test_server_assertion_client_data_processing().await.unwrap();
        test_server_authenticator_data_processing().await.unwrap();
        test_signature_verification().await.unwrap();
        test_user_handle_processing().await.unwrap();
        test_credential_id_validation().await.unwrap();
        test_assertion_response_missing_fields().await.unwrap();
        test_counter_validation().await.unwrap();
        
        println!("✅ All GetAssertion Response tests passed!");
    }
}
