/// FIDO2 Conformance Tests: GetAssertion Request Tests
/// 
/// Test ID: Server-ServerPublicKeyCredentialGetOptionsResponse-Req-1
/// Test server generating ServerPublicKeyCredentialGetOptionsResponse

use super::*;
use crate::conformance::test_data::*;
use actix_web::{test, http::StatusCode, web};
use serde_json::Value;

/// Test ID: Server-ServerPublicKeyCredentialGetOptionsResponse-Req-1
/// Test server generating ServerPublicKeyCredentialGetOptionsResponse
/// This test verifies that the server correctly processes assertion option requests
/// and returns properly formatted responses according to FIDO2 specification.
#[actix_web::test]
async fn test_server_assertion_options_req_1_positive() -> ConformanceTestResult {
    let app = test::init_service(
        actix_web::App::new()
            .service(
                web::resource("/assertion/options")
                    .route(web::post().to(mock_assertion_options_handler))
            )
    ).await;

    // Test with valid assertion options request
    let request_body = valid_assertion_options_request();
    
    let req = test::TestRequest::post()
        .uri("/assertion/options")
        .set_json(&request_body)
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    
    // Verify response status
    assert_eq!(resp.status(), StatusCode::OK);
    
    // Parse response body
    let body: Value = test::read_body_json(resp).await;
    
    // Verify response structure according to FIDO Alliance specification
    verify_assertion_options_response_structure(&body)?;
    
    // Verify status is "ok" 
    assert_eq!(body["status"], "ok");
    assert_eq!(body["errorMessage"], "");
    
    println!("✓ Server-ServerPublicKeyCredentialGetOptionsResponse-Req-1 (Positive): PASSED");
    Ok(())
}

/// Test server handling invalid ServerPublicKeyCredentialGetOptionsRequest
/// This test verifies that the server correctly rejects invalid requests with appropriate error messages.
#[actix_web::test]
async fn test_server_assertion_options_req_1_negative() -> ConformanceTestResult {
    let app = test::init_service(
        actix_web::App::new()
            .service(
                web::resource("/assertion/options")
                    .route(web::post().to(mock_assertion_options_handler))
            )
    ).await;

    let invalid_requests = invalid_assertion_options_requests();
    
    for (test_case, request_body) in invalid_requests {
        println!("Testing negative case: {}", test_case);
        
        let req = test::TestRequest::post()
            .uri("/assertion/options")
            .set_json(&request_body)
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        
        // Should return 4xx or 5xx status code for invalid requests
        assert!(resp.status().is_client_error() || resp.status().is_server_error());
        
        // Parse error response
        let body: Value = test::read_body_json(resp).await;
        
        // Verify error response structure
        assert_eq!(body["status"], "failed");
        assert!(!body["errorMessage"].as_str().unwrap_or("").is_empty());
        
        println!("✓ Negative case '{}': PASSED", test_case);
    }
    
    println!("✓ Server-ServerPublicKeyCredentialGetOptionsResponse-Req-1 (Negative): PASSED");
    Ok(())
}

/// Test challenge generation for assertion requests
/// Verifies that challenges meet FIDO2 specification requirements (16-64 bytes, base64url encoded)
#[actix_web::test]
async fn test_assertion_challenge_generation() -> ConformanceTestResult {
    let app = test::init_service(
        actix_web::App::new()
            .service(
                web::resource("/assertion/options")
                    .route(web::post().to(mock_assertion_options_handler))
            )
    ).await;

    let request_body = valid_assertion_options_request();
    let mut challenges = std::collections::HashSet::new();
    
    // Make multiple requests to test challenge uniqueness
    for i in 0..5 {
        let req = test::TestRequest::post()
            .uri("/assertion/options")
            .set_json(&request_body)
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        
        let body: Value = test::read_body_json(resp).await;
        let challenge = body["challenge"].as_str().unwrap();
        
        // Verify challenge format and length
        verify_challenge_format(challenge)?;
        
        // Verify uniqueness
        assert!(!challenges.contains(challenge), "Challenge should be unique");
        challenges.insert(challenge.to_string());
        
        println!("✓ Challenge {} format valid: {}", i + 1, challenge);
    }
    
    println!("✓ Assertion challenge generation: PASSED");
    Ok(())
}

/// Test user verification requirement handling
/// Verifies that server correctly handles different userVerification values
#[actix_web::test]
async fn test_user_verification_requirements() -> ConformanceTestResult {
    let app = test::init_service(
        actix_web::App::new()
            .service(
                web::resource("/assertion/options")
                    .route(web::post().to(mock_assertion_options_handler))
            )
    ).await;

    let user_verification_values = vec!["required", "preferred", "discouraged"];
    
    for uv_value in user_verification_values {
        println!("Testing userVerification: {}", uv_value);
        
        let mut request_body = valid_assertion_options_request();
        request_body["userVerification"] = Value::String(uv_value.to_string());
        
        let req = test::TestRequest::post()
            .uri("/assertion/options")
            .set_json(&request_body)
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        
        let body: Value = test::read_body_json(resp).await;
        
        // Verify userVerification is echoed back correctly
        assert_eq!(body["userVerification"], uv_value);
        assert_eq!(body["status"], "ok");
        
        println!("✓ userVerification '{}': PASSED", uv_value);
    }
    
    println!("✓ User verification requirements: PASSED");
    Ok(())
}

/// Test allowCredentials filtering
/// Verifies that server correctly filters and returns allowed credentials
#[actix_web::test]
async fn test_allow_credentials_filtering() -> ConformanceTestResult {
    let app = test::init_service(
        actix_web::App::new()
            .service(
                web::resource("/assertion/options")
                    .route(web::post().to(mock_assertion_options_handler))
            )
    ).await;

    let request_body = valid_assertion_options_request();
    
    let req = test::TestRequest::post()
        .uri("/assertion/options")
        .set_json(&request_body)
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    
    let body: Value = test::read_body_json(resp).await;
    
    // Verify allowCredentials structure
    if let Some(allow_credentials) = body.get("allowCredentials") {
        let credentials = allow_credentials.as_array().unwrap();
        
        for credential in credentials {
            // Verify credential structure
            assert!(credential.get("id").is_some(), "Missing credential id");
            assert!(credential.get("type").is_some(), "Missing credential type");
            assert_eq!(credential["type"], "public-key");
            
            // Verify credential ID format (base64url)
            let cred_id = credential["id"].as_str().unwrap();
            verify_base64url_format(cred_id)?;
            
            // Verify transports if present
            if let Some(transports) = credential.get("transports") {
                let transport_array = transports.as_array().unwrap();
                for transport in transport_array {
                    let transport_str = transport.as_str().unwrap();
                    assert!(
                        ["usb", "nfc", "ble", "smart-card", "hybrid", "internal"].contains(&transport_str),
                        "Invalid transport: {}", transport_str
                    );
                }
            }
        }
        
        println!("✓ Found {} allowed credentials", credentials.len());
    }
    
    println!("✓ Allow credentials filtering: PASSED");
    Ok(())
}

/// Test RP ID validation
/// Verifies that server correctly handles and validates RP ID
#[actix_web::test]
async fn test_rp_id_validation() -> ConformanceTestResult {
    let app = test::init_service(
        actix_web::App::new()
            .service(
                web::resource("/assertion/options")
                    .route(web::post().to(mock_assertion_options_handler))
            )
    ).await;

    let request_body = valid_assertion_options_request();
    
    let req = test::TestRequest::post()
        .uri("/assertion/options")
        .set_json(&request_body)
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    
    let body: Value = test::read_body_json(resp).await;
    
    // Verify RP ID is present and valid format
    if let Some(rp_id) = body.get("rpId") {
        let rp_id_str = rp_id.as_str().unwrap();
        
        // Basic domain format validation
        assert!(!rp_id_str.is_empty(), "RP ID cannot be empty");
        assert!(!rp_id_str.contains("://"), "RP ID should not contain protocol");
        assert!(!rp_id_str.starts_with('.'), "RP ID should not start with dot");
        assert!(!rp_id_str.ends_with('.'), "RP ID should not end with dot");
        
        println!("✓ RP ID format valid: {}", rp_id_str);
    }
    
    println!("✓ RP ID validation: PASSED");
    Ok(())
}

/// Test timeout parameter handling
/// Verifies that server sets appropriate timeout values
#[actix_web::test]
async fn test_timeout_parameter() -> ConformanceTestResult {
    let app = test::init_service(
        actix_web::App::new()
            .service(
                web::resource("/assertion/options")
                    .route(web::post().to(mock_assertion_options_handler))
            )
    ).await;

    let request_body = valid_assertion_options_request();
    
    let req = test::TestRequest::post()
        .uri("/assertion/options")
        .set_json(&request_body)
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    
    let body: Value = test::read_body_json(resp).await;
    
    // Verify timeout if present
    if let Some(timeout) = body.get("timeout") {
        let timeout_ms = timeout.as_u64().unwrap();
        
        // Reasonable timeout bounds (5 seconds to 10 minutes)
        assert!(timeout_ms >= 5000, "Timeout should be at least 5 seconds");
        assert!(timeout_ms <= 600000, "Timeout should be at most 10 minutes");
        
        println!("✓ Timeout value: {} ms", timeout_ms);
    }
    
    println!("✓ Timeout parameter: PASSED");
    Ok(())
}

/// Test extensions parameter handling
/// Verifies that server correctly handles extension parameters
#[actix_web::test]
async fn test_extensions_parameter() -> ConformanceTestResult {
    let app = test::init_service(
        actix_web::App::new()
            .service(
                web::resource("/assertion/options")
                    .route(web::post().to(mock_assertion_options_handler))
            )
    ).await;

    // Test with extensions in request
    let mut request_body = valid_assertion_options_request();
    request_body["extensions"] = serde_json::json!({
        "appid": "https://example.com",
        "txAuthSimple": "Please confirm transaction"
    });
    
    let req = test::TestRequest::post()
        .uri("/assertion/options")
        .set_json(&request_body)
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    
    let body: Value = test::read_body_json(resp).await;
    
    // Verify extensions are handled (may or may not be echoed back)
    if let Some(extensions) = body.get("extensions") {
        println!("✓ Extensions returned: {:?}", extensions);
    } else {
        println!("✓ Extensions not returned (acceptable)");
    }
    
    println!("✓ Extensions parameter: PASSED");
    Ok(())
}

/// Mock handler for assertion options endpoint
async fn mock_assertion_options_handler(
    request: web::Json<Value>
) -> actix_web::Result<web::Json<Value>> {
    // Validate required fields
    if request.get("username").is_none() || 
       request["username"].as_str().unwrap_or("").is_empty() {
        return Ok(web::Json(serde_json::json!({
            "status": "failed",
            "errorMessage": "Missing or empty username field"
        })));
    }
    
    // Validate userVerification value if present
    if let Some(user_verification) = request.get("userVerification") {
        let valid_values = ["required", "preferred", "discouraged"];
        if !valid_values.contains(&user_verification.as_str().unwrap_or("")) {
            return Ok(web::Json(serde_json::json!({
                "status": "failed",
                "errorMessage": "Invalid userVerification value"
            })));
        }
    }
    
    // Generate valid response
    let username = request["username"].as_str().unwrap();
    let user_verification = request.get("userVerification")
        .and_then(|v| v.as_str())
        .unwrap_or("preferred");
    
    // Mock credential lookup - in real implementation, this would query the database
    let allow_credentials = if username == "johndoe@example.com" {
        vec![
            serde_json::json!({
                "id": generate_test_credential_id(),
                "type": "public-key",
                "transports": ["usb", "nfc"]
            }),
            serde_json::json!({
                "id": generate_test_credential_id(),
                "type": "public-key",
                "transports": ["internal"]
            })
        ]
    } else {
        vec![] // No credentials for unknown users
    };
    
    let response = serde_json::json!({
        "status": "ok",
        "errorMessage": "",
        "challenge": generate_base64_challenge(32),
        "timeout": 60000,
        "rpId": "localhost",
        "allowCredentials": allow_credentials,
        "userVerification": user_verification,
        "extensions": request.get("extensions").cloned()
    });
    
    Ok(web::Json(response))
}

/// Verify assertion options response structure according to FIDO2 specification
fn verify_assertion_options_response_structure(response: &Value) -> ConformanceTestResult {
    // Check required fields
    assert!(response.get("status").is_some(), "Missing status field");
    assert!(response.get("errorMessage").is_some(), "Missing errorMessage field");
    assert!(response.get("challenge").is_some(), "Missing challenge field");
    
    // Verify challenge format
    let challenge = response["challenge"].as_str().unwrap();
    verify_challenge_format(challenge)?;
    
    // Verify optional fields format if present
    if let Some(allow_credentials) = response.get("allowCredentials") {
        let credentials = allow_credentials.as_array().unwrap();
        for credential in credentials {
            assert!(credential.get("id").is_some(), "Missing credential id");
            assert!(credential.get("type").is_some(), "Missing credential type");
            assert_eq!(credential["type"], "public-key");
        }
    }
    
    if let Some(user_verification) = response.get("userVerification") {
        let uv_str = user_verification.as_str().unwrap();
        assert!(
            ["required", "preferred", "discouraged"].contains(&uv_str),
            "Invalid userVerification value: {}", uv_str
        );
    }
    
    if let Some(timeout) = response.get("timeout") {
        assert!(timeout.is_number(), "Timeout must be a number");
    }
    
    Ok(())
}

/// Helper function to verify challenge format (reused from credential_creation_tests)
fn verify_challenge_format(challenge: &str) -> ConformanceTestResult {
    verify_base64url_format(challenge)?;
    
    let decoded = base64::prelude::BASE64_URL_SAFE_NO_PAD.decode(challenge)
        .map_err(|_| "Challenge is not valid base64url")?;
    
    assert!(decoded.len() >= 16, "Challenge must be at least 16 bytes");
    assert!(decoded.len() <= 64, "Challenge must be at most 64 bytes");
    
    Ok(())
}

/// Helper function to verify base64url format (reused from credential_creation_tests)
fn verify_base64url_format(data: &str) -> ConformanceTestResult {
    let valid_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    for c in data.chars() {
        assert!(valid_chars.contains(c), "Invalid base64url character: {}", c);
    }
    
    base64::prelude::BASE64_URL_SAFE_NO_PAD.decode(data)
        .map_err(|_| "Invalid base64url encoding")?;
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn run_all_credential_request_tests() {
        println!("🧪 Running FIDO2 Conformance Tests: GetAssertion Request");
        
        test_server_assertion_options_req_1_positive().await.unwrap();
        test_server_assertion_options_req_1_negative().await.unwrap();
        test_assertion_challenge_generation().await.unwrap();
        test_user_verification_requirements().await.unwrap();
        test_allow_credentials_filtering().await.unwrap();
        test_rp_id_validation().await.unwrap();
        test_timeout_parameter().await.unwrap();
        test_extensions_parameter().await.unwrap();
        
        println!("✅ All GetAssertion Request tests passed!");
    }
}
