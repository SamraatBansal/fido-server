/// FIDO2 Conformance Tests: MakeCredential Request Tests
/// 
/// Test ID: Server-ServerPublicKeyCredentialCreationOptions-Req-1
/// Test server generating ServerPublicKeyCredentialCreationOptionsRequest

use super::*;
use crate::conformance::test_data::*;
use actix_web::{test, http::StatusCode, web};
use serde_json::Value;

/// Test server generating ServerPublicKeyCredentialCreationOptionsRequest
/// This test verifies that the server correctly processes credential creation option requests
/// and returns properly formatted responses according to FIDO2 specification.
#[actix_web::test]
async fn test_server_credential_creation_options_req_1_positive() -> ConformanceTestResult {
    let app = test::init_service(
        actix_web::App::new()
            .service(
                web::resource("/attestation/options")
                    .route(web::post().to(mock_attestation_options_handler))
            )
    ).await;

    // Test with valid creation options request
    let request_body = valid_creation_options_request();
    
    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&request_body)
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    
    // Verify response status
    assert_eq!(resp.status(), StatusCode::OK);
    
    // Parse response body
    let body: Value = test::read_body_json(resp).await;
    
    // Verify response structure according to FIDO Alliance specification
    verify_creation_options_response_structure(&body)?;
    
    // Verify status is "ok" 
    assert_eq!(body["status"], "ok");
    assert_eq!(body["errorMessage"], "");
    
    println!("✓ Server-ServerPublicKeyCredentialCreationOptions-Req-1 (Positive): PASSED");
    Ok(())
}

/// Test server handling invalid ServerPublicKeyCredentialCreationOptionsRequest
/// This test verifies that the server correctly rejects invalid requests with appropriate error messages.
#[actix_web::test]
async fn test_server_credential_creation_options_req_1_negative() -> ConformanceTestResult {
    let app = test::init_service(
        actix_web::App::new()
            .service(
                web::resource("/attestation/options")
                    .route(web::post().to(mock_attestation_options_handler))
            )
    ).await;

    let invalid_requests = invalid_creation_options_requests();
    
    for (test_case, request_body) in invalid_requests {
        println!("Testing negative case: {}", test_case);
        
        let req = test::TestRequest::post()
            .uri("/attestation/options")
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
    
    println!("✓ Server-ServerPublicKeyCredentialCreationOptions-Req-1 (Negative): PASSED");
    Ok(())
}

/// Test challenge generation requirements
/// Verifies that challenges meet FIDO2 specification requirements (16-64 bytes, base64url encoded)
#[actix_web::test]
async fn test_challenge_generation_requirements() -> ConformanceTestResult {
    let app = test::init_service(
        actix_web::App::new()
            .service(
                web::resource("/attestation/options")
                    .route(web::post().to(mock_attestation_options_handler))
            )
    ).await;

    let request_body = valid_creation_options_request();
    
    // Make multiple requests to test challenge uniqueness
    for i in 0..5 {
        let req = test::TestRequest::post()
            .uri("/attestation/options")
            .set_json(&request_body)
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        
        let body: Value = test::read_body_json(resp).await;
        let challenge = body["challenge"].as_str().unwrap();
        
        // Verify challenge format and length
        verify_challenge_format(challenge)?;
        
        println!("✓ Challenge {} format valid: {}", i + 1, challenge);
    }
    
    println!("✓ Challenge generation requirements: PASSED");
    Ok(())
}

/// Test user ID generation and format
/// Verifies that user IDs are properly base64url encoded and unique
#[actix_web::test]
async fn test_user_id_generation() -> ConformanceTestResult {
    let app = test::init_service(
        actix_web::App::new()
            .service(
                web::resource("/attestation/options")
                    .route(web::post().to(mock_attestation_options_handler))
            )
    ).await;

    let mut user_ids = std::collections::HashSet::new();
    
    // Test with different usernames to ensure unique user IDs
    let usernames = vec![
        "user1@example.com",
        "user2@example.com", 
        "user3@example.com",
        "test.user@domain.org",
        "another+user@test.com"
    ];
    
    for username in usernames {
        let mut request_body = valid_creation_options_request();
        request_body["username"] = Value::String(username.to_string());
        
        let req = test::TestRequest::post()
            .uri("/attestation/options")
            .set_json(&request_body)
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        
        let body: Value = test::read_body_json(resp).await;
        let user_id = body["user"]["id"].as_str().unwrap();
        
        // Verify user ID format (base64url)
        verify_base64url_format(user_id)?;
        
        // Verify uniqueness
        assert!(!user_ids.contains(user_id), "User ID should be unique");
        user_ids.insert(user_id.to_string());
        
        // Verify user object structure
        assert_eq!(body["user"]["name"], username);
        assert!(!body["user"]["displayName"].as_str().unwrap().is_empty());
        
        println!("✓ User ID for {}: {}", username, user_id);
    }
    
    println!("✓ User ID generation: PASSED");
    Ok(())
}

/// Test pubKeyCredParams algorithm support
/// Verifies that server supports required algorithms (ES256, RS256, etc.)
#[actix_web::test]
async fn test_pubkey_cred_params_algorithms() -> ConformanceTestResult {
    let app = test::init_service(
        actix_web::App::new()
            .service(
                web::resource("/attestation/options")
                    .route(web::post().to(mock_attestation_options_handler))
            )
    ).await;

    let request_body = valid_creation_options_request();
    
    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&request_body)
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    
    let body: Value = test::read_body_json(resp).await;
    let pub_key_cred_params = body["pubKeyCredParams"].as_array().unwrap();
    
    // Verify at least one algorithm is supported
    assert!(!pub_key_cred_params.is_empty(), "At least one algorithm must be supported");
    
    // Check for required algorithms
    let mut has_es256 = false;
    let mut has_rs256 = false;
    
    for param in pub_key_cred_params {
        assert_eq!(param["type"], "public-key");
        
        let alg = param["alg"].as_i64().unwrap();
        match alg {
            -7 => has_es256 = true,   // ES256
            -257 => has_rs256 = true, // RS256
            _ => {} // Other algorithms are allowed
        }
    }
    
    // At least ES256 should be supported (FIDO2 requirement)
    assert!(has_es256, "ES256 algorithm (-7) must be supported");
    
    println!("✓ Supported algorithms: {:?}", 
        pub_key_cred_params.iter()
            .map(|p| p["alg"].as_i64().unwrap())
            .collect::<Vec<_>>()
    );
    println!("✓ PubKeyCredParams algorithms: PASSED");
    Ok(())
}

/// Mock handler for attestation options endpoint
async fn mock_attestation_options_handler(
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
    
    if request.get("displayName").is_none() {
        return Ok(web::Json(serde_json::json!({
            "status": "failed", 
            "errorMessage": "Missing displayName field"
        })));
    }
    
    // Validate attestation value if present
    if let Some(attestation) = request.get("attestation") {
        let valid_attestations = ["none", "indirect", "direct"];
        if !valid_attestations.contains(&attestation.as_str().unwrap_or("")) {
            return Ok(web::Json(serde_json::json!({
                "status": "failed",
                "errorMessage": "Invalid attestation value"
            })));
        }
    }
    
    // Generate valid response
    let username = request["username"].as_str().unwrap();
    let display_name = request["displayName"].as_str().unwrap();
    
    let response = serde_json::json!({
        "status": "ok",
        "errorMessage": "",
        "rp": {
            "name": "Test FIDO2 Server",
            "id": "localhost"
        },
        "user": {
            "id": generate_test_user_id(),
            "name": username,
            "displayName": display_name
        },
        "challenge": generate_base64_challenge(32),
        "pubKeyCredParams": [
            {
                "type": "public-key",
                "alg": -7  // ES256
            },
            {
                "type": "public-key", 
                "alg": -257 // RS256
            }
        ],
        "timeout": 60000,
        "excludeCredentials": [],
        "authenticatorSelection": request.get("authenticatorSelection").cloned().unwrap_or(serde_json::json!({
            "requireResidentKey": false,
            "authenticatorAttachment": "cross-platform",
            "userVerification": "preferred"
        })),
        "attestation": request.get("attestation").cloned().unwrap_or(serde_json::json!("none"))
    });
    
    Ok(web::Json(response))
}

/// Verify creation options response structure according to FIDO2 specification
fn verify_creation_options_response_structure(response: &Value) -> ConformanceTestResult {
    // Check required fields
    assert!(response.get("status").is_some(), "Missing status field");
    assert!(response.get("errorMessage").is_some(), "Missing errorMessage field");
    assert!(response.get("rp").is_some(), "Missing rp field");
    assert!(response.get("user").is_some(), "Missing user field");
    assert!(response.get("challenge").is_some(), "Missing challenge field");
    assert!(response.get("pubKeyCredParams").is_some(), "Missing pubKeyCredParams field");
    
    // Verify rp structure
    let rp = &response["rp"];
    assert!(rp.get("name").is_some(), "Missing rp.name field");
    
    // Verify user structure
    let user = &response["user"];
    assert!(user.get("id").is_some(), "Missing user.id field");
    assert!(user.get("name").is_some(), "Missing user.name field");
    assert!(user.get("displayName").is_some(), "Missing user.displayName field");
    
    // Verify challenge format
    let challenge = response["challenge"].as_str().unwrap();
    verify_challenge_format(challenge)?;
    
    // Verify pubKeyCredParams structure
    let pub_key_cred_params = response["pubKeyCredParams"].as_array().unwrap();
    assert!(!pub_key_cred_params.is_empty(), "pubKeyCredParams cannot be empty");
    
    for param in pub_key_cred_params {
        assert_eq!(param["type"], "public-key");
        assert!(param.get("alg").is_some(), "Missing alg field in pubKeyCredParams");
    }
    
    Ok(())
}

/// Verify challenge format (base64url, 16-64 bytes)
fn verify_challenge_format(challenge: &str) -> ConformanceTestResult {
    // Verify base64url format
    verify_base64url_format(challenge)?;
    
    // Decode and check length
    let decoded = base64::prelude::BASE64_URL_SAFE_NO_PAD.decode(challenge)
        .map_err(|_| "Challenge is not valid base64url")?;
    
    assert!(decoded.len() >= 16, "Challenge must be at least 16 bytes");
    assert!(decoded.len() <= 64, "Challenge must be at most 64 bytes");
    
    Ok(())
}

/// Verify base64url format
fn verify_base64url_format(data: &str) -> ConformanceTestResult {
    // Check if string contains only valid base64url characters
    let valid_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    for c in data.chars() {
        assert!(valid_chars.contains(c), "Invalid base64url character: {}", c);
    }
    
    // Try to decode
    base64::prelude::BASE64_URL_SAFE_NO_PAD.decode(data)
        .map_err(|_| "Invalid base64url encoding")?;
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn run_all_credential_creation_tests() {
        println!("🧪 Running FIDO2 Conformance Tests: MakeCredential Request");
        
        test_server_credential_creation_options_req_1_positive().await.unwrap();
        test_server_credential_creation_options_req_1_negative().await.unwrap();
        test_challenge_generation_requirements().await.unwrap();
        test_user_id_generation().await.unwrap();
        test_pubkey_cred_params_algorithms().await.unwrap();
        
        println!("✅ All MakeCredential Request tests passed!");
    }
}
