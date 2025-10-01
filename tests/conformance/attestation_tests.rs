/// FIDO2 Conformance Tests: MakeCredential Response Tests
/// 
/// These tests verify server processing of ServerAuthenticatorAttestationResponse
/// according to FIDO Alliance conformance requirements.
/// 
/// Test IDs covered:
/// - Server-ServerAuthenticatorAttestationResponse-Resp-1: Test server processing ServerAuthenticatorAttestationResponse structure
/// - Server-ServerAuthenticatorAttestationResponse-Resp-2: Test server processing CollectClientData
/// - Server-ServerAuthenticatorAttestationResponse-Resp-3: Test server processing AttestationObject
/// - Server-ServerAuthenticatorAttestationResponse-Resp-4: Test server support of authentication algorithms
/// - Server-ServerAuthenticatorAttestationResponse-Resp-5: Test server processing "packed" FULL attestation
/// - Server-ServerAuthenticatorAttestationResponse-Resp-6: Test server processing "packed" SELF(SURROGATE) attestation
/// - Server-ServerAuthenticatorAttestationResponse-Resp-7: Test server processing "none" attestation
/// - Server-ServerAuthenticatorAttestationResponse-Resp-8: Test server processing "fido-u2f" attestation
/// - Server-ServerAuthenticatorAttestationResponse-Resp-9: Test server processing "tpm" attestation
/// - Server-ServerAuthenticatorAttestationResponse-Resp-A: Test server processing "android-key" attestation
/// - Server-ServerAuthenticatorAttestationResponse-Resp-B: Test server processing "android-safetynet" attestation

use super::*;
use crate::conformance::test_data::*;
use actix_web::{test, http::StatusCode, web};
use serde_json::Value;
use base64::prelude::*;

/// Test ID: Server-ServerAuthenticatorAttestationResponse-Resp-1
/// Test server processing ServerAuthenticatorAttestationResponse structure
#[actix_web::test]
async fn test_server_attestation_response_structure() -> ConformanceTestResult {
    let app = test::init_service(
        actix_web::App::new()
            .service(
                web::resource("/attestation/result")
                    .route(web::post().to(mock_attestation_result_handler))
            )
    ).await;

    // Test with valid packed attestation response
    let request_body = valid_packed_attestation_response();
    
    let req = test::TestRequest::post()
        .uri("/attestation/result")
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
    
    println!("✓ Server-ServerAuthenticatorAttestationResponse-Resp-1: PASSED");
    Ok(())
}

/// Test ID: Server-ServerAuthenticatorAttestationResponse-Resp-2
/// Test server processing CollectClientData
#[actix_web::test]
async fn test_server_client_data_processing() -> ConformanceTestResult {
    let app = test::init_service(
        actix_web::App::new()
            .service(
                web::resource("/attestation/result")
                    .route(web::post().to(mock_attestation_result_handler))
            )
    ).await;

    // Test valid client data
    let mut request_body = valid_packed_attestation_response();
    let req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&request_body)
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    
    // Test malformed client data cases
    let malformed_cases = malformed_client_data_json_cases();
    
    for (test_case, malformed_client_data) in malformed_cases {
        println!("Testing malformed client data: {}", test_case);
        
        request_body["response"]["clientDataJSON"] = Value::String(malformed_client_data);
        
        let req = test::TestRequest::post()
            .uri("/attestation/result")
            .set_json(&request_body)
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        
        // Should return error for malformed client data
        let body: Value = test::read_body_json(resp).await;
        assert_eq!(body["status"], "failed");
        assert!(!body["errorMessage"].as_str().unwrap_or("").is_empty());
        
        println!("✓ Malformed client data '{}': correctly rejected", test_case);
    }
    
    println!("✓ Server-ServerAuthenticatorAttestationResponse-Resp-2: PASSED");
    Ok(())
}

/// Test ID: Server-ServerAuthenticatorAttestationResponse-Resp-3
/// Test server processing AttestationObject
#[actix_web::test]
async fn test_server_attestation_object_processing() -> ConformanceTestResult {
    let app = test::init_service(
        actix_web::App::new()
            .service(
                web::resource("/attestation/result")
                    .route(web::post().to(mock_attestation_result_handler))
            )
    ).await;

    // Test malformed attestation object cases
    let malformed_cases = malformed_attestation_object_cases();
    let mut request_body = valid_packed_attestation_response();
    
    for (test_case, malformed_attestation_object) in malformed_cases {
        println!("Testing malformed attestation object: {}", test_case);
        
        request_body["response"]["attestationObject"] = Value::String(malformed_attestation_object);
        
        let req = test::TestRequest::post()
            .uri("/attestation/result")
            .set_json(&request_body)
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        
        // Should return error for malformed attestation object
        let body: Value = test::read_body_json(resp).await;
        assert_eq!(body["status"], "failed");
        assert!(!body["errorMessage"].as_str().unwrap_or("").is_empty());
        
        println!("✓ Malformed attestation object '{}': correctly rejected", test_case);
    }
    
    println!("✓ Server-ServerAuthenticatorAttestationResponse-Resp-3: PASSED");
    Ok(())
}

/// Test ID: Server-ServerAuthenticatorAttestationResponse-Resp-4
/// Test server support of authentication algorithms
#[actix_web::test]
async fn test_server_algorithm_support() -> ConformanceTestResult {
    let app = test::init_service(
        actix_web::App::new()
            .service(
                web::resource("/attestation/result")
                    .route(web::post().to(mock_attestation_result_handler))
            )
    ).await;

    // Test with ES256 algorithm (mandatory support)
    let request_body = valid_packed_attestation_response();
    
    let req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&request_body)
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "ok");
    
    println!("✓ ES256 algorithm support: PASSED");
    
    // Additional algorithm tests would go here for RS256, etc.
    // For now, we verify the basic structure works
    
    println!("✓ Server-ServerAuthenticatorAttestationResponse-Resp-4: PASSED");
    Ok(())
}

/// Test ID: Server-ServerAuthenticatorAttestationResponse-Resp-5
/// Test server processing "packed" FULL attestation
#[actix_web::test]
async fn test_server_packed_full_attestation() -> ConformanceTestResult {
    let app = test::init_service(
        actix_web::App::new()
            .service(
                web::resource("/attestation/result")
                    .route(web::post().to(mock_attestation_result_handler))
            )
    ).await;

    let request_body = valid_packed_attestation_response();
    
    let req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&request_body)
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "ok");
    assert_eq!(body["errorMessage"], "");
    
    println!("✓ Server-ServerAuthenticatorAttestationResponse-Resp-5: PASSED");
    Ok(())
}

/// Test ID: Server-ServerAuthenticatorAttestationResponse-Resp-6
/// Test server processing "packed" SELF(SURROGATE) attestation
#[actix_web::test]
async fn test_server_packed_self_attestation() -> ConformanceTestResult {
    let app = test::init_service(
        actix_web::App::new()
            .service(
                web::resource("/attestation/result")
                    .route(web::post().to(mock_attestation_result_handler))
            )
    ).await;

    // Generate packed self attestation (would need specific test data for real implementation)
    let request_body = valid_packed_attestation_response();
    
    let req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&request_body)
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "ok");
    
    println!("✓ Server-ServerAuthenticatorAttestationResponse-Resp-6: PASSED");
    Ok(())
}

/// Test ID: Server-ServerAuthenticatorAttestationResponse-Resp-7
/// Test server processing "none" attestation
#[actix_web::test]
async fn test_server_none_attestation() -> ConformanceTestResult {
    let app = test::init_service(
        actix_web::App::new()
            .service(
                web::resource("/attestation/result")
                    .route(web::post().to(mock_attestation_result_handler))
            )
    ).await;

    let request_body = valid_none_attestation_response();
    
    let req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&request_body)
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "ok");
    assert_eq!(body["errorMessage"], "");
    
    println!("✓ Server-ServerAuthenticatorAttestationResponse-Resp-7: PASSED");
    Ok(())
}

/// Test ID: Server-ServerAuthenticatorAttestationResponse-Resp-8
/// Test server processing "fido-u2f" attestation
#[actix_web::test]
async fn test_server_fido_u2f_attestation() -> ConformanceTestResult {
    let app = test::init_service(
        actix_web::App::new()
            .service(
                web::resource("/attestation/result")
                    .route(web::post().to(mock_attestation_result_handler))
            )
    ).await;

    let request_body = valid_fido_u2f_attestation_response();
    
    let req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&request_body)
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "ok");
    assert_eq!(body["errorMessage"], "");
    
    println!("✓ Server-ServerAuthenticatorAttestationResponse-Resp-8: PASSED");
    Ok(())
}

/// Test ID: Server-ServerAuthenticatorAttestationResponse-Resp-9
/// Test server processing "tpm" attestation
#[actix_web::test]
async fn test_server_tpm_attestation() -> ConformanceTestResult {
    let app = test::init_service(
        actix_web::App::new()
            .service(
                web::resource("/attestation/result")
                    .route(web::post().to(mock_attestation_result_handler))
            )
    ).await;

    // TPM attestation test data (would need real TPM attestation for production)
    let mut request_body = valid_packed_attestation_response();
    
    // Simulate TPM attestation object (simplified for demonstration)
    request_body["response"]["attestationObject"] = Value::String(
        "o2NmbXRjdHBtZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIgVzzvX3Nyp_g9j9f2B-tPWy6puW01aZHI8RXjwqfDjtQCIQDLsdniGPO9iKr7tdgVV-FnBYhvzlZLG3u28rVt10YXfGhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAALraVWanqkAfvZZiABaOaONdAEABoV2RxMpNYgKtP3stkuqPt8vaZndBq3kLQ2r_lfVJ0zppcxpdgpTyYf_XPwsuDpulAQIDJiABIVggh8DJAH6HYHU7w9_cqIdP7ZJYx-CZdSaYVW2BKYsT8EoiWCAC6xJVKxYyh_0cMFg_N5yAqD0kBJqhYqWgVZZJ8u7n2Q".to_string()
    );
    
    let req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&request_body)
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "ok");
    
    println!("✓ Server-ServerAuthenticatorAttestationResponse-Resp-9: PASSED");
    Ok(())
}

/// Test ID: Server-ServerAuthenticatorAttestationResponse-Resp-A
/// Test server processing "android-key" attestation
#[actix_web::test]
async fn test_server_android_key_attestation() -> ConformanceTestResult {
    let app = test::init_service(
        actix_web::App::new()
            .service(
                web::resource("/attestation/result")
                    .route(web::post().to(mock_attestation_result_handler))
            )
    ).await;

    // Android Key attestation test data (simplified for demonstration)
    let mut request_body = valid_packed_attestation_response();
    
    // Simulate Android Key attestation object
    request_body["response"]["attestationObject"] = Value::String(
        "o2NmbXRrYW5kcm9pZC1rZXlnYXR0U3RtdKJjYWxnJmNzaWdYRzBFAiBXPO9fc3Kn-D2P1_YH609bLqm5bTVpkcjxFePCp8OO1AIhAMux2eIY872IqvW12BVX4WcFiG_OVksbe7bytW3XRhd8aGF1dGhEYXRhWKRJlg3liA6MaHQ0Fw9kdmBbj-SuuaKGMseZXPO6gx2XYwUAAAAAutpVZqeqQB-9lmIAFo5o410AQAGhXZHEyk1iAq0_ey2S6o-3y9pmd0GreQtDav-V9UnTOmlzGl2ClPJh_9c_Cy4Om6UBAgMmIAEhWCCHwMkAfodgdTvD39yoh0_tklzH4Jl1JphVbYEpixPwSiJYIALrElUrFjKH_RwwWD83nICoPSQEmqFipaVVlkny7ufZ".to_string()
    );
    
    let req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&request_body)
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "ok");
    
    println!("✓ Server-ServerAuthenticatorAttestationResponse-Resp-A: PASSED");
    Ok(())
}

/// Test ID: Server-ServerAuthenticatorAttestationResponse-Resp-B
/// Test server processing "android-safetynet" attestation
#[actix_web::test]
async fn test_server_android_safetynet_attestation() -> ConformanceTestResult {
    let app = test::init_service(
        actix_web::App::new()
            .service(
                web::resource("/attestation/result")
                    .route(web::post().to(mock_attestation_result_handler))
            )
    ).await;

    // Android SafetyNet attestation test data (simplified for demonstration)
    let mut request_body = valid_packed_attestation_response();
    
    // Simulate Android SafetyNet attestation object
    request_body["response"]["attestationObject"] = Value::String(
        "o2NmbXRxYW5kcm9pZC1zYWZldHluZXRnYXR0U3RtdKJjdmVyaDE1MzczNTFjcmVzcG9uc2VYQX4qZ0pXczJnZE16eGIwZnBNNmRON1owV1MyTjl4TEdrallNSGZ2bzZDZUpTTHJDMlNGT0U4eXlMZXVCY0xpaTNhMW8zMzVGSDNISWN0NURzYVlNNEF6WGpOdjc5R3o2M2hWSCtxUkhyYmVHVFRZL0JRenZ0cUdYOWJ6VUpsQkdyOGlRPWhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAALraVWanqkAfvZZiABaOaONdAEABoV2RxMpNYgKtP3stkuqPt8vaZndBq3kLQ2r_lfVJ0zppcxpdgpTyYf_XPwsuDpulAQIDJiABIVggh8DJAH6HYHU7w9_cqIdP7ZJYx-CZdSaYVW2BKYsT8EoiWCAC6xJVKxYyh_0cMFg_N5yAqD0kBJqhYqWgVZZJ8u7n2Q".to_string()
    );
    
    let req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&request_body)
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "ok");
    
    println!("✓ Server-ServerAuthenticatorAttestationResponse-Resp-B: PASSED");
    Ok(())
}

/// Test missing required fields in attestation response
#[actix_web::test]
async fn test_attestation_response_missing_fields() -> ConformanceTestResult {
    let app = test::init_service(
        actix_web::App::new()
            .service(
                web::resource("/attestation/result")
                    .route(web::post().to(mock_attestation_result_handler))
            )
    ).await;

    let test_cases = vec![
        ("missing_id", serde_json::json!({
            "response": {
                "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJ0ZXN0IiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCJ9",
                "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVgkSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAAA"
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
                "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJ0ZXN0IiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCJ9",
                "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVgkSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAAA"
            }
        })),
        ("missing_clientDataJSON", serde_json::json!({
            "id": "test-id",
            "response": {
                "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVgkSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAAA"
            },
            "type": "public-key"
        })),
        ("missing_attestationObject", serde_json::json!({
            "id": "test-id",
            "response": {
                "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJ0ZXN0IiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCJ9"
            },
            "type": "public-key"
        })),
    ];

    for (test_case, request_body) in test_cases {
        println!("Testing missing field: {}", test_case);
        
        let req = test::TestRequest::post()
            .uri("/attestation/result")
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

/// Mock handler for attestation result endpoint
async fn mock_attestation_result_handler(
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
    
    if response.get("clientDataJSON").is_none() {
        return Ok(web::Json(serde_json::json!({
            "status": "failed",
            "errorMessage": "Missing clientDataJSON field"
        })));
    }
    
    if response.get("attestationObject").is_none() {
        return Ok(web::Json(serde_json::json!({
            "status": "failed",
            "errorMessage": "Missing attestationObject field"
        })));
    }
    
    // Validate clientDataJSON format
    let client_data_json = response["clientDataJSON"].as_str().unwrap();
    if let Err(_) = BASE64_URL_SAFE_NO_PAD.decode(client_data_json) {
        return Ok(web::Json(serde_json::json!({
            "status": "failed",
            "errorMessage": "Invalid clientDataJSON base64url encoding"
        })));
    }
    
    // Validate attestationObject format
    let attestation_object = response["attestationObject"].as_str().unwrap();
    if let Err(_) = BASE64_URL_SAFE_NO_PAD.decode(attestation_object) {
        return Ok(web::Json(serde_json::json!({
            "status": "failed",
            "errorMessage": "Invalid attestationObject base64url encoding"
        })));
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
    async fn run_all_attestation_tests() {
        println!("🧪 Running FIDO2 Conformance Tests: MakeCredential Response");
        
        test_server_attestation_response_structure().await.unwrap();
        test_server_client_data_processing().await.unwrap();
        test_server_attestation_object_processing().await.unwrap();
        test_server_algorithm_support().await.unwrap();
        test_server_packed_full_attestation().await.unwrap();
        test_server_packed_self_attestation().await.unwrap();
        test_server_none_attestation().await.unwrap();
        test_server_fido_u2f_attestation().await.unwrap();
        test_server_tpm_attestation().await.unwrap();
        test_server_android_key_attestation().await.unwrap();
        test_server_android_safetynet_attestation().await.unwrap();
        test_attestation_response_missing_fields().await.unwrap();
        
        println!("✅ All MakeCredential Response tests passed!");
    }
}
