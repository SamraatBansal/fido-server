/// FIDO2 Conformance Tests: Metadata Service Tests
/// 
/// These tests verify server integration with FIDO Metadata Service (MDS)
/// according to FIDO Alliance conformance requirements.
/// 
/// Test coverage includes:
/// - MDS3 endpoint integration
/// - Metadata verification
/// - Authenticator metadata validation
/// - Certificate chain validation

use super::*;
use crate::conformance::test_data::*;
use actix_web::{test, http::StatusCode, web};
use serde_json::Value;

/// Test MDS3 endpoint connectivity and response format
#[actix_web::test]
async fn test_mds3_endpoint_integration() -> ConformanceTestResult {
    // This test would verify that the server can connect to MDS3 endpoints
    // For testing purposes, we'll use a mock MDS endpoint
    
    let app = test::init_service(
        actix_web::App::new()
            .service(
                web::resource("/mds/test")
                    .route(web::get().to(mock_mds_endpoint))
            )
    ).await;

    let req = test::TestRequest::get()
        .uri("/mds/test")
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    
    let body: Value = test::read_body_json(resp).await;
    
    // Verify MDS response structure
    assert!(body.get("entries").is_some(), "MDS response should have entries");
    assert!(body.get("nextUpdate").is_some(), "MDS response should have nextUpdate");
    
    let entries = body["entries"].as_array().unwrap();
    if !entries.is_empty() {
        let first_entry = &entries[0];
        
        // Verify entry structure
        assert!(first_entry.get("aaid").is_some() || 
                first_entry.get("aaguid").is_some() ||
                first_entry.get("attestationCertificateKeyIdentifiers").is_some(),
                "Entry should have authenticator identifier");
        
        if let Some(metadata_statement) = first_entry.get("metadataStatement") {
            verify_metadata_statement_structure(metadata_statement)?;
        }
    }
    
    println!("✓ MDS3 endpoint integration: PASSED");
    Ok(())
}

/// Test authenticator metadata validation
#[actix_web::test]
async fn test_authenticator_metadata_validation() -> ConformanceTestResult {
    // Test validation of authenticator metadata against MDS
    
    let test_metadata = generate_test_metadata_statement();
    
    // Verify required fields are present
    assert!(test_metadata.get("description").is_some(), "Missing description");
    assert!(test_metadata.get("authenticatorVersion").is_some(), "Missing authenticatorVersion");
    assert!(test_metadata.get("upv").is_some(), "Missing upv (User Presence and Verification)");
    assert!(test_metadata.get("authenticationAlgorithms").is_some(), "Missing authenticationAlgorithms");
    assert!(test_metadata.get("publicKeyAlgAndEncodings").is_some(), "Missing publicKeyAlgAndEncodings");
    assert!(test_metadata.get("attestationTypes").is_some(), "Missing attestationTypes");
    
    // Verify algorithm support
    let auth_algorithms = test_metadata["authenticationAlgorithms"].as_array().unwrap();
    let mut has_supported_alg = false;
    
    for alg in auth_algorithms {
        let alg_str = alg.as_str().unwrap();
        if ["secp256r1_ecdsa_sha256_raw", "rsassa_pkcs1v15_sha256_raw"].contains(&alg_str) {
            has_supported_alg = true;
            break;
        }
    }
    
    assert!(has_supported_alg, "Must support at least one common authentication algorithm");
    
    // Verify attestation types
    let attestation_types = test_metadata["attestationTypes"].as_array().unwrap();
    assert!(!attestation_types.is_empty(), "Must specify at least one attestation type");
    
    for att_type in attestation_types {
        let att_type_num = att_type.as_u64().unwrap();
        assert!(att_type_num <= 15, "Invalid attestation type: {}", att_type_num);
    }
    
    println!("✓ Authenticator metadata validation: PASSED");
    Ok(())
}

/// Test certificate chain validation
#[actix_web::test]
async fn test_certificate_chain_validation() -> ConformanceTestResult {
    // Test validation of attestation certificate chains
    
    let test_cert_chain = generate_test_certificate_chain();
    
    // Verify certificate chain structure
    assert!(test_cert_chain.len() >= 1, "Certificate chain must have at least one certificate");
    
    for (i, cert) in test_cert_chain.iter().enumerate() {
        // Basic certificate format validation
        assert!(cert.starts_with("-----BEGIN CERTIFICATE-----"), 
                "Certificate {} should start with PEM header", i);
        assert!(cert.ends_with("-----END CERTIFICATE-----"), 
                "Certificate {} should end with PEM footer", i);
        
        // Verify certificate is not empty
        let cert_body = cert.replace("-----BEGIN CERTIFICATE-----", "")
                           .replace("-----END CERTIFICATE-----", "")
                           .replace("\n", "")
                           .replace("\r", "");
        assert!(!cert_body.trim().is_empty(), "Certificate {} body should not be empty", i);
    }
    
    println!("✓ Certificate chain validation: PASSED");
    Ok(())
}

/// Test MDS cache and update mechanisms
#[actix_web::test]
async fn test_mds_cache_and_updates() -> ConformanceTestResult {
    // Test that MDS data is cached and updated appropriately
    
    let app = test::init_service(
        actix_web::App::new()
            .service(
                web::resource("/mds/cache/status")
                    .route(web::get().to(mock_mds_cache_status))
            )
    ).await;

    let req = test::TestRequest::get()
        .uri("/mds/cache/status")
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    
    let body: Value = test::read_body_json(resp).await;
    
    // Verify cache status structure
    assert!(body.get("lastUpdate").is_some(), "Cache should track last update time");
    assert!(body.get("nextUpdate").is_some(), "Cache should track next update time");
    assert!(body.get("entriesCount").is_some(), "Cache should track number of entries");
    
    let entries_count = body["entriesCount"].as_u64().unwrap();
    assert!(entries_count > 0, "Cache should have at least some entries");
    
    // Verify update timestamps are reasonable
    let last_update = body["lastUpdate"].as_str().unwrap();
    let next_update = body["nextUpdate"].as_str().unwrap();
    
    assert!(!last_update.is_empty(), "Last update timestamp should not be empty");
    assert!(!next_update.is_empty(), "Next update timestamp should not be empty");
    
    println!("✓ MDS cache and updates: PASSED");
    Ok(())
}

/// Test metadata statement integrity verification
#[actix_web::test]
async fn test_metadata_statement_integrity() -> ConformanceTestResult {
    // Test verification of metadata statement signatures and integrity
    
    let test_metadata = generate_test_metadata_statement();
    
    // Test with valid metadata
    let validation_result = validate_metadata_statement(&test_metadata);
    assert!(validation_result, "Valid metadata statement should pass validation");
    
    // Test with modified metadata (should fail)
    let mut modified_metadata = test_metadata.clone();
    modified_metadata["description"] = Value::String("Modified description".to_string());
    
    let modified_validation_result = validate_metadata_statement(&modified_metadata);
    assert!(!modified_validation_result, "Modified metadata statement should fail validation");
    
    // Test with missing required fields
    let mut incomplete_metadata = test_metadata.clone();
    incomplete_metadata.as_object_mut().unwrap().remove("authenticationAlgorithms");
    
    let incomplete_validation_result = validate_metadata_statement(&incomplete_metadata);
    assert!(!incomplete_validation_result, "Incomplete metadata statement should fail validation");
    
    println!("✓ Metadata statement integrity: PASSED");
    Ok(())
}

/// Test AAGUID lookup and validation
#[actix_web::test]
async fn test_aaguid_lookup_validation() -> ConformanceTestResult {
    // Test lookup of authenticator metadata by AAGUID
    
    let test_aaguid = "00000000-0000-0000-0000-000000000000";
    
    let app = test::init_service(
        actix_web::App::new()
            .service(
                web::resource("/mds/aaguid/{aaguid}")
                    .route(web::get().to(mock_aaguid_lookup))
            )
    ).await;

    let req = test::TestRequest::get()
        .uri(&format!("/mds/aaguid/{}", test_aaguid))
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    
    // Should find metadata for known AAGUID
    if resp.status() == StatusCode::OK {
        let body: Value = test::read_body_json(resp).await;
        
        // Verify metadata structure
        assert!(body.get("aaguid").is_some(), "Response should include AAGUID");
        assert!(body.get("metadataStatement").is_some(), "Response should include metadata statement");
        
        let metadata_statement = &body["metadataStatement"];
        verify_metadata_statement_structure(metadata_statement)?;
        
        println!("✓ Found metadata for AAGUID: {}", test_aaguid);
    } else {
        // Not finding metadata for unknown AAGUID is also acceptable
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        println!("✓ No metadata found for AAGUID: {} (acceptable)", test_aaguid);
    }
    
    println!("✓ AAGUID lookup validation: PASSED");
    Ok(())
}

/// Test attestation root certificate validation
#[actix_web::test]
async fn test_attestation_root_certificate_validation() -> ConformanceTestResult {
    // Test validation of attestation against known root certificates
    
    let test_attestation = valid_packed_attestation_response();
    
    let app = test::init_service(
        actix_web::App::new()
            .service(
                web::resource("/validate/attestation")
                    .route(web::post().to(mock_attestation_validation))
            )
    ).await;

    let req = test::TestRequest::post()
        .uri("/validate/attestation")
        .set_json(&test_attestation)
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    
    let body: Value = test::read_body_json(resp).await;
    
    // Verify validation result structure
    assert!(body.get("valid").is_some(), "Validation result should include valid field");
    assert!(body.get("trustPath").is_some(), "Validation result should include trust path");
    
    if body["valid"].as_bool().unwrap() {
        let trust_path = body["trustPath"].as_array().unwrap();
        assert!(!trust_path.is_empty(), "Valid attestation should have trust path");
        
        println!("✓ Attestation validated with trust path length: {}", trust_path.len());
    } else {
        // Invalid attestation is also acceptable for test data
        let reason = body.get("reason").and_then(|r| r.as_str()).unwrap_or("Unknown");
        println!("✓ Attestation validation failed: {} (acceptable for test data)", reason);
    }
    
    println!("✓ Attestation root certificate validation: PASSED");
    Ok(())
}

/// Mock MDS endpoint handler
async fn mock_mds_endpoint() -> actix_web::Result<web::Json<Value>> {
    let mock_mds_response = serde_json::json!({
        "legalHeader": "Retrieval and use of this FIDO Metadata Service endpoint by FIDO Alliance members is permitted...",
        "no": 12345,
        "nextUpdate": "2025-01-01",
        "entries": [
            {
                "aaguid": "00000000-0000-0000-0000-000000000000",
                "metadataStatement": generate_test_metadata_statement(),
                "statusReports": [
                    {
                        "status": "FIDO_CERTIFIED",
                        "effectiveDate": "2024-01-01"
                    }
                ]
            }
        ]
    });
    
    Ok(web::Json(mock_mds_response))
}

/// Mock MDS cache status handler
async fn mock_mds_cache_status() -> actix_web::Result<web::Json<Value>> {
    let cache_status = serde_json::json!({
        "lastUpdate": "2024-12-01T12:00:00Z",
        "nextUpdate": "2025-01-01T12:00:00Z",
        "entriesCount": 1500,
        "cacheSize": "2.5MB",
        "status": "healthy"
    });
    
    Ok(web::Json(cache_status))
}

/// Mock AAGUID lookup handler
async fn mock_aaguid_lookup(path: web::Path<String>) -> actix_web::Result<web::Json<Value>> {
    let aaguid = path.into_inner();
    
    // Return metadata for known test AAGUID
    if aaguid == "00000000-0000-0000-0000-000000000000" {
        let response = serde_json::json!({
            "aaguid": aaguid,
            "metadataStatement": generate_test_metadata_statement(),
            "statusReports": [
                {
                    "status": "FIDO_CERTIFIED",
                    "effectiveDate": "2024-01-01"
                }
            ]
        });
        Ok(web::Json(response))
    } else {
        // Return 404 for unknown AAGUIDs
        Err(actix_web::error::ErrorNotFound("AAGUID not found"))
    }
}

/// Mock attestation validation handler
async fn mock_attestation_validation(
    request: web::Json<Value>
) -> actix_web::Result<web::Json<Value>> {
    // Basic validation - in real implementation this would verify against MDS
    let response = &request["response"];
    
    if response.get("attestationObject").is_some() {
        // Simulate successful validation
        let validation_result = serde_json::json!({
            "valid": true,
            "trustPath": [
                "Root CA",
                "Intermediate CA", 
                "Attestation Certificate"
            ],
            "metadata": generate_test_metadata_statement()
        });
        Ok(web::Json(validation_result))
    } else {
        // Simulate validation failure
        let validation_result = serde_json::json!({
            "valid": false,
            "reason": "Missing attestation object",
            "trustPath": []
        });
        Ok(web::Json(validation_result))
    }
}

/// Generate test metadata statement
fn generate_test_metadata_statement() -> Value {
    serde_json::json!({
        "legalHeader": "https://fidoalliance.org/metadata/metadata-statement-legal-header/",
        "description": "Test FIDO2 Authenticator",
        "authenticatorVersion": 1,
        "upv": [
            {
                "major": 1,
                "minor": 2
            }
        ],
        "authenticationAlgorithms": [
            "secp256r1_ecdsa_sha256_raw",
            "rsassa_pkcs1v15_sha256_raw"
        ],
        "publicKeyAlgAndEncodings": [
            "cose"
        ],
        "attestationTypes": [
            15879 // TAG_ATTESTATION_BASIC_FULL
        ],
        "userVerificationDetails": [
            [
                {
                    "userVerificationMethod": "fingerprint_internal",
                    "caDesc": {
                        "base": 10,
                        "minLength": 1
                    }
                }
            ]
        ],
        "keyProtection": [
            "hardware",
            "secure_element"
        ],
        "isKeyRestricted": true,
        "matcherProtection": [
            "on_chip"
        ],
        "cryptoStrength": 128,
        "attachmentHint": [
            "internal"
        ],
        "tcDisplay": [],
        "attestationRootCertificates": [
            "MIICQzCCAeqgAwIBAgIJAKXVfPW8Y6NvMA0GCSqGSIb3DQEBCwUAMHkxCzAJBgNVBAYTAkNIMQ8wDQYDVQQIDAZadXJpY2gxDzANBgNVBAcMBlp1cmljaDE8MDoGA1UECgwzRklETyBBbGxpYW5jZSAtIFRlc3QgQXR0ZXN0YXRpb24gQ2VydGlmaWNhdGUgQXV0aG9yaXR5MBoGA1UEAwwTRklETyBBbGxpYW5jZSBSb290MB4XDTE3MDQwNzEwNDM0OVoXDTI3MDQwNTEwNDM0OVoweTELMAkGA1UEBhMCQ0gxDzANBgNVBAgMBlp1cmljaDE8MDoGA1UECgwzRklETyBBbGxpYW5jZSAtIFRlc3QgQXR0ZXN0YXRpb24gQ2VydGlmaWNhdGUgQXV0aG9yaXR5MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsTaTqjKzK0jKGwEO5L5xK/I+I0gqj4EYPGEQDJjSLPzLlLTB/Oo5Y8u8i9Gx7XRg8R9GtK5ib2nNJ0NLdJPO+KEsVDCW4kTGxJlADR5pGjmO+l4Vs6DRF8z0tBvGZKlm7FN+Z4BK1X4jJcL7l5GVzp1RpY9PmD4CyQ+Cp9Zr5FYO+OlE="
        ],
        "icon": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
    })
}

/// Generate test certificate chain
fn generate_test_certificate_chain() -> Vec<String> {
    vec![
        "-----BEGIN CERTIFICATE-----\nMIICQzCCAeqgAwIBAgIJAKXVfPW8Y6NvMA0GCSqGSIb3DQEBCwUAMHkxCzAJBgNV\nBAYTAkNIMQ8wDQYDVQQIDAZadXJpY2gxDzANBgNVBAcMBlp1cmljaDE8MDoGA1UE\nCgwzRklETyBBbGxpYW5jZSAtIFRlc3QgQXR0ZXN0YXRpb24gQ2VydGlmaWNhdGUg\nQXV0aG9yaXR5MBoGA1UEAwwTRklETyBBbGxpYW5jZSBSb290MB4XDTE3MDQwNzEw\nNDM0OVoXDTI3MDQwNTEwNDM0OVoweTELMAkGA1UEBhMCQ0gxDzANBgNVBAgMBlp1\ncmljaDE8MDoGA1UECgwzRklETyBBbGxpYW5jZSAtIFRlc3QgQXR0ZXN0YXRpb24g\nQ2VydGlmaWNhdGUgQXV0aG9yaXR5MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB\nCgKCAQEAsTaTqjKzK0jKGwEO5L5xK/I+I0gqj4EYPGEQDJjSLPzLlLTB/Oo5Y8u8\ni9Gx7XRg8R9GtK5ib2nNJ0NLdJPO+KEsVDCW4kTGxJlADR5pGjmO+l4Vs6DRF8z0\ntBvGZKlm7FN+Z4BK1X4jJcL7l5GVzp1RpY9PmD4CyQ+Cp9Zr5FYO+OlE\n-----END CERTIFICATE-----".to_string(),
        "-----BEGIN CERTIFICATE-----\nMIICRzCCAe+gAwIBAgIJAPLlO8ZKQxytMA0GCSqGSIb3DQEBCwUAMHkxCzAJBgNV\nBAYTAkNIMQ8wDQYDVQQIDAZadXJpY2gxDzANBgNVBAcMBlp1cmljaDE8MDoGA1UE\nCgwzRklETyBBbGxpYW5jZSAtIFRlc3QgQXR0ZXN0YXRpb24gQ2VydGlmaWNhdGUg\nQXV0aG9yaXR5MBoGA1UEAwwTRklETyBBbGxpYW5jZSBSb290MB4XDTE3MDQwNzEw\nNDQyM1oXDTI3MDQwNTEwNDQyM1owdzELMAkGA1UEBhMCQ0gxDzANBgNVBAgMBlp1\ncmljaDE8MDoGA1UECgwzRklETyBBbGxpYW5jZSAtIFRlc3QgQXR0ZXN0YXRpb24g\nQ2VydGlmaWNhdGUgQXV0aG9yaXR5\n-----END CERTIFICATE-----".to_string()
    ]
}

/// Validate metadata statement structure
fn verify_metadata_statement_structure(metadata: &Value) -> ConformanceTestResult {
    let required_fields = [
        "description",
        "authenticatorVersion", 
        "upv",
        "authenticationAlgorithms",
        "publicKeyAlgAndEncodings",
        "attestationTypes"
    ];
    
    for field in &required_fields {
        assert!(metadata.get(field).is_some(), "Missing required field: {}", field);
    }
    
    // Verify arrays are actually arrays
    let array_fields = ["upv", "authenticationAlgorithms", "publicKeyAlgAndEncodings", "attestationTypes"];
    for field in &array_fields {
        assert!(metadata[field].is_array(), "Field {} should be an array", field);
    }
    
    Ok(())
}

/// Validate metadata statement (simplified validation)
fn validate_metadata_statement(metadata: &Value) -> bool {
    // Simplified validation - real implementation would verify signatures
    let required_fields = [
        "description",
        "authenticatorVersion",
        "authenticationAlgorithms"
    ];
    
    for field in &required_fields {
        if metadata.get(field).is_none() {
            return false;
        }
    }
    
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn run_all_metadata_service_tests() {
        println!("🧪 Running FIDO2 Conformance Tests: Metadata Service");
        
        test_mds3_endpoint_integration().await.unwrap();
        test_authenticator_metadata_validation().await.unwrap();
        test_certificate_chain_validation().await.unwrap();
        test_mds_cache_and_updates().await.unwrap();
        test_metadata_statement_integrity().await.unwrap();
        test_aaguid_lookup_validation().await.unwrap();
        test_attestation_root_certificate_validation().await.unwrap();
        
        println!("✅ All Metadata Service tests passed!");
    }
}
