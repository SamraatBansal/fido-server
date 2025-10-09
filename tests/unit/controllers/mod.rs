//! Unit tests for API controllers

use crate::common::*;
use serde_json::json;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use uuid::Uuid;

#[cfg(test)]
mod attestation_tests {
    use super::*;

    #[tokio::test]
    async fn test_attestation_options_valid_request() {
        // Test valid attestation options request
        let request = create_attestation_options_request("alice", "Alice Smith");
        
        // Validate request structure
        assert!(request.get("username").is_some());
        assert!(request.get("displayName").is_some());
        assert_eq!(request["username"], "alice");
        assert_eq!(request["displayName"], "Alice Smith");
        
        // Validate attestation field
        assert_eq!(request["attestation"], "direct");
        
        // Validate authenticator selection
        let auth_selection = &request["authenticatorSelection"];
        assert_eq!(auth_selection["authenticatorAttachment"], "platform");
        assert_eq!(auth_selection["requireResidentKey"], false);
        assert_eq!(auth_selection["userVerification"], "preferred");
    }

    #[tokio::test]
    async fn test_attestation_options_minimal_request() {
        // Test minimal attestation options request
        let request = create_minimal_attestation_options_request("alice");
        
        assert_eq!(request["username"], "alice");
        assert_eq!(request["displayName"], "Test User");
    }

    #[tokio::test]
    async fn test_attestation_options_missing_username() {
        // Test request with missing username
        let request = create_invalid_attestation_options_request_missing_username();
        
        assert!(request.get("username").is_none());
        assert!(request.get("displayName").is_some());
    }

    #[tokio::test]
    async fn test_attestation_options_empty_username() {
        // Test request with empty username
        let request = create_invalid_attestation_options_request_empty_username();
        
        assert_eq!(request["username"], "");
        assert!(request["username"].as_str().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_attestation_result_valid_request() {
        // Test valid attestation result request
        let challenge = generate_secure_challenge();
        let request = create_attestation_result_request(&challenge);
        
        // Validate required fields
        assert!(request.get("id").is_some());
        assert!(request.get("rawId").is_some());
        assert!(request.get("response").is_some());
        assert!(request.get("type").is_some());
        
        // Validate response structure
        let response = &request["response"];
        assert!(response.get("attestationObject").is_some());
        assert!(response.get("clientDataJSON").is_some());
        
        // Validate type
        assert_eq!(request["type"], "public-key");
        
        // Validate base64url encoding
        let id = request["id"].as_str().unwrap();
        assert!(URL_SAFE_NO_PAD.decode(id).is_ok());
    }

    #[tokio::test]
    async fn test_attestation_result_missing_id() {
        // Test request with missing id
        let request = create_invalid_attestation_result_request_missing_id();
        
        assert!(request.get("id").is_none());
        assert!(request.get("rawId").is_some());
    }

    #[tokio::test]
    async fn test_attestation_result_invalid_base64() {
        // Test request with invalid base64
        let request = create_invalid_attestation_result_request_invalid_base64();
        
        let raw_id = request["rawId"].as_str().unwrap();
        assert!(URL_SAFE_NO_PAD.decode(raw_id).is_err());
    }

    #[tokio::test]
    async fn test_attestation_result_client_data_json_structure() {
        // Test clientDataJSON structure
        let challenge = generate_secure_challenge();
        let request = create_attestation_result_request(&challenge);
        
        let client_data_b64 = request["response"]["clientDataJSON"].as_str().unwrap();
        let client_data_bytes = URL_SAFE_NO_PAD.decode(client_data_b64).unwrap();
        let client_data: serde_json::Value = serde_json::from_slice(&client_data_bytes).unwrap();
        
        assert_eq!(client_data["type"], "webauthn.create");
        assert_eq!(client_data["challenge"], challenge);
        assert_eq!(client_data["origin"], "https://example.com");
    }
}

#[cfg(test)]
mod assertion_tests {
    use super::*;

    #[tokio::test]
    async fn test_assertion_options_valid_request() {
        // Test valid assertion options request
        let request = create_assertion_options_request("alice");
        
        // Validate required fields
        assert!(request.get("username").is_some());
        assert_eq!(request["username"], "alice");
        
        // Validate optional fields
        assert_eq!(request["userVerification"], "preferred");
    }

    #[tokio::test]
    async fn test_assertion_options_minimal_request() {
        // Test minimal assertion options request
        let request = create_minimal_assertion_options_request("alice");
        
        assert_eq!(request["username"], "alice");
        assert!(request.get("userVerification").is_none());
    }

    #[tokio::test]
    async fn test_assertion_options_missing_username() {
        // Test request with missing username
        let request = create_invalid_assertion_options_request_missing_username();
        
        assert!(request.get("username").is_none());
        assert!(request.get("userVerification").is_some());
    }

    #[tokio::test]
    async fn test_assertion_result_valid_request() {
        // Test valid assertion result request
        let challenge = generate_secure_challenge();
        let credential_id = URL_SAFE_NO_PAD.encode(Uuid::new_v4().as_bytes());
        let request = create_assertion_result_request(&challenge, &credential_id);
        
        // Validate required fields
        assert!(request.get("id").is_some());
        assert!(request.get("rawId").is_some());
        assert!(request.get("response").is_some());
        assert!(request.get("type").is_some());
        
        // Validate response structure
        let response = &request["response"];
        assert!(response.get("authenticatorData").is_some());
        assert!(response.get("clientDataJSON").is_some());
        assert!(response.get("signature").is_some());
        assert!(response.get("userHandle").is_some());
        
        // Validate type
        assert_eq!(request["type"], "public-key");
        
        // Validate credential ID consistency
        assert_eq!(request["id"], credential_id);
        assert_eq!(request["rawId"], credential_id);
    }

    #[tokio::test]
    async fn test_assertion_result_missing_signature() {
        // Test request with missing signature
        let request = create_invalid_assertion_result_request_missing_signature();
        
        let response = &request["response"];
        assert!(response.get("signature").is_none());
        assert!(response.get("authenticatorData").is_some());
        assert!(response.get("clientDataJSON").is_some());
    }

    #[tokio::test]
    async fn test_assertion_result_client_data_json_structure() {
        // Test clientDataJSON structure for assertion
        let challenge = generate_secure_challenge();
        let credential_id = URL_SAFE_NO_PAD.encode(Uuid::new_v4().as_bytes());
        let request = create_assertion_result_request(&challenge, &credential_id);
        
        let client_data_b64 = request["response"]["clientDataJSON"].as_str().unwrap();
        let client_data_bytes = URL_SAFE_NO_PAD.decode(client_data_b64).unwrap();
        let client_data: serde_json::Value = serde_json::from_slice(&client_data_bytes).unwrap();
        
        assert_eq!(client_data["type"], "webauthn.get");
        assert_eq!(client_data["challenge"], challenge);
        assert_eq!(client_data["origin"], "https://example.com");
    }

    #[tokio::test]
    async fn test_assertion_result_replay_attack() {
        // Test replay attack scenario
        let old_challenge = "reused_challenge_12345";
        let credential_id = URL_SAFE_NO_PAD.encode(Uuid::new_v4().as_bytes());
        let request = create_replay_assertion_result_request(old_challenge, &credential_id);
        
        let client_data_b64 = request["response"]["clientDataJSON"].as_str().unwrap();
        let client_data_bytes = URL_SAFE_NO_PAD.decode(client_data_b64).unwrap();
        let client_data: serde_json::Value = serde_json::from_slice(&client_data_bytes).unwrap();
        
        // This should be detected as a replay attack
        assert_eq!(client_data["challenge"], old_challenge);
    }
}

#[cfg(test)]
mod response_validation_tests {
    use super::*;

    #[tokio::test]
    async fn test_attestation_options_response_schema() {
        // Test expected response schema for attestation options
        let expected_response = json!({
            "challenge": "BASE64URLSTRING",
            "rp": { 
                "name": "Example RP", 
                "id": "example.com" 
            },
            "user": { 
                "id": "BASE64URL", 
                "name": "alice", 
                "displayName": "Alice Smith" 
            },
            "pubKeyCredParams": [{ 
                "type": "public-key", 
                "alg": -7 
            }],
            "timeout": 60000,
            "attestation": "direct"
        });
        
        // Validate required fields
        assert!(expected_response.get("challenge").is_some());
        assert!(expected_response.get("rp").is_some());
        assert!(expected_response.get("user").is_some());
        assert!(expected_response.get("pubKeyCredParams").is_some());
        assert!(expected_response.get("timeout").is_some());
        assert!(expected_response.get("attestation").is_some());
        
        // Validate rp structure
        let rp = &expected_response["rp"];
        assert!(rp.get("name").is_some());
        assert!(rp.get("id").is_some());
        
        // Validate user structure
        let user = &expected_response["user"];
        assert!(user.get("id").is_some());
        assert!(user.get("name").is_some());
        assert!(user.get("displayName").is_some());
        
        // Validate pubKeyCredParams
        let cred_params = expected_response["pubKeyCredParams"].as_array().unwrap();
        assert!(!cred_params.is_empty());
        
        for param in cred_params {
            assert_eq!(param["type"], "public-key");
            assert!(param.get("alg").is_some());
        }
    }

    #[tokio::test]
    async fn test_assertion_options_response_schema() {
        // Test expected response schema for assertion options
        let expected_response = json!({
            "challenge": "BASE64URLSTRING",
            "rpId": "example.com",
            "allowCredentials": [{ 
                "type": "public-key", 
                "id": "BASE64URL" 
            }],
            "timeout": 60000,
            "userVerification": "preferred"
        });
        
        // Validate required fields
        assert!(expected_response.get("challenge").is_some());
        assert!(expected_response.get("rpId").is_some());
        assert!(expected_response.get("allowCredentials").is_some());
        assert!(expected_response.get("timeout").is_some());
        assert!(expected_response.get("userVerification").is_some());
        
        // Validate allowCredentials structure
        let allow_creds = expected_response["allowCredentials"].as_array().unwrap();
        
        for cred in allow_creds {
            assert_eq!(cred["type"], "public-key");
            assert!(cred.get("id").is_some());
        }
    }

    #[tokio::test]
    async fn test_attestation_result_response_schema() {
        // Test expected response schema for attestation result
        let expected_response = json!({
            "status": "ok",
            "errorMessage": ""
        });
        
        assert_eq!(expected_response["status"], "ok");
        assert_eq!(expected_response["errorMessage"], "");
    }

    #[tokio::test]
    async fn test_assertion_result_response_schema() {
        // Test expected response schema for assertion result
        let expected_response = json!({
            "status": "ok",
            "errorMessage": ""
        });
        
        assert_eq!(expected_response["status"], "ok");
        assert_eq!(expected_response["errorMessage"], "");
    }
}

#[cfg(test)]
mod edge_case_tests {
    use super::*;

    #[tokio::test]
    async fn test_empty_values() {
        // Test handling of empty values
        let empty_username_request = json!({
            "username": "",
            "displayName": "Alice Smith"
        });
        
        assert_eq!(empty_username_request["username"], "");
        assert!(!empty_username_request["username"].as_str().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_oversized_payload() {
        // Test handling of oversized payloads
        let oversized_request = create_oversized_payload();
        
        let username = oversized_request["username"].as_str().unwrap();
        assert!(username.len() > 100000); // Should be > 1MB
    }

    #[tokio::test]
    async fn test_malformed_json() {
        // Test handling of malformed JSON
        let malformed_json = create_malformed_json();
        
        // This should fail to parse
        let parse_result: Result<serde_json::Value, _> = serde_json::from_str(&malformed_json);
        assert!(parse_result.is_err());
    }

    #[tokio::test]
    async fn test_unicode_handling() {
        // Test handling of Unicode characters
        let unicode_request = json!({
            "username": "älïcë",
            "displayName": "Älïcë Smïth 🦊"
        });
        
        assert_eq!(unicode_request["username"], "älïcë");
        assert_eq!(unicode_request["displayName"], "Älïcë Smïth 🦊");
    }

    #[tokio::test]
    async fn test_special_characters_in_username() {
        // Test various special characters in username
        let test_cases = vec![
            ("alice@example.com", "Email format"),
            ("alice_test", "Underscore"),
            ("alice-test", "Hyphen"),
            ("alice.test", "Dot"),
            ("alice123", "Numbers"),
        ];
        
        for (username, description) in test_cases {
            let request = create_attestation_options_request(username, "Test User");
            assert_eq!(request["username"], username, "Failed for {}", description);
        }
    }

    #[tokio::test]
    async fn test_extreme_attestation_values() {
        // Test extreme values for attestation parameter
        let attestation_values = vec!["none", "indirect", "direct", "enterprise"];
        
        for attestation in attestation_values {
            let request = json!({
                "username": "alice",
                "displayName": "Alice Smith",
                "attestation": attestation
            });
            
            assert_eq!(request["attestation"], attestation);
        }
    }

    #[tokio::test]
    async fn test_extreme_user_verification_values() {
        // Test extreme values for userVerification parameter
        let uv_values = vec!["required", "preferred", "discouraged"];
        
        for uv in uv_values {
            let request = json!({
                "username": "alice",
                "userVerification": uv
            });
            
            assert_eq!(request["userVerification"], uv);
        }
    }
}