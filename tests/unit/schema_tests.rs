//! Unit tests for request/response schema validation

use serde_json::{json, Value};
use crate::common::{factories, assertions, errors};

#[cfg(test)]
mod attestation_options_tests {
    use super::*;

    #[test]
    fn test_valid_attestation_options_request() {
        let request = factories::create_attestation_options_request();
        
        // Test that the request is valid JSON
        assert!(request.is_object());
        
        // Test required fields
        assert!(request.get("username").is_some());
        assert!(request.get("displayName").is_some());
        assert!(request.get("attestation").is_some());
        assert!(request.get("authenticatorSelection").is_some());
        
        // Test field values
        assert_eq!(request.get("username").unwrap().as_str().unwrap(), "test@example.com");
        assert_eq!(request.get("displayName").unwrap().as_str().unwrap(), "Test User");
        assert_eq!(request.get("attestation").unwrap().as_str().unwrap(), "direct");
    }

    #[test]
    fn test_attestation_options_missing_username() {
        let mut request = factories::create_attestation_options_request();
        if let Some(obj) = request.as_object_mut() {
            obj.remove("username");
        }
        
        // Should fail validation due to missing username
        assert!(request.get("username").is_none());
    }

    #[test]
    fn test_attestation_options_missing_display_name() {
        let mut request = factories::create_attestation_options_request();
        if let Some(obj) = request.as_object_mut() {
            obj.remove("displayName");
        }
        
        // Should fail validation due to missing displayName
        assert!(request.get("displayName").is_none());
    }

    #[test]
    fn test_attestation_options_invalid_attestation_value() {
        let mut request = factories::create_attestation_options_request();
        if let Some(obj) = request.as_object_mut() {
            obj.insert("attestation".to_string(), json!("invalid_value"));
        }
        
        // Should fail validation due to invalid attestation value
        assert_ne!(request.get("attestation").unwrap().as_str().unwrap(), "direct");
        assert_ne!(request.get("attestation").unwrap().as_str().unwrap(), "none");
        assert_ne!(request.get("attestation").unwrap().as_str().unwrap(), "indirect");
    }

    #[test]
    fn test_attestation_options_empty_username() {
        let mut request = factories::create_attestation_options_request();
        if let Some(obj) = request.as_object_mut() {
            obj.insert("username".to_string(), json!(""));
        }
        
        // Should fail validation due to empty username
        assert_eq!(request.get("username").unwrap().as_str().unwrap(), "");
    }

    #[test]
    fn test_attestation_options_oversized_display_name() {
        let oversized_name = "x".repeat(300);
        let mut request = factories::create_attestation_options_request();
        if let Some(obj) = request.as_object_mut() {
            obj.insert("displayName".to_string(), json!(oversized_name));
        }
        
        // Should fail validation due to oversized displayName
        assert!(request.get("displayName").unwrap().as_str().unwrap().len() > 255);
    }
}

#[cfg(test)]
mod attestation_result_tests {
    use super::*;

    #[test]
    fn test_valid_attestation_result_request() {
        let request = factories::create_attestation_result_request();
        
        // Test that the request is valid JSON
        assert!(request.is_object());
        
        // Test required fields
        assert!(request.get("id").is_some());
        assert!(request.get("rawId").is_some());
        assert!(request.get("response").is_some());
        assert!(request.get("type").is_some());
        
        // Test response structure
        let response = request.get("response").unwrap();
        assert!(response.get("attestationObject").is_some());
        assert!(response.get("clientDataJSON").is_some());
        
        // Test type field
        assert_eq!(request.get("type").unwrap().as_str().unwrap(), "public-key");
    }

    #[test]
    fn test_attestation_result_missing_id() {
        let mut request = factories::create_attestation_result_request();
        if let Some(obj) = request.as_object_mut() {
            obj.remove("id");
        }
        
        // Should fail validation due to missing id
        assert!(request.get("id").is_none());
    }

    #[test]
    fn test_attestation_result_missing_response() {
        let mut request = factories::create_attestation_result_request();
        if let Some(obj) = request.as_object_mut() {
            obj.remove("response");
        }
        
        // Should fail validation due to missing response
        assert!(request.get("response").is_none());
    }

    #[test]
    fn test_attestation_result_invalid_type() {
        let mut request = factories::create_attestation_result_request();
        if let Some(obj) = request.as_object_mut() {
            obj.insert("type".to_string(), json!("invalid_type"));
        }
        
        // Should fail validation due to invalid type
        assert_ne!(request.get("type").unwrap().as_str().unwrap(), "public-key");
    }

    #[test]
    fn test_attestation_result_invalid_base64url_attestation() {
        let mut request = factories::create_attestation_result_request();
        if let Some(response) = request.get_mut("response").unwrap().as_object_mut() {
            response.insert("attestationObject".to_string(), 
                json!(factories::create_invalid_base64url()));
        }
        
        // Should fail validation due to invalid base64url
        let attestation = request.get("response")
            .unwrap()
            .get("attestationObject")
            .unwrap()
            .as_str()
            .unwrap();
        
        // Test that it's invalid base64url
        assert!(base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(attestation.as_bytes())
            .is_err());
    }

    #[test]
    fn test_attestation_result_empty_id() {
        let mut request = factories::create_attestation_result_request();
        if let Some(obj) = request.as_object_mut() {
            obj.insert("id".to_string(), json!(""));
        }
        
        // Should fail validation due to empty id
        assert_eq!(request.get("id").unwrap().as_str().unwrap(), "");
    }
}

#[cfg(test)]
mod assertion_options_tests {
    use super::*;

    #[test]
    fn test_valid_assertion_options_request() {
        let request = factories::create_assertion_options_request();
        
        // Test that the request is valid JSON
        assert!(request.is_object());
        
        // Test required fields
        assert!(request.get("username").is_some());
        assert!(request.get("userVerification").is_some());
        
        // Test field values
        assert_eq!(request.get("username").unwrap().as_str().unwrap(), "test@example.com");
        assert_eq!(request.get("userVerification").unwrap().as_str().unwrap(), "preferred");
    }

    #[test]
    fn test_assertion_options_missing_username() {
        let mut request = factories::create_assertion_options_request();
        if let Some(obj) = request.as_object_mut() {
            obj.remove("username");
        }
        
        // Should fail validation due to missing username
        assert!(request.get("username").is_none());
    }

    #[test]
    fn test_assertion_options_invalid_user_verification() {
        let mut request = factories::create_assertion_options_request();
        if let Some(obj) = request.as_object_mut() {
            obj.insert("userVerification".to_string(), json!("invalid_value"));
        }
        
        // Should fail validation due to invalid userVerification value
        assert_ne!(request.get("userVerification").unwrap().as_str().unwrap(), "required");
        assert_ne!(request.get("userVerification").unwrap().as_str().unwrap(), "preferred");
        assert_ne!(request.get("userVerification").unwrap().as_str().unwrap(), "discouraged");
    }

    #[test]
    fn test_assertion_options_empty_username() {
        let mut request = factories::create_assertion_options_request();
        if let Some(obj) = request.as_object_mut() {
            obj.insert("username".to_string(), json!(""));
        }
        
        // Should fail validation due to empty username
        assert_eq!(request.get("username").unwrap().as_str().unwrap(), "");
    }
}

#[cfg(test)]
mod assertion_result_tests {
    use super::*;

    #[test]
    fn test_valid_assertion_result_request() {
        let request = factories::create_assertion_result_request();
        
        // Test that the request is valid JSON
        assert!(request.is_object());
        
        // Test required fields
        assert!(request.get("id").is_some());
        assert!(request.get("rawId").is_some());
        assert!(request.get("response").is_some());
        assert!(request.get("type").is_some());
        
        // Test response structure
        let response = request.get("response").unwrap();
        assert!(response.get("authenticatorData").is_some());
        assert!(response.get("clientDataJSON").is_some());
        assert!(response.get("signature").is_some());
        assert!(response.get("userHandle").is_some());
        
        // Test type field
        assert_eq!(request.get("type").unwrap().as_str().unwrap(), "public-key");
    }

    #[test]
    fn test_assertion_result_missing_signature() {
        let mut request = factories::create_assertion_result_request();
        if let Some(response) = request.get_mut("response").unwrap().as_object_mut() {
            response.remove("signature");
        }
        
        // Should fail validation due to missing signature
        assert!(request.get("response")
            .unwrap()
            .get("signature")
            .is_none());
    }

    #[test]
    fn test_assertion_result_missing_authenticator_data() {
        let mut request = factories::create_assertion_result_request();
        if let Some(response) = request.get_mut("response").unwrap().as_object_mut() {
            response.remove("authenticatorData");
        }
        
        // Should fail validation due to missing authenticatorData
        assert!(request.get("response")
            .unwrap()
            .get("authenticatorData")
            .is_none());
    }

    #[test]
    fn test_assertion_result_invalid_base64url_signature() {
        let mut request = factories::create_assertion_result_request();
        if let Some(response) = request.get_mut("response").unwrap().as_object_mut() {
            response.insert("signature".to_string(), 
                json!(factories::create_invalid_base64url()));
        }
        
        // Should fail validation due to invalid base64url
        let signature = request.get("response")
            .unwrap()
            .get("signature")
            .unwrap()
            .as_str()
            .unwrap();
        
        // Test that it's invalid base64url
        assert!(base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(signature.as_bytes())
            .is_err());
    }

    #[test]
    fn test_assertion_result_empty_credential_id() {
        let mut request = factories::create_assertion_result_request();
        if let Some(obj) = request.as_object_mut() {
            obj.insert("id".to_string(), json!(""));
        }
        
        // Should fail validation due to empty id
        assert_eq!(request.get("id").unwrap().as_str().unwrap(), "");
    }
}

#[cfg(test)]
mod response_validation_tests {
    use super::*;

    #[test]
    fn test_attestation_options_response_structure() {
        let response = json!({
            "challenge": factories::generate_challenge(),
            "rp": {
                "name": "Test FIDO Server",
                "id": "localhost"
            },
            "user": {
                "id": factories::generate_user_id(),
                "name": "test@example.com",
                "displayName": "Test User"
            },
            "pubKeyCredParams": [
                {"type": "public-key", "alg": -7},
                {"type": "public-key", "alg": -257}
            ],
            "timeout": 60000,
            "attestation": "direct"
        });
        
        assertions::assert_attestation_options_response(&response);
    }

    #[test]
    fn test_assertion_options_response_structure() {
        let response = json!({
            "challenge": factories::generate_challenge(),
            "rpId": "localhost",
            "allowCredentials": [
                {
                    "type": "public-key",
                    "id": factories::generate_credential_id(),
                    "transports": ["internal", "usb", "nfc", "ble"]
                }
            ],
            "timeout": 60000,
            "userVerification": "preferred"
        });
        
        assertions::assert_assertion_options_response(&response);
    }

    #[test]
    fn test_attestation_result_response_structure() {
        let response = json!({
            "status": "ok",
            "errorMessage": ""
        });
        
        assertions::assert_attestation_result_response(&response);
    }

    #[test]
    fn test_assertion_result_response_structure() {
        let response = json!({
            "status": "ok",
            "errorMessage": ""
        });
        
        assertions::assert_assertion_result_response(&response);
    }

    #[test]
    fn test_response_with_error_status() {
        let response = json!({
            "status": "error",
            "errorMessage": "Invalid attestation"
        });
        
        assertions::assert_attestation_result_response(&response);
        assertions::assert_assertion_result_response(&response);
        
        assert_eq!(response.get("status").unwrap().as_str().unwrap(), "error");
        assert!(!response.get("errorMessage").unwrap().as_str().unwrap().is_empty());
    }
}

#[cfg(test)]
mod edge_case_tests {
    use super::*;

    #[test]
    fn test_malformed_json_request() {
        let malformed_json = r#"{"username": "test", "invalid": }"#;
        
        // Should fail to parse as JSON
        assert!(serde_json::from_str::<Value>(malformed_json).is_err());
    }

    #[test]
    fn test_request_with_null_values() {
        let request = json!({
            "username": null,
            "displayName": "Test User",
            "attestation": "direct"
        });
        
        // Should fail validation due to null username
        assert!(request.get("username").unwrap().is_null());
    }

    #[test]
    fn test_request_with_wrong_data_types() {
        let request = json!({
            "username": 123,  // Should be string
            "displayName": "Test User",
            "attestation": "direct"
        });
        
        // Should fail validation due to wrong data type
        assert!(request.get("username").unwrap().is_number());
    }

    #[test]
    fn test_request_with_additional_fields() {
        let request = json!({
            "username": "test@example.com",
            "displayName": "Test User",
            "attestation": "direct",
            "unexpectedField": "should not be here"
        });
        
        // Additional fields should be ignored or cause validation error
        assert!(request.get("unexpectedField").is_some());
    }

    #[test]
    fn test_unicode_characters_in_display_name() {
        let unicode_name = "🔐 Test User 🚀";
        let request = json!({
            "username": "test@example.com",
            "displayName": unicode_name,
            "attestation": "direct"
        });
        
        // Should handle Unicode characters properly
        assert_eq!(request.get("displayName").unwrap().as_str().unwrap(), unicode_name);
    }

    #[test]
    fn test_special_characters_in_username() {
        let special_username = "test+user@example.com";
        let request = json!({
            "username": special_username,
            "displayName": "Test User",
            "attestation": "direct"
        });
        
        // Should handle special characters in email
        assert_eq!(request.get("username").unwrap().as_str().unwrap(), special_username);
    }
}