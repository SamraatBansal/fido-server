//! Unit tests for schema validation

use fido2_webauthn_server::schema::*;
use validator::Validate;

#[cfg(test)]
mod registration_request_tests {
    

    #[test]
    fn test_valid_registration_request() {
        let request = crate::fixtures::RegistrationRequestFactory::valid();
        assert!(request.validate().is_ok(), "Valid registration request should pass validation");
    }

    #[test]
    fn test_empty_username_validation() {
        let request = crate::fixtures::RegistrationRequestFactory::empty_username();
        let result = request.validate();
        assert!(result.is_err(), "Empty username should fail validation");
        
        let errors = result.unwrap_err();
        assert!(errors.field_errors().contains_key("username"), 
                "Should have username validation error");
    }

    #[test]
    fn test_long_username_validation() {
        let request = crate::fixtures::RegistrationRequestFactory::long_username();
        let result = request.validate();
        assert!(result.is_err(), "Long username should fail validation");
        
        let errors = result.unwrap_err();
        assert!(errors.field_errors().contains_key("username"), 
                "Should have username validation error");
    }

    #[test]
    fn test_invalid_attestation_validation() {
        let request = crate::fixtures::RegistrationRequestFactory::invalid_attestation();
        let result = request.validate();
        assert!(result.is_err(), "Invalid attestation should fail validation");
        
        let errors = result.unwrap_err();
        assert!(errors.field_errors().contains_key("attestation"), 
                "Should have attestation validation error");
    }

    #[test]
    fn test_display_name_validation() {
        let mut request = crate::fixtures::RegistrationRequestFactory::valid();
        request.display_name = "".to_string(); // Empty display name
        
        let result = request.validate();
        assert!(result.is_err(), "Empty display name should fail validation");
        
        let errors = result.unwrap_err();
        assert!(errors.field_errors().contains_key("display_name"), 
                "Should have display_name validation error");
    }
}

#[cfg(test)]
mod authentication_request_tests {
    

    #[test]
    fn test_valid_authentication_request() {
        let request = crate::fixtures::AuthenticationRequestFactory::valid();
        assert!(request.validate().is_ok(), "Valid authentication request should pass validation");
    }

    #[test]
    fn test_invalid_user_verification_validation() {
        let request = crate::fixtures::AuthenticationRequestFactory::invalid_user_verification();
        let result = request.validate();
        assert!(result.is_err(), "Invalid user verification should fail validation");
        
        let errors = result.unwrap_err();
        assert!(errors.field_errors().contains_key("user_verification"), 
                "Should have user_verification validation error");
    }

    #[test]
    fn test_no_username_validation() {
        let request = crate::fixtures::AuthenticationRequestFactory::no_username();
        assert!(request.validate().is_ok(), "Request without username should be valid");
    }
}

#[cfg(test)]
mod attestation_response_tests {
    

    #[test]
    fn test_valid_attestation_response() {
        let response = crate::fixtures::AttestationResponseFactory::valid();
        assert!(response.validate().is_ok(), "Valid attestation response should pass validation");
    }

    #[test]
    fn test_empty_id_validation() {
        let response = crate::fixtures::AttestationResponseFactory::empty_id();
        let result = response.validate();
        assert!(result.is_err(), "Empty ID should fail validation");
        
        let errors = result.unwrap_err();
        assert!(errors.field_errors().contains_key("id"), 
                "Should have id validation error");
    }

    #[test]
    fn test_invalid_type_validation() {
        let response = crate::fixtures::AttestationResponseFactory::invalid_type();
        let result = response.validate();
        assert!(result.is_err(), "Invalid type should fail validation");
        
        let errors = result.unwrap_err();
        assert!(errors.field_errors().contains_key("cred_type"), 
                "Should have cred_type validation error");
    }

    #[test]
    fn test_invalid_client_data_validation() {
        let response = crate::fixtures::AttestationResponseFactory::invalid_client_data();
        let result = response.validate();
        assert!(result.is_err(), "Invalid client data should fail validation");
        
        let errors = result.unwrap_err();
        assert!(errors.field_errors().contains_key("response"), 
                "Should have response validation error");
    }
}

#[cfg(test)]
mod assertion_response_tests {
    

    #[test]
    fn test_valid_assertion_response() {
        let response = crate::fixtures::AssertionResponseFactory::valid();
        assert!(response.validate().is_ok(), "Valid assertion response should pass validation");
    }

    #[test]
    fn test_empty_id_validation() {
        let response = crate::fixtures::AssertionResponseFactory::empty_id();
        let result = response.validate();
        assert!(result.is_err(), "Empty ID should fail validation");
        
        let errors = result.unwrap_err();
        assert!(errors.field_errors().contains_key("id"), 
                "Should have id validation error");
    }

    #[test]
    fn test_invalid_authenticator_data_validation() {
        let response = crate::fixtures::AssertionResponseFactory::invalid_authenticator_data();
        let result = response.validate();
        assert!(result.is_err(), "Invalid authenticator data should fail validation");
        
        let errors = result.unwrap_err();
        assert!(errors.field_errors().contains_key("response"), 
                "Should have response validation error");
    }

    #[test]
    fn test_empty_signature_validation() {
        let response = crate::fixtures::AssertionResponseFactory::empty_signature();
        let result = response.validate();
        assert!(result.is_err(), "Empty signature should fail validation");
        
        let errors = result.unwrap_err();
        assert!(errors.field_errors().contains_key("response"), 
                "Should have response validation error");
    }
}

#[cfg(test)]
mod server_response_tests {
    

    #[test]
    fn test_server_response_success() {
        let response = ServerResponse::success();
        assert_eq!(response.status, "ok");
        assert_eq!(response.error_message, "");
    }

    #[test]
    fn test_server_response_error() {
        let error_msg = "Test error message";
        let response = ServerResponse::error(error_msg);
        assert_eq!(response.status, "failed");
        assert_eq!(response.error_message, error_msg);
    }

    #[test]
    fn test_server_response_serialization() {
        let response = ServerResponse::success();
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"status\":\"ok\""));
        assert!(json.contains("\"error_message\":\"\""));
    }
}

#[cfg(test)]
mod credential_descriptor_tests {
    

    #[test]
    fn test_valid_credential_descriptor() {
        let descriptor = ServerPublicKeyCredentialDescriptor {
            cred_type: "public-key".to_string(),
            id: crate::fixtures::generate_test_credential_id(),
            transports: Some(vec!["usb".to_string(), "nfc".to_string()]),
        };

        // Should serialize/deserialize correctly
        let json = serde_json::to_string(&descriptor).unwrap();
        let deserialized: ServerPublicKeyCredentialDescriptor = serde_json::from_str(&json).unwrap();
        
        assert_eq!(descriptor.cred_type, deserialized.cred_type);
        assert_eq!(descriptor.id, deserialized.id);
        assert_eq!(descriptor.transports, deserialized.transports);
    }
}

#[cfg(test)]
mod authenticator_selection_tests {
    

    #[test]
    fn test_authenticator_selection_criteria() {
        let criteria = AuthenticatorSelectionCriteria {
            require_resident_key: Some(true),
            user_verification: Some("required".to_string()),
            authenticator_attachment: Some("platform".to_string()),
        };

        // Should serialize/deserialize correctly
        let json = serde_json::to_string(&criteria).unwrap();
        let deserialized: AuthenticatorSelectionCriteria = serde_json::from_str(&json).unwrap();
        
        assert_eq!(criteria.require_resident_key, deserialized.require_resident_key);
        assert_eq!(criteria.user_verification, deserialized.user_verification);
        assert_eq!(criteria.authenticator_attachment, deserialized.authenticator_attachment);
    }

    #[test]
    fn test_authenticator_selection_optional_fields() {
        let criteria = AuthenticatorSelectionCriteria {
            require_resident_key: None,
            user_verification: None,
            authenticator_attachment: None,
        };

        let json = serde_json::to_string(&criteria).unwrap();
        let deserialized: AuthenticatorSelectionCriteria = serde_json::from_str(&json).unwrap();
        
        assert_eq!(criteria.require_resident_key, deserialized.require_resident_key);
        assert_eq!(criteria.user_verification, deserialized.user_verification);
        assert_eq!(criteria.authenticator_attachment, deserialized.authenticator_attachment);
    }
}