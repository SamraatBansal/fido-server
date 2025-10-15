use crate::models::*;
use crate::error::{AppError, Result};
use mockall::automock;

#[automock]
pub trait WebAuthnServiceTrait {
    async fn begin_registration(&self, request: &AttestationOptionsRequest) -> Result<AttestationOptionsResponse>;
    async fn complete_registration(&self, request: &AttestationResultRequest) -> Result<ServerResponse>;
    async fn begin_authentication(&self, request: &AssertionOptionsRequest) -> Result<AssertionOptionsResponse>;
    async fn complete_authentication(&self, request: &AssertionResultRequest) -> Result<ServerResponse>;
}

pub struct WebAuthnService {
    // This will be implemented with actual WebAuthn logic
}

impl WebAuthnService {
    pub fn new() -> Self {
        Self {}
    }
}

impl WebAuthnServiceTrait for WebAuthnService {
    async fn begin_registration(&self, request: &AttestationOptionsRequest) -> Result<AttestationOptionsResponse> {
        // Validate input
        if request.username.is_empty() {
            return Err(AppError::ValidationError("Missing username field!".to_string()));
        }

        if request.display_name.is_empty() {
            return Err(AppError::ValidationError("Missing displayName field!".to_string()));
        }

        // TODO: Implement actual WebAuthn registration logic
        // For now, return a mock response that matches the specification
        Ok(AttestationOptionsResponse {
            base: ServerResponse::ok(),
            rp: Some(RelyingParty {
                name: "Example Corporation".to_string(),
                id: None,
            }),
            user: Some(UserEntity {
                id: base64::encode("user_id_placeholder"),
                name: request.username.clone(),
                display_name: request.display_name.clone(),
            }),
            challenge: Some(base64::encode("challenge_placeholder")),
            pub_key_cred_params: Some(vec![PubKeyCredParam {
                cred_type: "public-key".to_string(),
                alg: -7, // ES256
            }]),
            timeout: Some(10000),
            exclude_credentials: Some(vec![]),
            authenticator_selection: request.authenticator_selection.clone(),
            attestation: Some(request.attestation.clone()),
        })
    }

    async fn complete_registration(&self, request: &AttestationResultRequest) -> Result<ServerResponse> {
        // Validate input
        if request.id.is_empty() {
            return Err(AppError::ValidationError("Missing credential id!".to_string()));
        }

        if request.response.client_data_json.is_empty() {
            return Err(AppError::ValidationError("Missing clientDataJSON!".to_string()));
        }

        if request.response.attestation_object.is_empty() {
            return Err(AppError::ValidationError("Missing attestationObject!".to_string()));
        }

        // TODO: Implement actual attestation validation
        // For now, return success
        Ok(ServerResponse::ok())
    }

    async fn begin_authentication(&self, request: &AssertionOptionsRequest) -> Result<AssertionOptionsResponse> {
        // Validate input
        if request.username.is_empty() {
            return Err(AppError::ValidationError("Missing username field!".to_string()));
        }

        // TODO: Check if user exists
        // For now, simulate user not found for certain usernames
        if request.username == "nonexistent@example.com" {
            return Err(AppError::UserNotFound);
        }

        // TODO: Implement actual WebAuthn authentication logic
        Ok(AssertionOptionsResponse {
            base: ServerResponse::ok(),
            challenge: Some(base64::encode("auth_challenge_placeholder")),
            timeout: Some(20000),
            rp_id: Some("example.com".to_string()),
            allow_credentials: Some(vec![CredentialDescriptor {
                cred_type: "public-key".to_string(),
                id: base64::encode("credential_id_placeholder"),
                transports: None,
            }]),
            user_verification: request.user_verification.clone(),
        })
    }

    async fn complete_authentication(&self, request: &AssertionResultRequest) -> Result<ServerResponse> {
        // Validate input
        if request.id.is_empty() {
            return Err(AppError::ValidationError("Missing credential id!".to_string()));
        }

        if request.response.authenticator_data.is_empty() {
            return Err(AppError::ValidationError("Missing authenticatorData!".to_string()));
        }

        if request.response.client_data_json.is_empty() {
            return Err(AppError::ValidationError("Missing clientDataJSON!".to_string()));
        }

        if request.response.signature.is_empty() {
            return Err(AppError::ValidationError("Missing signature!".to_string()));
        }

        // TODO: Implement actual assertion validation
        // For now, return success
        Ok(ServerResponse::ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_begin_registration_success() {
        let service = WebAuthnService::new();
        let request = AttestationOptionsRequest::new("test@example.com", "Test User");

        let result = service.begin_registration(&request).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(response.base.status, "ok");
        assert!(response.challenge.is_some());
        assert!(response.user.is_some());
        
        let user = response.user.unwrap();
        assert_eq!(user.name, "test@example.com");
        assert_eq!(user.display_name, "Test User");
    }

    #[tokio::test]
    async fn test_begin_registration_empty_username() {
        let service = WebAuthnService::new();
        let request = AttestationOptionsRequest::new("", "Test User");

        let result = service.begin_registration(&request).await;
        assert!(result.is_err());
        
        match result.unwrap_err() {
            AppError::ValidationError(msg) => assert!(msg.contains("Missing username field!")),
            _ => panic!("Expected ValidationError"),
        }
    }

    #[tokio::test]
    async fn test_begin_registration_empty_display_name() {
        let service = WebAuthnService::new();
        let request = AttestationOptionsRequest::new("test@example.com", "");

        let result = service.begin_registration(&request).await;
        assert!(result.is_err());
        
        match result.unwrap_err() {
            AppError::ValidationError(msg) => assert!(msg.contains("Missing displayName field!")),
            _ => panic!("Expected ValidationError"),
        }
    }

    #[tokio::test]
    async fn test_begin_authentication_user_not_found() {
        let service = WebAuthnService::new();
        let request = AssertionOptionsRequest::new("nonexistent@example.com");

        let result = service.begin_authentication(&request).await;
        assert!(result.is_err());
        
        match result.unwrap_err() {
            AppError::UserNotFound => {},
            _ => panic!("Expected UserNotFound error"),
        }
    }

    #[tokio::test]
    async fn test_complete_registration_missing_fields() {
        let service = WebAuthnService::new();
        
        // Test missing credential ID
        let request = AttestationResultRequest {
            id: "".to_string(),
            raw_id: None,
            response: AttestationResponse {
                client_data_json: "valid_data".to_string(),
                attestation_object: "valid_object".to_string(),
            },
            get_client_extension_results: None,
            cred_type: "public-key".to_string(),
        };

        let result = service.complete_registration(&request).await;
        assert!(result.is_err());
    }
}