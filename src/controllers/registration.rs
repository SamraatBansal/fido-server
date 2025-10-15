//! Registration Controller
//! 
//! Handles FIDO2/WebAuthn registration endpoints with security validation

use actix_web::{web, HttpRequest, HttpResponse, Result as ActixResult};
use serde::{Deserialize, Serialize};
use validator::Validate;
use webauthn_rs::prelude::*;

use crate::{
    config::WebAuthnConfig,
    controllers::Response,
    error::AppError,
    services::WebAuthnService,
    db::models::{User, NewUser},
    utils::validation::validate_origin,
};

/// Registration options request
#[derive(Debug, Deserialize, Validate)]
pub struct RegistrationOptionsRequest {
    #[validate(length(min = 1, max = 255))]
    pub username: String,
    
    #[validate(length(min = 1, max = 255))]
    pub display_name: String,
    
    pub authenticator_selection: Option<AuthenticatorSelection>,
    pub attestation: Option<AttestationConveyancePreference>,
}

/// Registration options response
#[derive(Debug, Serialize)]
pub struct RegistrationOptionsResponse {
    pub status: String,
    pub error_message: String,
    pub challenge: String,
    pub rp: RpEntity,
    pub user: UserEntity,
    pub pub_key_cred_params: Vec<PubKeyCredParams>,
    pub timeout: u64,
    pub attestation: AttestationConveyancePreference,
    pub extensions: Option<RegistrationExtensions>,
}

/// Registration result request
#[derive(Debug, Deserialize, Validate)]
pub struct RegistrationResultRequest {
    #[validate(length(min = 1))]
    pub id: String,
    
    #[validate(length(min = 1))]
    pub raw_id: String,
    
    #[validate(custom = "validate_response")]
    pub response: RegistrationCredentialResponse,
    
    #[validate(custom = "validate_credential_type")]
    #[serde(rename = "type")]
    pub credential_type: String,
    
    pub client_extension_results: Option<AuthenticationExtensionsClientOutputs>,
}

/// Registration result response
#[derive(Debug, Serialize)]
pub struct RegistrationResultResponse {
    pub status: String,
    pub error_message: String,
    pub credential_id: String,
    pub new_user: bool,
}

/// Registration controller
pub struct RegistrationController {
    webauthn_service: WebAuthnService,
    config: WebAuthnConfig,
}

impl RegistrationController {
    /// Create new registration controller
    pub fn new(webauthn_service: WebAuthnService, config: WebAuthnConfig) -> Self {
        Self {
            webauthn_service,
            config,
        }
    }

    /// Generate registration options
    pub async fn options(
        &self,
        req: HttpRequest,
        request: RegistrationOptionsRequest,
    ) -> ActixResult<HttpResponse> {
        // Validate request
        if let Err(e) = request.validate() {
            return Ok(HttpResponse::BadRequest().json(Response::error(
                format!("Validation error: {}", e)
            )));
        }

        // Validate origin
        if let Err(e) = validate_origin(&req, &self.config.rp.origins) {
            return Ok(HttpResponse::BadRequest().json(Response::error(
                format!("Origin validation failed: {}", e)
            )));
        }

        // Check if user already exists
        // TODO: Implement user lookup
        // let existing_user = self.user_service.find_by_username(&request.username).await?;
        // if existing_user.is_some() {
        //     return Ok(HttpResponse::Conflict().json(Response::error(
        //         "User already exists".to_string()
        //     )));
        // }

        // Create temporary user for registration
        let user = User {
            id: uuid::Uuid::new_v4(),
            username: request.username.clone(),
            display_name: request.display_name.clone(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        // Generate registration options
        let registration_state = match self.webauthn_service
            .generate_registration_options(
                &user,
                request.authenticator_selection,
                request.attestation,
            )
            .await
        {
            Ok(state) => state,
            Err(e) => {
                log::error!("Failed to generate registration options: {}", e);
                return Ok(HttpResponse::InternalServerError().json(Response::error(
                    "Failed to generate registration options".to_string()
                )));
            }
        };

        // Convert to response format
        let response = RegistrationOptionsResponse {
            status: "ok".to_string(),
            error_message: "".to_string(),
            challenge: base64::encode_config(&registration_state.challenge, base64::URL_SAFE_NO_PAD),
            rp: RpEntity {
                name: self.config.rp.name.clone(),
                id: self.config.rp.id.clone(),
            },
            user: UserEntity {
                id: base64::encode_config(user.id.as_bytes(), base64::URL_SAFE_NO_PAD),
                name: user.username,
                display_name: user.display_name,
            },
            pub_key_cred_params: registration_state.pub_key_cred_params,
            timeout: registration_state.timeout,
            attestation: registration_state.attestation,
            extensions: registration_state.extensions,
        };

        Ok(HttpResponse::Ok().json(Response::success(response)))
    }

    /// Process registration result
    pub async fn result(
        &self,
        req: HttpRequest,
        request: RegistrationResultRequest,
    ) -> ActixResult<HttpResponse> {
        // Validate request
        if let Err(e) = request.validate() {
            return Ok(HttpResponse::BadRequest().json(Response::error(
                format!("Validation error: {}", e)
            )));
        }

        // Validate origin
        if let Err(e) = validate_origin(&req, &self.config.rp.origins) {
            return Ok(HttpResponse::BadRequest().json(Response::error(
                format!("Origin validation failed: {}", e)
            )));
        }

        // Decode credential data
        let credential_id = match base64::decode_config(&request.raw_id, base64::URL_SAFE_NO_PAD) {
            Ok(id) => id,
            Err(e) => {
                log::error!("Failed to decode credential ID: {}", e);
                return Ok(HttpResponse::BadRequest().json(Response::error(
                    "Invalid credential ID format".to_string()
                )));
            }
        };

        // Decode client data JSON
        let client_data_json = match base64::decode_config(
            &request.response.client_data_json,
            base64::URL_SAFE_NO_PAD
        ) {
            Ok(data) => data,
            Err(e) => {
                log::error!("Failed to decode client data JSON: {}", e);
                return Ok(HttpResponse::BadRequest().json(Response::error(
                    "Invalid client data JSON format".to_string()
                )));
            }
        };

        // Parse client data
        let client_data: CollectedClientData = match serde_json::from_slice(&client_data_json) {
            Ok(data) => data,
            Err(e) => {
                log::error!("Failed to parse client data: {}", e);
                return Ok(HttpResponse::BadRequest().json(Response::error(
                    "Invalid client data format".to_string()
                )));
            }
        };

        // Extract user ID from client data
        let user_id_bytes = match base64::decode_config(&client_data.user.id, base64::URL_SAFE_NO_PAD) {
            Ok(id) => id,
            Err(e) => {
                log::error!("Failed to decode user ID: {}", e);
                return Ok(HttpResponse::BadRequest().json(Response::error(
                    "Invalid user ID format".to_string()
                )));
            }
        };

        let user_id = uuid::Uuid::from_slice(&user_id_bytes)
            .map_err(|e| {
                log::error!("Invalid user ID UUID: {}", e);
                AppError::InvalidRequest("Invalid user ID".to_string())
            })?;

        // Decode attestation object
        let attestation_object = match base64::decode_config(
            &request.response.attestation_object,
            base64::URL_SAFE_NO_PAD
        ) {
            Ok(data) => data,
            Err(e) => {
                log::error!("Failed to decode attestation object: {}", e);
                return Ok(HttpResponse::BadRequest().json(Response::error(
                    "Invalid attestation object format".to_string()
                )));
            }
        };

        // Create registration credential response
        let registration_response = RegisterPublicKeyCredential {
            id: request.id,
            raw_id: credential_id,
            response: RegistrationCredentialResponse {
                attestation_object,
                client_data_json,
                transports: request.response.transports,
            },
            type_: request.credential_type,
            client_extension_results: request.client_extension_results.unwrap_or_default(),
        };

        // Verify registration
        let credential = match self.webauthn_service
            .verify_registration(registration_response, user_id)
            .await
        {
            Ok(credential) => credential,
            Err(e) => {
                log::error!("Registration verification failed: {}", e);
                return Ok(HttpResponse::BadRequest().json(Response::error(
                    format!("Registration verification failed: {}", e)
                )));
            }
        };

        // Create user if this is a new user
        // TODO: Implement user creation
        // let new_user = self.user_service.create(NewUser {
        //     username: client_data.user.name,
        //     display_name: client_data.user.display_name,
        // }).await?;

        let response = RegistrationResultResponse {
            status: "ok".to_string(),
            error_message: "".to_string(),
            credential_id: base64::encode_config(&credential.credential_id, base64::URL_SAFE_NO_PAD),
            new_user: true, // TODO: Determine if user is actually new
        };

        Ok(HttpResponse::Ok().json(Response::success(response)))
    }
}

// Custom validation functions
fn validate_response(response: &RegistrationCredentialResponse) -> Result<(), validator::ValidationError> {
    // Validate attestation object format
    if base64::decode_config(&response.attestation_object, base64::URL_SAFE_NO_PAD).is_err() {
        return Err(validator::ValidationError::new("invalid_attestation_object"));
    }

    // Validate client data JSON format
    if base64::decode_config(&response.client_data_json, base64::URL_SAFE_NO_PAD).is_err() {
        return Err(validator::ValidationError::new("invalid_client_data_json"));
    }

    Ok(())
}

fn validate_credential_type(credential_type: &str) -> Result<(), validator::ValidationError> {
    if credential_type != "public-key" {
        return Err(validator::ValidationError::new("invalid_credential_type"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test;
    use serde_json::json;

    #[test]
    fn test_registration_options_request_validation() {
        let valid_request = RegistrationOptionsRequest {
            username: "test@example.com".to_string(),
            display_name: "Test User".to_string(),
            authenticator_selection: None,
            attestation: None,
        };

        assert!(valid_request.validate().is_ok());

        let invalid_request = RegistrationOptionsRequest {
            username: "".to_string(), // Invalid: empty
            display_name: "Test User".to_string(),
            authenticator_selection: None,
            attestation: None,
        };

        assert!(invalid_request.validate().is_err());
    }

    #[test]
    fn test_credential_type_validation() {
        assert!(validate_credential_type("public-key").is_ok());
        assert!(validate_credential_type("invalid").is_err());
    }

    #[actix_rt::test]
    async fn test_registration_options_endpoint() {
        // This would require setting up the full application state
        // For now, we'll test the validation logic
        let request = RegistrationOptionsRequest {
            username: "test@example.com".to_string(),
            display_name: "Test User".to_string(),
            authenticator_selection: None,
            attestation: None,
        };

        assert!(request.validate().is_ok());
    }
}