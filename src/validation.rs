use crate::api::*;
use crate::error::{AppError, Result};
use serde_json::Value;

pub fn validate_registration_request(request: &ServerPublicKeyCredentialCreationOptionsRequest) -> Result<()> {
    // Validate required username
    if request.username.is_empty() {
        return Err(AppError::MissingField("username".to_string()));
    }
    
    // Validate required displayName
    if request.display_name.is_empty() {
        return Err(AppError::MissingField("displayName".to_string()));
    }
    
    Ok(())
}

pub fn validate_registration_credential(credential: &ServerPublicKeyCredential) -> Result<()> {
    // Validate id field
    if credential.id.is_empty() {
        return Err(AppError::MissingField("id".to_string()));
    }
    
    // Validate type field
    if credential.type_ != "public-key" {
        return Err(AppError::InvalidField("type must be 'public-key'".to_string()));
    }
    
    // Validate response field and its contents
    match &credential.response {
        ServerAuthenticatorResponse::Attestation(response) => {
            validate_attestation_response(response)?;
        },
        _ => return Err(AppError::MissingField("response".to_string())),
    }
    
    Ok(())
}

pub fn validate_attestation_response(response: &ServerAuthenticatorAttestationResponse) -> Result<()> {
    // Validate clientDataJSON
    if response.client_data_json.is_empty() {
        return Err(AppError::MissingField("clientDataJSON".to_string()));
    }
    
    // Validate attestationObject
    if response.attestation_object.is_empty() {
        return Err(AppError::MissingField("attestationObject".to_string()));
    }
    
    // Validate base64url encoding of clientDataJSON
    let client_data_bytes = validate_base64url_field(&response.client_data_json, "clientDataJSON")?;
    
    // Validate base64url encoding of attestationObject  
    validate_base64url_field(&response.attestation_object, "attestationObject")?;
    
    // Parse and validate client data JSON structure
    let client_data: Value = serde_json::from_slice(&client_data_bytes)
        .map_err(|_| AppError::InvalidField("clientDataJSON is not valid JSON".to_string()))?;
    
    validate_client_data_json(&client_data, "webauthn.create")?;
    
    Ok(())
}

pub fn validate_authentication_request(request: &ServerPublicKeyCredentialGetOptionsRequest) -> Result<()> {
    // Validate required username
    if request.username.is_empty() {
        return Err(AppError::MissingField("username".to_string()));
    }
    
    Ok(())
}

pub fn validate_authentication_credential(credential: &ServerPublicKeyCredential) -> Result<()> {
    // Validate id field
    if credential.id.is_empty() {
        return Err(AppError::MissingField("id".to_string()));
    }
    
    // Validate type field
    if credential.type_ != "public-key" {
        return Err(AppError::InvalidField("type must be 'public-key'".to_string()));
    }
    
    // Validate response field and its contents
    match &credential.response {
        ServerAuthenticatorResponse::Assertion(response) => {
            validate_assertion_response(response)?;
        },
        _ => return Err(AppError::MissingField("response".to_string())),
    }
    
    Ok(())
}

pub fn validate_assertion_response(response: &ServerAuthenticatorAssertionResponse) -> Result<()> {
    // Validate clientDataJSON
    if response.client_data_json.is_empty() {
        return Err(AppError::MissingField("clientDataJSON".to_string()));
    }
    
    // Validate authenticatorData
    if response.authenticator_data.is_empty() {
        return Err(AppError::MissingField("authenticatorData".to_string()));
    }
    
    // Validate signature
    if response.signature.is_empty() {
        return Err(AppError::MissingField("signature".to_string()));
    }
    
    // Validate base64url encoding of clientDataJSON
    let client_data_bytes = validate_base64url_field(&response.client_data_json, "clientDataJSON")?;
    
    // Validate base64url encoding of other fields
    validate_base64url_field(&response.authenticator_data, "authenticatorData")?;
    validate_base64url_field(&response.signature, "signature")?;
    
    // Parse and validate client data JSON structure
    let client_data: Value = serde_json::from_slice(&client_data_bytes)
        .map_err(|_| AppError::InvalidField("clientDataJSON is not valid JSON".to_string()))?;
    
    validate_client_data_json(&client_data, "webauthn.get")?;
    
    Ok(())
}

pub fn validate_base64url_field(value: &str, field_name: &str) -> Result<Vec<u8>> {
    use base64::prelude::*;
    
    // Check for valid base64url characters
    if value.chars().any(|c| !matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_')) {
        return Err(AppError::InvalidField(format!("{} is not valid base64url", field_name)));
    }
    
    // Try to decode to verify it's valid base64url
    BASE64_URL_SAFE_NO_PAD.decode(value)
        .map_err(|_| AppError::InvalidField(format!("{} is not valid base64url", field_name)))
}

pub fn validate_client_data_json(client_data: &Value, expected_type: &str) -> Result<()> {
    // Validate type field
    match client_data.get("type") {
        Some(Value::String(type_val)) if type_val == expected_type => {},
        Some(Value::String(type_val)) => {
            return Err(AppError::InvalidField(format!("clientDataJSON.type must be '{}', got: {}", expected_type, type_val)));
        },
        Some(_) => {
            return Err(AppError::InvalidField("clientDataJSON.type must be a string".to_string()));
        },
        None => {
            return Err(AppError::MissingField("clientDataJSON.type".to_string()));
        }
    }
    
    // Validate challenge field
    match client_data.get("challenge") {
        Some(Value::String(challenge)) if !challenge.is_empty() => {
            validate_base64url_field(challenge, "clientDataJSON.challenge")?;
        },
        Some(Value::String(_)) => {
            return Err(AppError::InvalidField("clientDataJSON.challenge cannot be empty".to_string()));
        },
        Some(_) => {
            return Err(AppError::InvalidField("clientDataJSON.challenge must be a string".to_string()));
        },
        None => {
            return Err(AppError::MissingField("clientDataJSON.challenge".to_string()));
        }
    }
    
    // Validate origin field
    match client_data.get("origin") {
        Some(Value::String(origin)) if !origin.is_empty() => {},
        Some(Value::String(_)) => {
            return Err(AppError::InvalidField("clientDataJSON.origin cannot be empty".to_string()));
        },
        Some(_) => {
            return Err(AppError::InvalidField("clientDataJSON.origin must be a string".to_string()));
        },
        None => {
            return Err(AppError::MissingField("clientDataJSON.origin".to_string()));
        }
    }
    
    // Validate tokenBinding if present
    if let Some(token_binding) = client_data.get("tokenBinding") {
        if !token_binding.is_object() {
            return Err(AppError::InvalidField("clientDataJSON.tokenBinding must be an object".to_string()));
        }
        
        let token_binding_obj = token_binding.as_object().unwrap();
        match token_binding_obj.get("status") {
            Some(Value::String(status)) => {
                if !matches!(status.as_str(), "present" | "supported" | "not-supported") {
                    return Err(AppError::InvalidField("clientDataJSON.tokenBinding.status must be 'present', 'supported', or 'not-supported'".to_string()));
                }
            },
            Some(_) => {
                return Err(AppError::InvalidField("clientDataJSON.tokenBinding.status must be a string".to_string()));
            },
            None => {
                return Err(AppError::MissingField("clientDataJSON.tokenBinding.status".to_string()));
            }
        }
    }
    
    Ok(())
}