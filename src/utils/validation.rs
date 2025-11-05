use crate::error::{AppError, Result};

pub fn validate_username(username: &str) -> Result<()> {
    if username.is_empty() {
        return Err(AppError::validation("Username cannot be empty"));
    }
    
    if username.len() > 255 {
        return Err(AppError::validation("Username too long"));
    }
    
    // Basic email validation
    if username.contains('@') && !username.contains('.') {
        return Err(AppError::validation("Invalid email format"));
    }
    
    Ok(())
}

pub fn validate_display_name(display_name: &str) -> Result<()> {
    if display_name.is_empty() {
        return Err(AppError::validation("Display name cannot be empty"));
    }
    
    if display_name.len() > 255 {
        return Err(AppError::validation("Display name too long"));
    }
    
    Ok(())
}

pub fn validate_credential_id(credential_id: &str) -> Result<()> {
    if credential_id.is_empty() {
        return Err(AppError::validation("Credential ID cannot be empty"));
    }
    
    // Validate base64url encoding
    crate::utils::crypto::validate_base64_url(credential_id)?;
    
    Ok(())
}

pub fn validate_origin(origin: &str, allowed_origins: &[String]) -> Result<()> {
    if !allowed_origins.contains(&origin.to_string()) {
        return Err(AppError::InvalidOrigin {
            origin: origin.to_string(),
        });
    }
    
    Ok(())
}