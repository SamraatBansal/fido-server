//! Input validation utilities

use crate::error::{AppError, Result};
use regex::Regex;
use lazy_static::lazy_static;

lazy_static! {
    static ref EMAIL_REGEX: Regex = Regex::new(
        r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    ).unwrap();
    
    static ref USERNAME_REGEX: Regex = Regex::new(
        r"^[a-zA-Z0-9_-]{3,50}$"
    ).unwrap();
}

/// Validate email format
pub fn validate_email(email: &str) -> Result<()> {
    if !EMAIL_REGEX.is_match(email) {
        return Err(AppError::ValidationError("Invalid email format".to_string()));
    }
    Ok(())
}

/// Validate username format
pub fn validate_username(username: &str) -> Result<()> {
    if !USERNAME_REGEX.is_match(username) {
        return Err(AppError::ValidationError(
            "Username must be 3-50 characters and contain only letters, numbers, underscores, and hyphens".to_string()
        ));
    }
    Ok(())
}

/// Validate display name
pub fn validate_display_name(display_name: &str) -> Result<()> {
    if display_name.trim().is_empty() {
        return Err(AppError::ValidationError("Display name cannot be empty".to_string()));
    }
    
    if display_name.len() > 100 {
        return Err(AppError::ValidationError("Display name too long (max 100 characters)".to_string()));
    }
    
    Ok(())
}

/// Validate URL format
pub fn validate_url(url: &str) -> Result<()> {
    url::Url::parse(url)
        .map_err(|_| AppError::ValidationError("Invalid URL format".to_string()))?;
    Ok(())
}

/// Validate UUID format
pub fn validate_uuid(uuid_str: &str) -> Result<()> {
    uuid::Uuid::parse_str(uuid_str)
        .map_err(|_| AppError::ValidationError("Invalid UUID format".to_string()))?;
    Ok(())
}