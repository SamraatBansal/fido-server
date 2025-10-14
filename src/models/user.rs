//! User domain model

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use regex::Regex;
use std::sync::OnceLock;

static EMAIL_REGEX: OnceLock<Regex> = OnceLock::new();

fn get_email_regex() -> &'static Regex {
    EMAIL_REGEX.get_or_init(|| {
        Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap()
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub is_active: bool,
}

impl User {
    pub fn new(username: &str, display_name: &str) -> Result<Self, crate::error::AppError> {
        // Validate email format
        if !get_email_regex().is_match(username) {
            return Err(crate::error::AppError::InvalidInput(
                "Invalid email format".to_string(),
            ));
        }

        // Validate display name
        if display_name.is_empty() || display_name.len() > 255 {
            return Err(crate::error::AppError::InvalidInput(
                "Display name must be between 1 and 255 characters".to_string(),
            ));
        }

        let now = Utc::now();
        Ok(User {
            id: Uuid::new_v4(),
            username: username.to_string(),
            display_name: display_name.to_string(),
            created_at: now,
            updated_at: now,
            is_active: true,
        })
    }

    pub fn user_id_base64(&self) -> Result<String, crate::error::AppError> {
        let bytes = self.id.as_bytes();
        Ok(base64::encode_config(bytes, base64::URL_SAFE_NO_PAD))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_creation_valid() {
        let user = User::new("user@example.com", "Test User").unwrap();
        assert_eq!(user.username, "user@example.com");
        assert_eq!(user.display_name, "Test User");
        assert!(user.is_active);
    }

    #[test]
    fn test_user_creation_invalid_email() {
        let result = User::new("invalid-email", "Test User");
        assert!(result.is_err());
    }

    #[test]
    fn test_user_creation_empty_display_name() {
        let result = User::new("user@example.com", "");
        assert!(result.is_err());
    }

    #[test]
    fn test_user_creation_long_display_name() {
        let long_name = "a".repeat(256);
        let result = User::new("user@example.com", &long_name);
        assert!(result.is_err());
    }

    #[test]
    fn test_user_id_base64() {
        let user = User::new("user@example.com", "Test User").unwrap();
        let base64_id = user.user_id_base64().unwrap();
        assert!(!base64_id.is_empty());
        assert!(!base64_id.contains('+'));
        assert!(!base64_id.contains('/'));
        assert!(!base64_id.contains('='));
    }
}