//! User management service

use uuid::Uuid;
use crate::db::{PooledDb, UserRepository, NewUser, User};
use crate::error::{AppError, Result};

/// User service for managing users
pub struct UserService {
    _db: std::marker::PhantomData<()>, // Placeholder for database connection
}

impl UserService {
    /// Create a new user service
    pub fn new() -> Self {
        Self {
            _db: std::marker::PhantomData,
        }
    }

    /// Get or create a user
    pub async fn get_or_create_user(
        &self,
        conn: &mut PooledDb,
        username: &str,
        display_name: &str,
    ) -> Result<User> {
        // Validate username
        self.validate_username(username)?;
        
        // Validate display name
        self.validate_display_name(display_name)?;

        UserRepository::get_or_create(conn, username, display_name)
    }

    /// Get user by ID
    pub async fn get_user_by_id(
        &self,
        conn: &mut PooledDb,
        user_id: Uuid,
    ) -> Result<Option<User>> {
        UserRepository::find_by_id(conn, user_id)
    }

    /// Get user by username
    pub async fn get_user_by_username(
        &self,
        conn: &mut PooledDb,
        username: &str,
    ) -> Result<Option<User>> {
        UserRepository::find_by_username(conn, username)
    }

    /// Create a new user
    pub async fn create_user(
        &self,
        conn: &mut PooledDb,
        username: &str,
        display_name: &str,
    ) -> Result<User> {
        // Validate inputs
        self.validate_username(username)?;
        self.validate_display_name(display_name)?;

        // Check if user already exists
        if let Some(_) = UserRepository::find_by_username(conn, username)? {
            return Err(AppError::BadRequest(format!("User '{}' already exists", username)));
        }

        let new_user = NewUser {
            username: username.to_string(),
            display_name: display_name.to_string(),
        };

        UserRepository::create(conn, new_user)
    }

    /// Validate username format
    fn validate_username(&self, username: &str) -> Result<()> {
        if username.is_empty() {
            return Err(AppError::ValidationError("Username cannot be empty".to_string()));
        }

        if username.len() > 255 {
            return Err(AppError::ValidationError("Username too long (max 255 characters)".to_string()));
        }

        // Allow alphanumeric characters, dots, hyphens, and underscores
        let username_regex = regex::Regex::new(r"^[a-zA-Z0-9._-]+$")
            .map_err(|e| AppError::InternalError(format!("Invalid username regex: {}", e)))?;

        if !username_regex.is_match(username) {
            return Err(AppError::ValidationError("Username contains invalid characters".to_string()));
        }

        Ok(())
    }

    /// Validate display name format
    fn validate_display_name(&self, display_name: &str) -> Result<()> {
        if display_name.is_empty() {
            return Err(AppError::ValidationError("Display name cannot be empty".to_string()));
        }

        if display_name.len() > 255 {
            return Err(AppError::ValidationError("Display name too long (max 255 characters)".to_string()));
        }

        // Basic validation - no control characters
        if display_name.chars().any(|c| c.is_control()) {
            return Err(AppError::ValidationError("Display name contains invalid characters".to_string()));
        }

        Ok(())
    }
}

impl Default for UserService {
    fn default() -> Self {
        Self::new()
    }
}