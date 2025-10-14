//! User service for managing users

use crate::error::{AppError, Result};
use std::collections::HashMap;
use uuid::Uuid;

/// User entity
#[derive(Debug, Clone)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
}

/// User service
pub struct UserService {
    users: std::sync::Arc<std::sync::Mutex<HashMap<String, User>>>,
}

impl UserService {
    /// Create a new user service
    pub fn new() -> Self {
        Self {
            users: std::sync::Arc::new(std::sync::Mutex::new(HashMap::new())),
        }
    }

    /// Create a new user
    pub fn create_user(&self, username: &str, display_name: &str) -> Result<User> {
        let mut users = self.users.lock().unwrap();
        
        // Check if user already exists
        if users.contains_key(username) {
            return Err(AppError::conflict("User already exists"));
        }

        let user = User {
            id: Uuid::new_v4(),
            username: username.to_string(),
            display_name: display_name.to_string(),
        };

        users.insert(username.to_string(), user.clone());
        Ok(user)
    }

    /// Get user by username
    pub fn get_user(&self, username: &str) -> Result<User> {
        let users = self.users.lock().unwrap();
        
        users
            .get(username)
            .cloned()
            .ok_or_else(|| AppError::not_found("User does not exist"))
    }

    /// Check if user exists
    pub fn user_exists(&self, username: &str) -> bool {
        let users = self.users.lock().unwrap();
        users.contains_key(username)
    }
}

impl Default for UserService {
    fn default() -> Self {
        Self::new()
    }
}