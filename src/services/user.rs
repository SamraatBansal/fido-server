//! User management service

use crate::db::models::User;
use uuid::Uuid;
use chrono::Utc;

/// User service
pub struct UserService {
    // In-memory storage (in production, use database)
    users: std::collections::HashMap<Uuid, User>,
    username_index: std::collections::HashMap<String, Uuid>,
}

impl UserService {
    /// Create new user service
    pub fn new() -> Self {
        Self {
            users: std::collections::HashMap::new(),
            username_index: std::collections::HashMap::new(),
        }
    }

    /// Get or create user
    pub fn get_or_create_user(
        &mut self,
        username: &str,
        display_name: &str,
    ) -> crate::error::Result<User> {
        // Check if user exists
        if let Some(user_id) = self.username_index.get(username) {
            if let Some(user) = self.users.get(user_id) {
                return Ok(user.clone());
            }
        }

        // Create new user
        let user_id = Uuid::new_v4();
        let now = Utc::now();
        
        let user = User {
            id: user_id,
            username: username.to_string(),
            display_name: display_name.to_string(),
            created_at: now,
            updated_at: now,
        };

        self.users.insert(user_id, user.clone());
        self.username_index.insert(username.to_string(), user_id);
        
        Ok(user)
    }

    /// Get user by username
    pub fn get_user_by_username(&self, username: &str) -> crate::error::Result<Option<User>> {
        if let Some(user_id) = self.username_index.get(username) {
            if let Some(user) = self.users.get(user_id) {
                return Ok(Some(user.clone()));
            }
        }
        Ok(None)
    }

    /// Get user by ID
    pub fn get_user_by_id(&self, user_id: Uuid) -> crate::error::Result<Option<User>> {
        Ok(self.users.get(&user_id).cloned())
    }
}