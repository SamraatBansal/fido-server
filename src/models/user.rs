use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl User {
    pub fn new(username: String, display_name: String) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            username,
            display_name,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn update_display_name(&mut self, display_name: String) {
        self.display_name = display_name;
        self.updated_at = Utc::now();
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub display_name: String,
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub created_at: DateTime<Utc>,
    pub credential_count: usize,
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            username: user.username,
            display_name: user.display_name,
            created_at: user.created_at,
            credential_count: 0, // Will be populated by the service layer
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_creation() {
        let user = User::new("test@example.com".to_string(), "Test User".to_string());
        
        assert_eq!(user.username, "test@example.com");
        assert_eq!(user.display_name, "Test User");
        assert!(user.created_at <= Utc::now());
        assert_eq!(user.created_at, user.updated_at);
    }

    #[test]
    fn test_user_update_display_name() {
        let mut user = User::new("test@example.com".to_string(), "Test User".to_string());
        let original_updated_at = user.updated_at;
        
        // Small delay to ensure timestamp difference
        std::thread::sleep(std::time::Duration::from_millis(1));
        
        user.update_display_name("Updated User".to_string());
        
        assert_eq!(user.display_name, "Updated User");
        assert!(user.updated_at > original_updated_at);
    }
}