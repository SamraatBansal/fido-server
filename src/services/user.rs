//! User management service

use async_trait::async_trait;
use crate::error::{AppError, Result};
use crate::schema::user::User;
use uuid::Uuid;

/// User repository trait for dependency injection
#[async_trait]
pub trait UserRepository: Send + Sync {
    /// Create a new user
    async fn create(&self, user: &User) -> Result<()>;
    
    /// Find a user by ID
    async fn find_by_id(&self, id: &Uuid) -> Result<Option<User>>;
    
    /// Find a user by username (email)
    async fn find_by_username(&self, username: &str) -> Result<Option<User>>;
    
    /// Update a user
    async fn update(&self, user: &User) -> Result<()>;
    
    /// Delete a user
    async fn delete(&self, id: &Uuid) -> Result<()>;
    
    /// Check if a username exists
    async fn username_exists(&self, username: &str) -> Result<bool>;
}

/// In-memory user repository for testing and development
#[derive(Debug, Default)]
pub struct InMemoryUserRepository {
    users: std::sync::Arc<tokio::sync::RwLock<std::collections::HashMap<Uuid, User>>>,
    username_index: std::sync::Arc<tokio::sync::RwLock<std::collections::HashMap<String, Uuid>>>,
}

impl InMemoryUserRepository {
    /// Create a new in-memory user repository
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl UserRepository for InMemoryUserRepository {
    async fn create(&self, user: &User) -> Result<()> {
        // Validate user before storing
        user.validate().map_err(|e| AppError::ValidationError(e))?;

        let mut users = self.users.write().await;
        let mut username_index = self.username_index.write().await;
        
        // Check for duplicate username
        if username_index.contains_key(&user.username) {
            return Err(AppError::BadRequest("Username already exists".to_string()));
        }
        
        users.insert(user.id, user.clone());
        username_index.insert(user.username.clone(), user.id);
        Ok(())
    }

    async fn find_by_id(&self, id: &Uuid) -> Result<Option<User>> {
        let users = self.users.read().await;
        Ok(users.get(id).cloned())
    }

    async fn find_by_username(&self, username: &str) -> Result<Option<User>> {
        let username_index = self.username_index.read().await;
        
        if let Some(user_id) = username_index.get(username) {
            let users = self.users.read().await;
            Ok(users.get(user_id).cloned())
        } else {
            Ok(None)
        }
    }

    async fn update(&self, user: &User) -> Result<()> {
        // Validate user before updating
        user.validate().map_err(|e| AppError::ValidationError(e))?;

        let mut users = self.users.write().await;
        let mut username_index = self.username_index.write().await;
        
        // Check if user exists
        if let Some(existing_user) = users.get(&user.id) {
            // If username changed, update the index
            if existing_user.username != user.username {
                // Remove old username from index
                username_index.remove(&existing_user.username);
                
                // Check if new username is already taken
                if username_index.contains_key(&user.username) {
                    return Err(AppError::BadRequest("Username already exists".to_string()));
                }
                
                // Add new username to index
                username_index.insert(user.username.clone(), user.id);
            }
            
            users.insert(user.id, user.clone());
            Ok(())
        } else {
            Err(AppError::NotFound("User not found".to_string()))
        }
    }

    async fn delete(&self, id: &Uuid) -> Result<()> {
        let mut users = self.users.write().await;
        let mut username_index = self.username_index.write().await;
        
        if let Some(user) = users.remove(id) {
            username_index.remove(&user.username);
            Ok(())
        } else {
            Err(AppError::NotFound("User not found".to_string()))
        }
    }

    async fn username_exists(&self, username: &str) -> Result<bool> {
        let username_index = self.username_index.read().await;
        Ok(username_index.contains_key(username))
    }
}

/// User service
pub struct UserService {
    repository: InMemoryUserRepository,
}

impl UserService {
    /// Create a new user service
    pub fn new(repository: InMemoryUserRepository) -> Self {
        Self { repository }
    }

    /// Create a new user
    pub async fn create_user(&self, username: String, display_name: String) -> Result<User> {
        let user = User::new(username.clone(), display_name);
        
        // Check if username already exists
        if self.repository.username_exists(&username).await? {
            return Err(AppError::BadRequest("Username already exists".to_string()));
        }
        
        self.repository.create(&user).await?;
        Ok(user)
    }

    /// Get a user by ID
    pub async fn get_user(&self, id: &Uuid) -> Result<Option<User>> {
        self.repository.find_by_id(id).await
    }

    /// Get a user by username
    pub async fn get_user_by_username(&self, username: &str) -> Result<Option<User>> {
        self.repository.find_by_username(username).await
    }

    /// Get or create a user (useful for registration flows)
    pub async fn get_or_create_user(&self, username: String, display_name: String) -> Result<User> {
        // Try to find existing user
        if let Some(user) = self.repository.find_by_username(&username).await? {
            return Ok(user);
        }
        
        // Create new user if not found
        self.create_user(username, display_name).await
    }

    /// Update user information
    pub async fn update_user(&self, user: User) -> Result<User> {
        self.repository.update(&user).await?;
        Ok(user)
    }

    /// Delete a user
    pub async fn delete_user(&self, id: &Uuid) -> Result<()> {
        self.repository.delete(id).await
    }

    /// Validate username format
    pub fn validate_username(&self, username: &str) -> Result<()> {
        if username.is_empty() {
            return Err(AppError::ValidationError("Username cannot be empty".to_string()));
        }

        // Basic email validation - check for exactly one @ and no SQL injection patterns
        if !username.contains('@') {
            return Err(AppError::ValidationError("Username must be a valid email address".to_string()));
        }

        // Check for SQL injection patterns
        if username.to_lowercase().contains("drop") || 
           username.to_lowercase().contains("delete") ||
           username.to_lowercase().contains("insert") ||
           username.to_lowercase().contains("update") ||
           username.contains(';') ||
           username.contains('\'') {
            return Err(AppError::ValidationError("Invalid characters in username".to_string()));
        }

        // Basic email validation
        if username.len() > 255 {
            return Err(AppError::ValidationError("Username too long (max 255 characters)".to_string()));
        }

        // More comprehensive email validation could be added here
        Ok(())
    }

    /// Validate display name format
    pub fn validate_display_name(&self, display_name: &str) -> Result<()> {
        if display_name.is_empty() {
            return Err(AppError::ValidationError("Display name cannot be empty".to_string()));
        }

        if display_name.len() > 255 {
            return Err(AppError::ValidationError("Display name too long (max 255 characters)".to_string()));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_in_memory_user_repository() {
        let repo = InMemoryUserRepository::new();
        let user = User::new(
            "test@example.com".to_string(),
            "Test User".to_string(),
        );

        // Create user
        repo.create(&user).await.unwrap();

        // Find by ID
        let found = repo.find_by_id(&user.id).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap(), user);

        // Find by username
        let found_by_username = repo.find_by_username(&user.username).await.unwrap();
        assert!(found_by_username.is_some());
        assert_eq!(found_by_username.unwrap(), user);

        // Check username exists
        assert!(repo.username_exists(&user.username).await.unwrap());

        // Update user
        let mut updated_user = user.clone();
        updated_user.display_name = "Updated Name".to_string();
        repo.update(&updated_user).await.unwrap();

        let found_updated = repo.find_by_id(&user.id).await.unwrap();
        assert_eq!(found_updated.unwrap().display_name, "Updated Name");

        // Delete user
        repo.delete(&user.id).await.unwrap();
        assert!(!repo.username_exists(&user.username).await.unwrap());
    }

    #[tokio::test]
    async fn test_duplicate_username() {
        let repo = InMemoryUserRepository::new();
        let user1 = User::new(
            "test@example.com".to_string(),
            "Test User 1".to_string(),
        );

        let user2 = User::new(
            "test@example.com".to_string(),
            "Test User 2".to_string(),
        );

        // Create first user
        repo.create(&user1).await.unwrap();

        // Try to create second user with same username
        let result = repo.create(&user2).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::BadRequest(_)));
    }

    #[tokio::test]
    async fn test_user_validation() {
        let repo = InMemoryUserRepository::new();

        // Test invalid user (empty username)
        let invalid_user = User::new(
            "".to_string(),
            "Test User".to_string(),
        );

        let result = repo.create(&invalid_user).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::ValidationError(_)));

        // Test invalid user (invalid email)
        let invalid_user2 = User::new(
            "invalid-email".to_string(),
            "Test User".to_string(),
        );

        let result = repo.create(&invalid_user2).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AppError::ValidationError(_)));
    }

    #[tokio::test]
    async fn test_user_service_create() {
        let repo = InMemoryUserRepository::new();
        let service = UserService::new(repo);

        let user = service.create_user(
            "test@example.com".to_string(),
            "Test User".to_string(),
        ).await.unwrap();

        assert_eq!(user.username, "test@example.com");
        assert_eq!(user.display_name, "Test User");
        assert!(!user.id.to_string().is_empty());
    }

    #[tokio::test]
    async fn test_user_service_get_by_username() {
        let repo = InMemoryUserRepository::new();
        let service = UserService::new(repo);

        // Create user
        let created_user = service.create_user(
            "test@example.com".to_string(),
            "Test User".to_string(),
        ).await.unwrap();

        // Get by username
        let found_user = service.get_user_by_username("test@example.com").await.unwrap();
        assert!(found_user.is_some());
        assert_eq!(found_user.unwrap().id, created_user.id);
    }

    #[tokio::test]
    async fn test_user_service_get_or_create_new() {
        let repo = InMemoryUserRepository::new();
        let service = UserService::new(repo);

        // Get or create (should create new user)
        let user = service.get_or_create_user(
            "test@example.com".to_string(),
            "Test User".to_string(),
        ).await.unwrap();

        assert_eq!(user.username, "test@example.com");
    }

    #[tokio::test]
    async fn test_user_service_get_or_create_existing() {
        let repo = InMemoryUserRepository::new();
        let service = UserService::new(repo);

        // Create initial user
        let initial_user = service.create_user(
            "test@example.com".to_string(),
            "Test User".to_string(),
        ).await.unwrap();

        // Get or create (should return existing user)
        let user = service.get_or_create_user(
            "test@example.com".to_string(),
            "Different Name".to_string(), // This should be ignored
        ).await.unwrap();

        assert_eq!(user.id, initial_user.id);
        assert_eq!(user.display_name, "Test User"); // Original name preserved
    }

    #[tokio::test]
    async fn test_user_service_validation() {
        let repo = InMemoryUserRepository::new();
        let service = UserService::new(repo);

        // Test valid username
        assert!(service.validate_username("test@example.com").is_ok());

        // Test invalid usernames
        assert!(service.validate_username("").is_err());
        assert!(service.validate_username("invalid-email").is_err());
        assert!(service.validate_username(&"a".repeat(256)).is_err());

        // Test valid display name
        assert!(service.validate_display_name("Test User").is_ok());

        // Test invalid display names
        assert!(service.validate_display_name("").is_err());
        assert!(service.validate_display_name(&"a".repeat(256)).is_err());
    }

    #[tokio::test]
    async fn test_user_service_update() {
        let repo = InMemoryUserRepository::new();
        let service = UserService::new(repo);

        // Create user
        let mut user = service.create_user(
            "test@example.com".to_string(),
            "Test User".to_string(),
        ).await.unwrap();

        // Update user
        user.display_name = "Updated Name".to_string();
        let updated_user = service.update_user(user).await.unwrap();

        assert_eq!(updated_user.display_name, "Updated Name");
    }

    #[tokio::test]
    async fn test_user_service_delete() {
        let repo = InMemoryUserRepository::new();
        let service = UserService::new(repo);

        // Create user
        let user = service.create_user(
            "test@example.com".to_string(),
            "Test User".to_string(),
        ).await.unwrap();

        // Delete user
        service.delete_user(&user.id).await.unwrap();

        // Verify user is gone
        let found = service.get_user(&user.id).await.unwrap();
        assert!(found.is_none());
    }
}