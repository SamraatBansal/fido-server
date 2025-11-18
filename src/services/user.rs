//! User service implementation

use std::sync::Arc;
use diesel::prelude::*;
use uuid::Uuid;

use crate::{
    db::{models::*, DbPool},
    schema_diesel::{users, credentials},
    AppError, Result,
};

#[derive(Clone)]
pub struct UserService {
    db_pool: Arc<DbPool>,
}

impl UserService {
    pub fn new(db_pool: Arc<DbPool>) -> Self {
        Self { db_pool }
    }

    pub async fn get_user_by_id(&self, user_id: Uuid) -> Result<User> {
        let mut conn = self.db_pool.get().map_err(|e| AppError::DatabaseError(e.to_string()))?;
        
        users::table
            .filter(users::id.eq(user_id))
            .select(User::as_select())
            .first(&mut conn)
            .map_err(|_| AppError::NotFound("User not found".to_string()))
    }

    pub async fn get_user_by_username(&self, username: &str) -> Result<User> {
        let mut conn = self.db_pool.get().map_err(|e| AppError::DatabaseError(e.to_string()))?;
        
        users::table
            .filter(users::username.eq(username))
            .select(User::as_select())
            .first(&mut conn)
            .map_err(|_| AppError::NotFound("User not found".to_string()))
    }

    pub async fn get_user_credentials(&self, user_id: Uuid) -> Result<Vec<Credential>> {
        let mut conn = self.db_pool.get().map_err(|e| AppError::DatabaseError(e.to_string()))?;
        
        credentials::table
            .filter(credentials::user_id.eq(user_id))
            .select(Credential::as_select())
            .load(&mut conn)
            .map_err(|e| AppError::DatabaseError(e.to_string()))
    }

    pub async fn create_user(&self, new_user: &NewUser) -> Result<User> {
        let mut conn = self.db_pool.get().map_err(|e| AppError::DatabaseError(e.to_string()))?;
        
        diesel::insert_into(users::table)
            .values(new_user)
            .get_result::<User>(&mut conn)
            .map_err(|e| AppError::DatabaseError(e.to_string()))
    }
}