//! User repository implementation

use crate::error::{AppError, Result};
use crate::models::User;
use crate::repositories::UserRepository;
use async_trait::async_trait;
use diesel::prelude::*;
use diesel::r2d2::{ConnectionManager, Pool};
use diesel::pg::PgConnection;
use std::sync::Arc;
use uuid::Uuid;

diesel::table! {
    users (id) {
        id -> Uuid,
        username -> Varchar,
        display_name -> Varchar,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        is_active -> Bool,
    }
}

#[derive(Queryable, Insertable, AsChangeset)]
#[diesel(table_name = users)]
struct UserRow {
    id: Uuid,
    username: String,
    display_name: String,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
    is_active: bool,
}

impl From<User> for UserRow {
    fn from(user: User) -> Self {
        UserRow {
            id: user.id,
            username: user.username,
            display_name: user.display_name,
            created_at: user.created_at,
            updated_at: user.updated_at,
            is_active: user.is_active,
        }
    }
}

impl TryFrom<UserRow> for User {
    type Error = AppError;

    fn try_from(row: UserRow) -> Result<Self> {
        Ok(User {
            id: row.id,
            username: row.username,
            display_name: row.display_name,
            created_at: row.created_at,
            updated_at: row.updated_at,
            is_active: row.is_active,
        })
    }
}

pub struct UserRepositoryImpl {
    pool: Arc<Pool<ConnectionManager<PgConnection>>>,
}

impl UserRepositoryImpl {
    pub fn new(pool: Arc<Pool<ConnectionManager<PgConnection>>>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserRepository for UserRepositoryImpl {
    async fn create_user(&self, user: &User) -> Result<()> {
        let user_row = UserRow::from(user.clone());
        let mut conn = self.pool.get()?;
        
        diesel::insert_into(users::table)
            .values(&user_row)
            .execute(&mut conn)?;
            
        Ok(())
    }

    async fn get_user_by_username(&self, username: &str) -> Result<Option<User>> {
        let mut conn = self.pool.get()?;
        
        let user_row: Option<UserRow> = users::table
            .filter(users::username.eq(username))
            .first(&mut conn)
            .optional()?;
            
        match user_row {
            Some(row) => Ok(Some(User::try_from(row)?)),
            None => Ok(None),
        }
    }

    async fn get_user_by_id(&self, user_id: &Uuid) -> Result<Option<User>> {
        let mut conn = self.pool.get()?;
        
        let user_row: Option<UserRow> = users::table
            .filter(users::id.eq(user_id))
            .first(&mut conn)
            .optional()?;
            
        match user_row {
            Some(row) => Ok(Some(User::try_from(row)?)),
            None => Ok(None),
        }
    }

    async fn update_user(&self, user: &User) -> Result<()> {
        let user_row = UserRow::from(user.clone());
        let mut conn = self.pool.get()?;
        
        diesel::update(users::table.filter(users::id.eq(&user.id)))
            .set(&user_row)
            .execute(&mut conn)?;
            
        Ok(())
    }

    async fn delete_user(&self, user_id: &Uuid) -> Result<()> {
        let mut conn = self.pool.get()?;
        
        diesel::delete(users::table.filter(users::id.eq(user_id)))
            .execute(&mut conn)?;
            
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use diesel::r2d2::ConnectionManager;

    fn create_test_pool() -> Arc<Pool<ConnectionManager<PgConnection>>> {
        // This would normally use a test database
        // For now, we'll create a mock implementation
        panic!("Test database not configured");
    }

    #[tokio::test]
    async fn test_user_crud_operations() {
        // These tests would require a test database
        // For now, we'll skip actual database tests
        // In a real implementation, you'd set up an in-memory test database
    }
}