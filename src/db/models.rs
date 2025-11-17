use crate::schema::*;
use crate::{AppError, Result};
use chrono::{NaiveDateTime, Utc};
use diesel::prelude::*;
use uuid::Uuid;

use super::{DbPool, PooledDbConnection};

pub struct UserRepository {
    pool: DbPool,
}

impl UserRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
    
    fn get_connection(&self) -> Result<PooledDbConnection> {
        self.pool.get().map_err(AppError::Pool)
    }
    
    pub fn find_by_username(&self, username: &str) -> Result<Option<User>> {
        use crate::schema::users::dsl::*;
        
        let mut conn = self.get_connection()?;
        let user = users
            .filter(crate::schema::users::username.eq(username))
            .first::<User>(&mut conn)
            .optional()?;
            
        Ok(user)
    }
    
    pub fn find_by_user_handle(&self, user_handle: &[u8]) -> Result<Option<User>> {
        use crate::schema::users::dsl::*;
        
        let mut conn = self.get_connection()?;
        let user = users
            .filter(crate::schema::users::user_handle.eq(user_handle))
            .first::<User>(&mut conn)
            .optional()?;
            
        Ok(user)
    }
    
    pub fn create(&self, new_user: &NewUser) -> Result<User> {
        use crate::schema::users::dsl::*;
        
        let mut conn = self.get_connection()?;
        let user = diesel::insert_into(users)
            .values(new_user)
            .get_result::<User>(&mut conn)?;
            
        Ok(user)
    }
    
    pub fn find_or_create(&self, username: &str, display_name: &str) -> Result<User> {
        if let Some(user) = self.find_by_username(username)? {
            Ok(user)
        } else {
            let new_user = NewUser::new(username.to_string(), display_name.to_string());
            self.create(&new_user)
        }
    }
}

pub struct CredentialRepository {
    pool: DbPool,
}

impl CredentialRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
    
    fn get_connection(&self) -> Result<PooledDbConnection> {
        self.pool.get().map_err(AppError::Pool)
    }
    
    pub fn find_by_user_id(&self, user_id: Uuid) -> Result<Vec<Credential>> {
        use crate::schema::credentials::dsl::*;
        
        let mut conn = self.get_connection()?;
        let creds = credentials
            .filter(crate::schema::credentials::user_id.eq(user_id))
            .load::<Credential>(&mut conn)?;
            
        Ok(creds)
    }
    
    pub fn find_by_credential_id(&self, credential_id: &[u8]) -> Result<Option<Credential>> {
        use crate::schema::credentials::dsl::*;
        
        let mut conn = self.get_connection()?;
        let cred = credentials
            .filter(crate::schema::credentials::credential_id.eq(credential_id))
            .first::<Credential>(&mut conn)
            .optional()?;
            
        Ok(cred)
    }
    
    pub fn create(&self, new_credential: &NewCredential) -> Result<Credential> {
        use crate::schema::credentials::dsl::*;
        
        let mut conn = self.get_connection()?;
        let cred = diesel::insert_into(credentials)
            .values(new_credential)
            .get_result::<Credential>(&mut conn)?;
            
        Ok(cred)
    }
    
    pub fn update_sign_count(&self, credential_id: &[u8], new_count: i64) -> Result<()> {
        use crate::schema::credentials::dsl::*;
        
        let mut conn = self.get_connection()?;
        
        let update_data = UpdateCredential {
            sign_count: Some(new_count),
            last_used_at: Some(Utc::now().naive_utc()),
        };
        
        diesel::update(credentials.filter(crate::schema::credentials::credential_id.eq(credential_id)))
            .set(&update_data)
            .execute(&mut conn)?;
            
        Ok(())
    }
}

pub struct ChallengeRepository {
    pool: DbPool,
}

impl ChallengeRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
    
    fn get_connection(&self) -> Result<PooledDbConnection> {
        self.pool.get().map_err(AppError::Pool)
    }
    
    pub fn store_registration_challenge(&self, challenge: &NewRegistrationChallenge) -> Result<RegistrationChallenge> {
        use crate::schema::registration_challenges::dsl::*;
        
        let mut conn = self.get_connection()?;
        let stored = diesel::insert_into(registration_challenges)
            .values(challenge)
            .get_result::<RegistrationChallenge>(&mut conn)?;
            
        Ok(stored)
    }
    
    pub fn get_registration_challenge(&self, user_id: Uuid) -> Result<Option<RegistrationChallenge>> {
        use crate::schema::registration_challenges::dsl::*;
        
        let mut conn = self.get_connection()?;
        let now = Utc::now().naive_utc();
        
        let challenge = registration_challenges
            .filter(crate::schema::registration_challenges::user_id.eq(user_id))
            .filter(expires_at.gt(now))
            .order(created_at.desc())
            .first::<RegistrationChallenge>(&mut conn)
            .optional()?;
            
        Ok(challenge)
    }
    
    pub fn delete_registration_challenge(&self, user_id: Uuid) -> Result<()> {
        use crate::schema::registration_challenges::dsl::*;
        
        let mut conn = self.get_connection()?;
        diesel::delete(registration_challenges.filter(crate::schema::registration_challenges::user_id.eq(user_id)))
            .execute(&mut conn)?;
            
        Ok(())
    }
    
    pub fn store_authentication_challenge(&self, challenge: &NewAuthenticationChallenge) -> Result<AuthenticationChallenge> {
        use crate::schema::authentication_challenges::dsl::*;
        
        let mut conn = self.get_connection()?;
        let stored = diesel::insert_into(authentication_challenges)
            .values(challenge)
            .get_result::<AuthenticationChallenge>(&mut conn)?;
            
        Ok(stored)
    }
    
    pub fn get_authentication_challenge(&self, challenge_bytes: &[u8]) -> Result<Option<AuthenticationChallenge>> {
        use crate::schema::authentication_challenges::dsl::*;
        
        let mut conn = self.get_connection()?;
        let now = Utc::now().naive_utc();
        
        let challenge = authentication_challenges
            .filter(challenge.eq(challenge_bytes))
            .filter(expires_at.gt(now))
            .first::<AuthenticationChallenge>(&mut conn)
            .optional()?;
            
        Ok(challenge)
    }
    
    pub fn delete_authentication_challenge(&self, challenge_bytes: &[u8]) -> Result<()> {
        use crate::schema::authentication_challenges::dsl::*;
        
        let mut conn = self.get_connection()?;
        diesel::delete(authentication_challenges.filter(challenge.eq(challenge_bytes)))
            .execute(&mut conn)?;
            
        Ok(())
    }
    
    pub fn find_registration_challenge_by_bytes(&self, challenge_bytes: &[u8]) -> Result<(RegistrationChallenge, Uuid)> {
        use crate::schema::registration_challenges::dsl::*;
        
        let mut conn = self.get_connection()?;
        let now = Utc::now().naive_utc();
        
        let challenge = registration_challenges
            .filter(challenge.eq(challenge_bytes))
            .filter(expires_at.gt(now))
            .first::<RegistrationChallenge>(&mut conn)?;
            
        Ok((challenge.clone(), challenge.user_id))
    }
}