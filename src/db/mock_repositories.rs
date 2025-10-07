use mockall::mock;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use crate::db::models::{User, Credential, AuthSession, AuditLog, NewUser, NewCredential, NewAuthSession, NewAuditLog};
use crate::error::{AppError, Result};
use async_trait::async_trait;

mock! {
    pub UserRepository {}

    #[async_trait]
    impl UserRepository for UserRepository {
        async fn create_user(&self, user: &NewUser) -> Result<User>;
        async fn find_by_id(&self, id: &Uuid) -> Result<Option<User>>;
        async fn find_by_username(&self, username: &str) -> Result<Option<User>>;
        async fn update_user(&self, user: &User) -> Result<User>;
        async fn delete_user(&self, id: &Uuid) -> Result<()>;
        async fn update_last_login(&self, id: &Uuid) -> Result<()>;
        async fn list_users(&self, limit: i64, offset: i64) -> Result<Vec<User>>;
    }
}

mock! {
    pub CredentialRepository {}

    #[async_trait]
    impl CredentialRepository for CredentialRepository {
        async fn create_credential(&self, credential: &NewCredential) -> Result<Credential>;
        async fn find_by_id(&self, id: &Uuid) -> Result<Option<Credential>>;
        async fn find_by_credential_id(&self, id: &[u8]) -> Result<Option<Credential>>;
        async fn find_by_user_id(&self, user_id: &Uuid) -> Result<Vec<Credential>>;
        async fn update_credential(&self, credential: &Credential) -> Result<Credential>;
        async fn update_sign_count(&self, id: &[u8], count: i64) -> Result<()>;
        async fn update_last_used(&self, id: &[u8]) -> Result<()>;
        async fn delete_credential(&self, id: &[u8]) -> Result<()>;
        async fn list_credentials(&self, limit: i64, offset: i64) -> Result<Vec<Credential>>;
    }
}

mock! {
    pub AuthSessionRepository {}

    #[async_trait]
    impl AuthSessionRepository for AuthSessionRepository {
        async fn create_session(&self, session: &NewAuthSession) -> Result<AuthSession>;
        async fn find_by_id(&self, id: &Uuid) -> Result<Option<AuthSession>>;
        async fn find_by_session_id(&self, session_id: &str) -> Result<Option<AuthSession>>;
        async fn find_by_user_id(&self, user_id: &Uuid) -> Result<Vec<AuthSession>>;
        async fn delete_session(&self, session_id: &str) -> Result<()>;
        async fn cleanup_expired_sessions(&self) -> Result<u64>;
    }
}

mock! {
    pub AuditLogRepository {}

    #[async_trait]
    impl AuditLogRepository for AuditLogRepository {
        async fn create_log(&self, log: &NewAuditLog) -> Result<AuditLog>;
        async fn find_by_id(&self, id: &Uuid) -> Result<Option<AuditLog>>;
        async fn find_by_user_id(&self, user_id: &Uuid, limit: i64, offset: i64) -> Result<Vec<AuditLog>>;
        async fn find_by_action(&self, action: &str, limit: i64, offset: i64) -> Result<Vec<AuditLog>>;
        async fn list_logs(&self, limit: i64, offset: i64) -> Result<Vec<AuditLog>>;
        async fn cleanup_old_logs(&self, days: i64) -> Result<u64>;
    }
}