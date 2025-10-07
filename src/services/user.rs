use std::sync::Arc;
use uuid::Uuid;
use crate::db::repositories::{UserRepository, CredentialRepository, AuditLogRepository};
use crate::db::models::User;
use crate::schema::CredentialInfo;
use crate::error::{AppError, Result};
use base64::Engine;

pub struct UserService {
    user_repo: Arc<dyn UserRepository>,
    credential_repo: Arc<dyn CredentialRepository>,
    audit_repo: Arc<dyn AuditLogRepository>,
}

impl UserService {
    pub fn new(
        user_repo: Arc<dyn UserRepository>,
        credential_repo: Arc<dyn CredentialRepository>,
        audit_repo: Arc<dyn AuditLogRepository>,
    ) -> Self {
        Self {
            user_repo,
            credential_repo,
            audit_repo,
        }
    }

    pub async fn get_user(&self, user_id: &Uuid) -> Result<User> {
        self.user_repo.find_by_id(user_id).await?
            .ok_or(AppError::UserNotFound)
    }

    pub async fn get_user_by_username(&self, username: &str) -> Result<User> {
        self.user_repo.find_by_username(username).await?
            .ok_or(AppError::UserNotFound)
    }

    pub async fn delete_user(&self, user_id: &Uuid, ip_address: Option<String>, user_agent: Option<String>) -> Result<()> {
        // Delete all credentials first
        self.credential_repo.delete_by_user_id(user_id).await?;
        
        // Delete user
        self.user_repo.delete_user(user_id).await?;

        // Log audit event
        let audit_log = crate::db::models::NewAuditLog {
            user_id: Some(*user_id),
            action: "user_deleted".to_string(),
            resource_type: Some("user".to_string()),
            resource_id: Some(user_id.to_string()),
            ip_address,
            user_agent,
            success: true,
            error_message: None,
            metadata: None,
        };

        self.audit_repo.create_log(&audit_log).await?;

        Ok(())
    }
}

pub struct CredentialService {
    credential_repo: Arc<dyn CredentialRepository>,
    user_repo: Arc<dyn UserRepository>,
    audit_repo: Arc<dyn AuditLogRepository>,
}

impl CredentialService {
    pub fn new(
        credential_repo: Arc<dyn CredentialRepository>,
        user_repo: Arc<dyn UserRepository>,
        audit_repo: Arc<dyn AuditLogRepository>,
    ) -> Self {
        Self {
            credential_repo,
            user_repo,
            audit_repo,
        }
    }

    pub async fn list_user_credentials(&self, user_id: &Uuid) -> Result<Vec<CredentialInfo>> {
        // Verify user exists
        let _user = self.user_repo.find_by_id(user_id).await?
            .ok_or(AppError::UserNotFound)?;

        let credentials = self.credential_repo.find_by_user_id(user_id).await?;
        
        let credential_infos: Vec<CredentialInfo> = credentials.into_iter().map(|cred| {
            CredentialInfo {
                credential_id: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&cred.credential_id),
                type_: "public-key".to_string(),
                name: None, // Could be stored as a separate field
                last_used_at: cred.last_used_at.map(|dt| dt.to_rfc3339()),
                created_at: cred.created_at.to_rfc3339(),
                transports: cred.transfers.as_ref().map(|t| {
                    t.iter().filter_map(|s| match s.as_str() {
                        "usb" => Some(AuthenticatorTransport::Usb),
                        "nfc" => Some(AuthenticatorTransport::Nfc),
                        "ble" => Some(AuthenticatorTransport::Ble),
                        "internal" => Some(AuthenticatorTransport::Internal),
                        _ => None,
                    }).collect()
                }),
            }
        }).collect();

        Ok(credential_infos)
    }

    pub async fn delete_credential(
        &self, 
        credential_id: &str, 
        user_id: &Uuid,
        ip_address: Option<String>, 
        user_agent: Option<String>
    ) -> Result<()> {
        // Decode credential ID
        let credential_id_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(credential_id)
            .map_err(|_| AppError::InvalidRequest("Invalid credential ID".to_string()))?;

        // Find credential and verify ownership
        let credential = self.credential_repo.find_by_credential_id(&credential_id_bytes).await?
            .ok_or(AppError::CredentialNotFound)?;

        if credential.user_id != *user_id {
            return Err(AppError::InvalidRequest("Credential does not belong to user".to_string()));
        }

        // Delete credential
        self.credential_repo.delete_credential(&credential_id_bytes).await?;

        // Log audit event
        let audit_log = crate::db::models::NewAuditLog {
            user_id: Some(*user_id),
            action: "credential_deleted".to_string(),
            resource_type: Some("credential".to_string()),
            resource_id: Some(credential_id.to_string()),
            ip_address,
            user_agent,
            success: true,
            error_message: None,
            metadata: Some(serde_json::json!({
                "credential_id": credential_id
            })),
        };

        self.audit_repo.create_log(&audit_log).await?;

        Ok(())
    }
}