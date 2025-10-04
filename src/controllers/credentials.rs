//! Credential management controller

use actix_web::{web, HttpResponse, Result};
use uuid::Uuid;

use crate::{
    error::AppError,
    middleware::auth::AuthenticatedUser,
    schema::responses::{CredentialInfo, CredentialsListResponse},
    services::CredentialService,
};

/// List user's credentials
pub async fn list_credentials(
    user: AuthenticatedUser,
    credential_service: web::Data<CredentialService>,
) -> Result<HttpResponse> {
    let credentials = credential_service
        .get_user_credentials(&user.user_id)
        .await?;

    let credential_infos: Vec<CredentialInfo> = credentials
        .into_iter()
        .map(|cred| cred.into())
        .collect();

    let response = CredentialsListResponse {
        credentials: credential_infos,
    };

    Ok(HttpResponse::Ok().json(response))
}

/// Delete a credential
pub async fn delete_credential(
    path: web::Path<String>,
    user: AuthenticatedUser,
    credential_service: web::Data<CredentialService>,
) -> Result<HttpResponse> {
    let credential_id = path.into_inner();
    
    // Validate credential ID format
    let _credential_uuid = Uuid::parse_str(&credential_id)
        .map_err(|_| AppError::InvalidRequest("Invalid credential ID format".to_string()))?;

    credential_service
        .delete_credential(&credential_id, &user.user_id)
        .await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Credential deleted successfully"
    })))
}