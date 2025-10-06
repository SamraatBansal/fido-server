//! Credential management controller

use actix_web::{web, HttpResponse, Result};
use serde_json::json;
use uuid::Uuid;

use crate::services::{CredentialService, UserService};
use crate::schema::responses::SuccessResponse;

/// List user credentials endpoint
pub async fn list_credentials(
    user_service: web::Data<Arc<UserService>>,
    credential_service: web::Data<Arc<CredentialService>>,
    // TODO: Add authentication middleware to get user_id from JWT
) -> Result<HttpResponse> {
    // For now, use a dummy user_id - in production, this would come from JWT
    let user_id = Uuid::new_v4(); // TODO: Get from authenticated session

    match user_service.get_user_by_id(&user_id).await {
        Ok(Some(_user)) => {
            match credential_service.get_user_credentials(&user_id).await {
                Ok(credentials) => {
                    let credential_list: Vec<serde_json::Value> = credentials
                        .into_iter()
                        .map(|cred| json!({
                            "id": cred.id,
                            "credential_id": base64::engine::general_purpose::STANDARD.encode(&cred.credential_id),
                            "created_at": cred.created_at,
                            "last_used_at": cred.last_used_at,
                            "backup_eligible": cred.backup_eligible,
                            "backup_state": cred.backup_state,
                            "attestation_format": cred.attestation_format
                        }))
                        .collect();

                    let response = SuccessResponse::new(json!({
                        "credentials": credential_list,
                        "count": credential_list.len()
                    }));
                    Ok(HttpResponse::Ok().json(response))
                }
                Err(e) => {
                    log::error!("Failed to list credentials: {:?}", e);
                    Err(actix_web::error::ErrorInternalServerError(e.to_string()))
                }
            }
        }
        Ok(None) => {
            Err(actix_web::error::ErrorNotFound("User not found"))
        }
        Err(e) => {
            log::error!("Failed to get user: {:?}", e);
            Err(actix_web::error::ErrorInternalServerError(e.to_string()))
        }
    }
}

/// Delete credential endpoint
pub async fn delete_credential(
    user_service: web::Data<Arc<UserService>>,
    credential_service: web::Data<Arc<CredentialService>>,
    path: web::Path<Uuid>,
    // TODO: Add authentication middleware to get user_id from JWT
) -> Result<HttpResponse> {
    let credential_id = path.into_inner();
    
    // For now, use a dummy user_id - in production, this would come from JWT
    let user_id = Uuid::new_v4(); // TODO: Get from authenticated session

    // Verify user exists
    match user_service.get_user_by_id(&user_id).await {
        Ok(Some(_user)) => {
            match credential_service.delete_credential(&credential_id, &user_id).await {
                Ok(_) => {
                    let response = SuccessResponse::with_message(
                        json!({"credential_id": credential_id}),
                        "Credential deleted successfully"
                    );
                    Ok(HttpResponse::Ok().json(response))
                }
                Err(e) => {
                    log::error!("Failed to delete credential: {:?}", e);
                    Err(actix_web::error::ErrorInternalServerError(e.to_string()))
                }
            }
        }
        Ok(None) => {
            Err(actix_web::error::ErrorNotFound("User not found"))
        }
        Err(e) => {
            log::error!("Failed to get user: {:?}", e);
            Err(actix_web::error::ErrorInternalServerError(e.to_string()))
        }
    }
}