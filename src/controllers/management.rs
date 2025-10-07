use actix_web::{web, HttpRequest, HttpResponse, Result as ActixResult};
use uuid::Uuid;

use crate::services::{CredentialService, UserService};
use crate::schema::{CredentialListResponse, ErrorResponse, HealthResponse};
use crate::error::{AppError, Result};

pub struct ManagementController {
    user_service: web::Data<UserService>,
    credential_service: web::Data<CredentialService>,
}

impl ManagementController {
    pub fn new(
        user_service: web::Data<UserService>,
        credential_service: web::Data<CredentialService>,
    ) -> Self {
        Self {
            user_service,
            credential_service,
        }
    }

    fn extract_request_context(req: &HttpRequest) -> (Option<String>, Option<String>) {
        let ip_address = req.connection_info().peer_addr().map(|s| s.to_string());
        let user_agent = req.headers().get("user-agent")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());
        (ip_address, user_agent)
    }

    pub async fn list_credentials(
        path: web::Path<String>,
        credential_service: web::Data<CredentialService>,
    ) -> ActixResult<HttpResponse> {
        let user_id_str = path.into_inner();
        
        let user_id = Uuid::parse_str(&user_id_str)
            .map_err(|_| AppError::InvalidRequest("Invalid user ID".to_string()))?;

        match credential_service.list_user_credentials(&user_id).await {
            Ok(credentials) => Ok(HttpResponse::Ok().json(CredentialListResponse {
                status: "ok".to_string(),
                error_message: String::new(),
                credentials,
            })),
            Err(e) => {
                log::error!("List credentials error: {}", e);
                Ok(HttpResponse::BadRequest().json(ErrorResponse {
                    status: "error".to_string(),
                    error_message: e.to_string(),
                }))
            }
        }
    }

    pub async fn delete_credential(
        path: web::Path<(String, String)>,
        req: HttpRequest,
        credential_service: web::Data<CredentialService>,
    ) -> ActixResult<HttpResponse> {
        let (user_id_str, credential_id) = path.into_inner();
        
        let user_id = Uuid::parse_str(&user_id_str)
            .map_err(|_| AppError::InvalidRequest("Invalid user ID".to_string()))?;

        let (ip_address, user_agent) = Self::extract_request_context(&req);

        match credential_service.delete_credential(&credential_id, &user_id, ip_address, user_agent).await {
            Ok(_) => Ok(HttpResponse::Ok().json(serde_json::json!({
                "status": "ok",
                "message": "Credential deleted successfully"
            }))),
            Err(e) => {
                log::error!("Delete credential error: {}", e);
                Ok(HttpResponse::BadRequest().json(ErrorResponse {
                    status: "error".to_string(),
                    error_message: e.to_string(),
                }))
            }
        }
    }

    pub async fn health_check() -> ActixResult<HttpResponse> {
        let response = HealthResponse {
            status: "healthy".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        };
        
        Ok(HttpResponse::Ok().json(response))
    }
}