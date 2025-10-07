use actix_web::{web, HttpRequest, HttpResponse, Result as ActixResult};
use uuid::Uuid;
use validator::Validate;

use crate::error::{AppError, Result};
use crate::schema::{
    AttestationOptionsRequest, AttestationOptionsResponse, AttestationResultRequest,
    AttestationResultResponse, ErrorResponse, RequestContext,
};
use crate::services::WebAuthnService;

pub struct WebAuthnController {
    webauthn_service: web::Data<WebAuthnService>,
}

impl WebAuthnController {
    pub fn new(webauthn_service: web::Data<WebAuthnService>) -> Self {
        Self { webauthn_service }
    }

    fn extract_request_context(req: &HttpRequest) -> RequestContext {
        RequestContext {
            ip_address: req.connection_info().peer_addr().map(|s| s.to_string()),
            user_agent: req
                .headers()
                .get("user-agent")
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string()),
            session_id: None,
        }
    }

    pub async fn start_attestation(
        req: HttpRequest,
        webauthn_service: web::Data<WebAuthnService>,
        request: web::Json<AttestationOptionsRequest>,
    ) -> ActixResult<HttpResponse> {
        let context = Self::extract_request_context(&req);

        match webauthn_service
            .start_attestation(request.into_inner(), &context)
            .await
        {
            Ok(response) => Ok(HttpResponse::Ok().json(response)),
            Err(e) => {
                log::error!("Attestation start error: {}", e);
                Ok(HttpResponse::BadRequest().json(ErrorResponse {
                    status: "error".to_string(),
                    error_message: e.to_string(),
                }))
            }
        }
    }

    pub async fn finish_attestation(
        req: HttpRequest,
        webauthn_service: web::Data<WebAuthnService>,
        request: web::Json<AttestationResultRequest>,
    ) -> ActixResult<HttpResponse> {
        let context = Self::extract_request_context(&req);

        match webauthn_service
            .finish_attestation(request.into_inner(), &context)
            .await
        {
            Ok(response) => Ok(HttpResponse::Ok().json(response)),
            Err(e) => {
                log::error!("Attestation finish error: {}", e);
                Ok(HttpResponse::BadRequest().json(ErrorResponse {
                    status: "error".to_string(),
                    error_message: e.to_string(),
                }))
            }
        }
    }
}
