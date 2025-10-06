//! FIDO/WebAuthn HTTP controllers

use actix_web::{web, HttpResponse, Result as ActixResult};
use webauthn_rs::prelude::*;
use webauthn_rs_proto::{
    UserVerificationPolicy, AttestationConveyancePreference, 
    ResidentKeyRequirement, AuthenticatorAttachment
};
use uuid::Uuid;

use crate::db::DbPool;
use crate::error::{AppError, Result};
use crate::schema::*;
use crate::services::FidoService;

/// FIDO controller state
pub struct FidoController {
    /// FIDO service
    fido_service: FidoService,
}

impl FidoController {
    /// Create new FIDO controller
    pub fn new(fido_service: FidoService) -> Self {
        Self { fido_service }
    }

    /// Start registration
    pub async fn start_registration(
        &self,
        pool: web::Data<DbPool>,
        req: web::Json<RegistrationStartRequest>,
    ) -> ActixResult<HttpResponse> {
        let mut conn = pool.get().map_err(|e| AppError::DatabaseConnection(e))?;

        let user_verification = match req.user_verification.as_deref() {
            Some("required") => Some(UserVerificationPolicy::Required),
            Some("preferred") => Some(UserVerificationPolicy::Preferred),
            Some("discouraged") => Some(UserVerificationPolicy::Discouraged),
            _ => Some(UserVerificationPolicy::Preferred),
        };

        let attestation = match req.attestation.as_deref() {
            Some("none") => Some(AttestationConveyancePreference::None),
            Some("indirect") => Some(AttestationConveyancePreference::Indirect),
            Some("direct") => Some(AttestationConveyancePreference::Direct),
            Some("enterprise") => Some(AttestationConveyancePreference::Enterprise),
            _ => Some(AttestationConveyancePreference::Direct),
        };

        let resident_key = match req.resident_key.as_deref() {
            Some("discouraged") => Some(ResidentKeyRequirement::Discouraged),
            Some("preferred") => Some(ResidentKeyRequirement::Preferred),
            Some("required") => Some(ResidentKeyRequirement::Required),
            _ => Some(ResidentKeyRequirement::Preferred),
        };

        let authenticator_attachment = match req.authenticator_attachment.as_deref() {
            Some("platform") => Some(AuthenticatorAttachment::Platform),
            Some("cross-platform") => Some(AuthenticatorAttachment::CrossPlatform),
            _ => None,
        };

        let response = self.fido_service
            .start_registration(
                &mut conn,
                &req.username,
                &req.display_name,
                user_verification,
                attestation,
                resident_key,
                authenticator_attachment,
            )
            .await?;

        Ok(HttpResponse::Ok().json(SuccessResponse::new(response)))
    }

    /// Finish registration
    pub async fn finish_registration(
        &self,
        pool: web::Data<DbPool>,
        req: web::Json<RegistrationFinishRequest>,
    ) -> ActixResult<HttpResponse> {
        let mut conn = pool.get().map_err(|e| AppError::DatabaseConnection(e))?;

        let response = self.fido_service
            .finish_registration(
                &mut conn,
                &req.credential_id,
                &req.client_data_json,
                &req.attestation_object,
                req.transports.clone(),
            )
            .await?;

        Ok(HttpResponse::Ok().json(SuccessResponse::new(response)))
    }

    /// Start authentication
    pub async fn start_authentication(
        &self,
        pool: web::Data<DbPool>,
        req: web::Json<AuthenticationStartRequest>,
    ) -> ActixResult<HttpResponse> {
        let mut conn = pool.get().map_err(|e| AppError::DatabaseConnection(e))?;

        let user_verification = match req.user_verification.as_deref() {
            Some("required") => Some(UserVerificationPolicy::Required),
            Some("preferred") => Some(UserVerificationPolicy::Preferred),
            Some("discouraged") => Some(UserVerificationPolicy::Discouraged),
            _ => Some(UserVerificationPolicy::Preferred),
        };

        let response = self.fido_service
            .start_authentication(
                &mut conn,
                req.username.as_deref(),
                user_verification,
            )
            .await?;

        Ok(HttpResponse::Ok().json(SuccessResponse::new(response)))
    }

    /// Finish authentication
    pub async fn finish_authentication(
        &self,
        pool: web::Data<DbPool>,
        req: web::Json<AuthenticationFinishRequest>,
    ) -> ActixResult<HttpResponse> {
        let mut conn = pool.get().map_err(|e| AppError::DatabaseConnection(e))?;

        let response = self.fido_service
            .finish_authentication(
                &mut conn,
                &req.credential_id,
                &req.client_data_json,
                &req.authenticator_data,
                &req.signature,
                req.user_handle.as_deref(),
            )
            .await?;

        Ok(HttpResponse::Ok().json(SuccessResponse::new(response)))
    }

    /// List credentials
    pub async fn list_credentials(
        &self,
        pool: web::Data<DbPool>,
        path: web::Path<Uuid>,
    ) -> ActixResult<HttpResponse> {
        let mut conn = pool.get().map_err(|e| AppError::DatabaseConnection(e))?;
        let user_id = path.into_inner();

        let credentials = self.fido_service
            .list_credentials(&mut conn, user_id)
            .await?;

        let response = ListCredentialsResponse {
            credentials,
            total: credentials.len(),
        };

        Ok(HttpResponse::Ok().json(SuccessResponse::new(response)))
    }

    /// Delete credential
    pub async fn delete_credential(
        &self,
        pool: web::Data<DbPool>,
        path: web::Path<(Uuid, String)>,
    ) -> ActixResult<HttpResponse> {
        let mut conn = pool.get().map_err(|e| AppError::DatabaseConnection(e))?;
        let (user_id, credential_id) = path.into_inner();

        self.fido_service
            .delete_credential(&mut conn, &credential_id, user_id)
            .await?;

        let response = DeleteCredentialResponse {
            success: true,
            message: "Credential deleted successfully".to_string(),
        };

        Ok(HttpResponse::Ok().json(SuccessResponse::new(response)))
    }
}

/// Configure FIDO routes
pub fn configure(cfg: &mut web::ServiceConfig, controller: web::Data<FidoController>) {
    cfg.service(
        web::scope("/api/v1")
            .route("/register/start", web::post().to({
                let controller = controller.clone();
                move |pool, req| controller.start_registration(pool, req)
            }))
            .route("/register/finish", web::post().to({
                let controller = controller.clone();
                move |pool, req| controller.finish_registration(pool, req)
            }))
            .route("/authenticate/start", web::post().to({
                let controller = controller.clone();
                move |pool, req| controller.start_authentication(pool, req)
            }))
            .route("/authenticate/finish", web::post().to({
                let controller = controller.clone();
                move |pool, req| controller.finish_authentication(pool, req)
            }))
            .route("/credentials/{user_id}", web::get().to({
                let controller = controller.clone();
                move |pool, path| controller.list_credentials(pool, path)
            }))
            .route("/credentials/{user_id}/{credential_id}", web::delete().to({
                let controller = controller.clone();
                move |pool, path| controller.delete_credential(pool, path)
            })),
    );
}