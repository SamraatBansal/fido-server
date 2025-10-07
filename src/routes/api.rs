use actix_web::{web, Scope};

use crate::controllers::management::ManagementController;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api")
            .route("/health", web::get().to(ManagementController::health_check))
            .service(
                web::scope("/users/{user_id}")
                    .route("/credentials", web::get().to(ManagementController::list_credentials))
                    .route("/credentials/{credential_id}", web::delete().to(ManagementController::delete_credential))
            )
    );
}