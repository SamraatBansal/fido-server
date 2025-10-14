//! Health check controller

use actix_web::{HttpResponse, Result as ActixResult};
use serde_json::json;

use crate::AppError;

/// Health check endpoint
pub async fn health_check() -> ActixResult<HttpResponse, AppError> {
    Ok(HttpResponse::Ok().json(json!({
        "status": "ok",
        "service": "fido-server",
        "version": env!("CARGO_PKG_VERSION")
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[actix_web::test]
    async fn test_health_check() {
        let result = health_check().await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(response.status(), 200);
    }
}