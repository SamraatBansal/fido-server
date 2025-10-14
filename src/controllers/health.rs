//! Health check controller

use actix_web::{HttpResponse, Result};
use crate::models::ServerResponse;

/// Health check endpoint
pub async fn health_check() -> Result<HttpResponse> {
    let response = ServerResponse::success(serde_json::json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now().to_rfc3339()
    }));
    
    Ok(HttpResponse::Ok().json(response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test;

    #[actix_rt::test]
    async fn test_health_check() {
        let result = health_check().await;
        assert!(result.is_ok());
        
        let response = result.unwrap();
        assert_eq!(response.status(), actix_web::http::StatusCode::OK);
    }
}