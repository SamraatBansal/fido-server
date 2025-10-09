//! Security middleware

use actix_web::{dev::ServiceRequest, Error, Result};
use actix_web_httpauth::middleware::HttpAuthentication;

/// Authentication middleware
pub async fn auth_validator(
    req: ServiceRequest,
    _credentials: actix_web_httpauth::extractors::bearer::BearerAuth,
) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    // TODO: Implement proper authentication validation
    Ok(req)
}

/// Create authentication middleware
pub fn auth_middleware() -> HttpAuthentication<actix_web_httpauth::extractors::bearer::BearerAuth, impl Fn(ServiceRequest, actix_web_httpauth::extractors::bearer::BearerAuth) -> _> {
    HttpAuthentication::bearer(auth_validator)
}