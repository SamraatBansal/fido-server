//! Authentication middleware

use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpMessage,
};
use futures_util::future::LocalBoxFuture;
use std::future::{ready, Ready};
use uuid::Uuid;

/// Authenticated user extracted from request
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub user_id: Uuid,
    pub username: String,
}

/// Authentication middleware
pub struct AuthMiddleware;

impl<S, B> Transform<S, ServiceRequest> for AuthMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = AuthMiddlewareService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthMiddlewareService { service }))
    }
}

pub struct AuthMiddlewareService<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for AuthMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        // Extract Authorization header
        let auth_header = req.headers().get("Authorization");
        
        if let Some(auth_header) = auth_header {
            if let Ok(auth_str) = auth_header.to_str() {
                if let Some(token) = auth_str.strip_prefix("Bearer ") {
                    // TODO: Validate JWT token and extract user info
                    // For now, we'll skip actual validation
                    if let Ok(user_id) = extract_user_from_token(token) {
                        let user = AuthenticatedUser {
                            user_id,
                            username: "user".to_string(), // TODO: Extract from token
                        };
                        
                        // Store user in request extensions
                        req.extensions_mut().insert(user);
                    }
                }
            }
        }

        let fut = self.service.call(req);
        Box::pin(async move {
            let res = fut.await?;
            Ok(res)
        })
    }
}

/// Extract user from JWT token (placeholder implementation)
fn extract_user_from_token(token: &str) -> Result<Uuid, Error> {
    // TODO: Implement proper JWT validation
    // For now, this is a placeholder that would validate the token
    // and extract the user ID from the claims
    
    // This is just for demonstration - in production, you would:
    // 1. Validate the JWT signature
    // 2. Check token expiration
    // 3. Extract user claims
    // 4. Validate the user exists in the database
    
    // For now, return a dummy UUID if token is "valid"
    if token.len() > 10 {
        Uuid::parse_str("00000000-0000-0000-0000-000000000000")
            .map_err(|_| actix_web::error::ErrorInternalServerError("Invalid user ID"))
    } else {
        Err(actix_web::error::ErrorUnauthorized("Invalid token"))
    }
}

/// Extractor for AuthenticatedUser
impl actix_web::FromRequest for AuthenticatedUser {
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &actix_web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        if let Some(user) = req.extensions().get::<AuthenticatedUser>() {
            ready(Ok(user.clone()))
        } else {
            ready(Err(actix_web::error::ErrorUnauthorized("Authentication required")))
        }
    }
}