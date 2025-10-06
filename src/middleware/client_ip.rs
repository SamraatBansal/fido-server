//! Client IP extraction middleware

use actix_web::{
    dev::{Payload, ServiceRequest, ServiceResponse, Transform},
    Error, FromRequest, HttpRequest,
};
use futures_util::future::{ok, Ready};
use std::net::IpAddr;
use std::sync::Arc;

/// Client IP extractor
pub struct ClientIp(pub IpAddr);

impl FromRequest for ClientIp {
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        let ip = get_client_ip(req);
        ok(ClientIp(ip))
    }
}

/// Get client IP from request
fn get_client_ip(req: &HttpRequest) -> IpAddr {
    // Try to get IP from X-Forwarded-For header first
    if let Some(forwarded) = req.headers().get("x-forwarded-for") {
        if let Ok(forwarded_str) = forwarded.to_str() {
            // X-Forwarded-For can contain multiple IPs, take the first one
            if let Some(first_ip) = forwarded_str.split(',').next() {
                if let Ok(ip) = first_ip.trim().parse() {
                    return ip;
                }
            }
        }
    }

    // Try X-Real-IP header
    if let Some(real_ip) = req.headers().get("x-real-ip") {
        if let Ok(real_ip_str) = real_ip.to_str() {
            if let Ok(ip) = real_ip_str.parse() {
                return ip;
            }
        }
    }

    // Fall back to connection info
    req.connection_info()
        .realip_remote_addr()
        .and_then(|addr| addr.parse().ok())
        .unwrap_or_else(|| "127.0.0.1".parse().unwrap())
}

/// Middleware to add client IP to request extensions
pub struct ClientIpMiddleware;

impl<S, B> Transform<S, ServiceRequest> for ClientIpMiddleware
where
    S: actix_web::dev::Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = ClientIpMiddlewareService<S>;
    type InitError = ();
    type Future = futures_util::future::Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        futures_util::future::ready(Ok(ClientIpMiddlewareService { service }))
    }
}

pub struct ClientIpMiddlewareService<S> {
    service: S,
}

impl<S, B> actix_web::dev::Service<ServiceRequest> for ClientIpMiddlewareService<S>
where
    S: actix_web::dev::Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = futures_util::future::LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    actix_web::dev::forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let ip = get_client_ip(&req);
        req.extensions_mut().insert(ip);

        let fut = self.service.call(req);
        Box::pin(async move {
            let res = fut.await?;
            Ok(res)
        })
    }
}