//! Rate limiting middleware

use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    error::ErrorTooManyRequests,
    Error, HttpMessage,
};
use futures_util::future::LocalBoxFuture;
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use std::future::ready;

/// Rate limiter
#[derive(Debug, Clone)]
pub struct RateLimiter {
    requests_per_minute: u32,
    clients: Arc<Mutex<HashMap<IpAddr, Vec<Instant>>>>,
}

impl RateLimiter {
    pub fn new(requests_per_minute: u32) -> Self {
        Self {
            requests_per_minute,
            clients: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn is_allowed(&self, ip: IpAddr) -> bool {
        let mut clients = self.clients.lock().unwrap();
        let now = Instant::now();
        let one_minute_ago = now - Duration::from_secs(60);

        let requests = clients.entry(ip).or_insert_with(Vec::new);
        
        // Remove old requests
        requests.retain(|&timestamp| timestamp > one_minute_ago);
        
        // Check if under limit
        if requests.len() < self.requests_per_minute as usize {
            requests.push(now);
            true
        } else {
            false
        }
    }

    pub fn cleanup_expired_entries(&self) {
        let mut clients = self.clients.lock().unwrap();
        let one_minute_ago = Instant::now() - Duration::from_secs(60);
        
        clients.retain(|_, requests| {
            requests.retain(|&timestamp| timestamp > one_minute_ago);
            !requests.is_empty()
        });
    }
}

/// Rate limiting middleware
pub struct RateLimitMiddleware {
    rate_limiter: Arc<RateLimiter>,
}

impl RateLimitMiddleware {
    pub fn new(requests_per_minute: u32) -> Self {
        Self {
            rate_limiter: Arc::new(RateLimiter::new(requests_per_minute)),
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for RateLimitMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static + Clone,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = RateLimitMiddlewareService<S>;
    type InitError = ();
    type Future = ready::Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RateLimitMiddlewareService {
            service,
            rate_limiter: self.rate_limiter.clone(),
        }))
    }
}

pub struct RateLimitMiddlewareService<S> {
    service: S,
    rate_limiter: Arc<RateLimiter>,
}

impl<S, B> Service<ServiceRequest> for RateLimitMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static + Clone,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = self.service.clone();
        let rate_limiter = self.rate_limiter.clone();
        
        Box::pin(async move {
            // Get client IP
            let ip = req
                .connection_info()
                .peer_addr()
                .and_then(|addr| addr.parse::<IpAddr>().ok())
                .unwrap_or_else(|| "127.0.0.1".parse().unwrap());

            // Check rate limit
            if !rate_limiter.is_allowed(ip) {
                return Err(ErrorTooManyRequests("Rate limit exceeded".to_string()));
            }

            // Periodic cleanup (run occasionally)
            if rand::random::<f32>() < 0.01 { // 1% chance
                rate_limiter.cleanup_expired_entries();
            }

            service.call(req).await
        })
    }
}