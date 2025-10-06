//! Rate limiting middleware

use actix_web::{dev::ServiceRequest, dev::ServiceResponse, Error, HttpMessage};
use actix_web::dev::{forward_ready, Transform};
use futures::future::{ready, LocalBoxFuture};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::task::{Context, Poll};

/// Rate limiter state
#[derive(Debug, Clone)]
struct RateLimiterState {
    /// Request counts per IP
    counts: Arc<Mutex<HashMap<String, (u32, Instant)>>>,
    /// Maximum requests per minute
    max_requests: u32,
}

impl RateLimiterState {
    fn new(max_requests: u32) -> Self {
        Self {
            counts: Arc::new(Mutex::new(HashMap::new())),
            max_requests,
        }
    }

    fn check_rate_limit(&self, ip: &str) -> bool {
        let mut counts = self.counts.lock().unwrap();
        let now = Instant::now();

        match counts.get_mut(ip) {
            Some((count, last_reset)) => {
                if now.duration_since(*last_reset) >= Duration::from_secs(60) {
                    *count = 1;
                    *last_reset = now;
                    true
                } else if *count < self.max_requests {
                    *count += 1;
                    true
                } else {
                    false
                }
            }
            None => {
                counts.insert(ip.to_string(), (1, now));
                true
            }
        }
    }
}

/// Rate limiting middleware
pub struct RateLimitMiddleware {
    state: RateLimiterState,
}

impl RateLimitMiddleware {
    pub fn new(max_requests_per_minute: u32) -> Self {
        Self {
            state: RateLimiterState::new(max_requests_per_minute),
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for RateLimitMiddleware
where
    S: actix_web::dev::Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
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
            state: self.state.clone(),
        }))
    }
}

pub struct RateLimitMiddlewareService<S> {
    service: S,
    state: RateLimiterState,
}

impl<S, B> actix_web::dev::Service<ServiceRequest> for RateLimitMiddlewareService<S>
where
    S: actix_web::dev::Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let ip = req
            .connection_info()
            .peer_addr()
            .map(|addr| addr.ip().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        if !self.state.check_rate_limit(&ip) {
            let response = actix_web::HttpResponse::TooManyRequests().json(serde_json::json!({
                "error": "rate_limit_exceeded",
                "message": "Rate limit exceeded. Please try again later."
            }));
            let (req, _) = req.into_parts();
            let response = req.into_response(response);
            return Box::pin(async { Ok(response) });
        }

        let fut = self.service.call(req);
        Box::pin(async move {
            let res = fut.await?;
            Ok(res)
        })
    }
}