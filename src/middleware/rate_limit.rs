use actix_web::{dev::ServiceRequest, error, Error};
use actix_web::dev::{forward_ready, Service, ServiceResponse, Transform};
use governor::{clock::DefaultClock, state::keyed::HashMapKeyedStateStore, Quota, RateLimiter};
use std::future::{ready, Ready};
use std::num::NonZeroU32;
use std::sync::Arc;

pub struct RateLimitMiddleware {
    limiter: Arc<RateLimiter<String, HashMapKeyedStateStore<String>, DefaultClock>>,
}

impl RateLimitMiddleware {
    pub fn new(requests_per_minute: u32) -> Self {
        let quota = Quota::per_minute(NonZeroU32::new(requests_per_minute).unwrap())
            .allow_burst(NonZeroU32::new(requests_per_minute * 2).unwrap());
        
        let limiter = Arc::new(RateLimiter::direct(quota));
        
        Self { limiter }
    }
}

impl<S, B> Transform<S, ServiceRequest> for RateLimitMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = RateLimitService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RateLimitService {
            service,
            limiter: self.limiter.clone(),
        }))
    }
}

pub struct RateLimitService<S> {
    service: S,
    limiter: Arc<RateLimiter<String, HashMapKeyedStateStore<String>, DefaultClock>>,
}

impl<S, B> Service<ServiceRequest> for RateLimitService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let limiter = self.limiter.clone();
        
        // Extract IP address for rate limiting
        let key = req
            .connection_info()
            .peer_addr()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|| "unknown".to_string());

        // Check rate limit
        match limiter.check_key(&key) {
            Ok(_) => {
                let fut = self.service.call(req);
                Box::pin(async move {
                    let res = fut.await?;
                    Ok(res)
                })
            }
            Err(_) => {
                Box::pin(async {
                    Err(error::ErrorTooManyRequests("Rate limit exceeded"))
                })
            }
        }
    }
}