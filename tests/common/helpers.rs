//! Test helper functions and utilities

use crate::common::{ServerResponse, TestConfig, TestResult};
use actix_web::{dev::ServiceResponse, http::StatusCode, test, App};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{de::DeserializeOwned, Serialize};
use std::collections::HashMap;

/// Helper to make HTTP requests and parse responses
pub async fn make_request<T: Serialize, R: DeserializeOwned>(
    app: &actix_web::App<
        impl actix_web::dev::ServiceFactory<
            actix_web::dev::ServiceRequest,
            Config = (),
            Response = ServiceResponse,
            Error = actix_web::Error,
            InitError = (),
        >,
    >,
    method: actix_web::http::Method,
    path: &str,
    body: Option<T>,
    headers: Option<HashMap<String, String>>,
) -> TestResult<(StatusCode, R)> {
    let mut req = test::TestRequest::default().method(method).uri(path);

    // Add headers if provided
    if let Some(hdrs) = headers {
        for (key, value) in hdrs {
            req = req.insert_header((key.clone(), value));
        }
    }

    // Add body if provided
    let req = if let Some(b) = body {
        req.set_json(&b)
    } else {
        req
    };

    let resp = test::call_service(app, req.to_request()).await;
    let status = resp.status();

    let body = test::read_body(resp).await;
    let response: R = serde_json::from_slice(&body)?;

    Ok((status, response))
}

/// Helper to make simple requests and check for success/failure
pub async fn check_endpoint_success<T: Serialize>(
    app: &actix_web::App<
        impl actix_web::dev::ServiceFactory<
            actix_web::dev::ServiceRequest,
            Config = (),
            Response = ServiceResponse,
            Error = actix_web::Error,
            InitError = (),
        >,
    >,
    method: actix_web::http::Method,
    path: &str,
    body: Option<T>,
) -> TestResult<bool> {
    let (status, response: ServerResponse) = make_request(app, method, path, body, None).await?;
    Ok(status.is_success() && response.is_success())
}

/// Helper to make requests and expect failure
pub async fn check_endpoint_failure<T: Serialize>(
    app: &actix_web::App<
        impl actix_web::dev::ServiceFactory<
            actix_web::dev::ServiceRequest,
            Config = (),
            Response = ServiceResponse,
            Error = actix_web::Error,
            InitError = (),
        >,
    >,
    method: actix_web::http::Method,
    path: &str,
    body: Option<T>,
    expected_status: StatusCode,
) -> TestResult<(StatusCode, ServerResponse)> {
    let (status, response: ServerResponse) = make_request(app, method, path, body, None).await?;
    Ok((status, response))
}

/// Validate base64url string
pub fn is_valid_base64url(s: &str) -> bool {
    URL_SAFE_NO_PAD.decode(s).is_ok()
}

/// Generate random base64url string of specified length
pub fn generate_random_base64url(length: usize) -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..length).map(|_| rng.gen()).collect();
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Create test app with basic configuration
pub fn create_test_app() -> App<
    impl actix_web::dev::ServiceFactory<
        actix_web::dev::ServiceRequest,
        Config = (),
        Response = ServiceResponse,
        Error = actix_web::Error,
        InitError = (),
    >,
> {
    use actix_web::web;
    
    // This will be replaced with actual app configuration
    // when the main application is implemented
    App::new().configure(|cfg| {
        cfg.service(
            web::resource("/attestation/options")
                .route(web::post().to(crate::routes::attestation_options)),
        );
        cfg.service(
            web::resource("/attestation/result")
                .route(web::post().to(crate::routes::attestation_result)),
        );
        cfg.service(
            web::resource("/assertion/options")
                .route(web::post().to(crate::routes::assertion_options)),
        );
        cfg.service(
            web::resource("/assertion/result")
                .route(web::post().to(crate::routes::assertion_result)),
        );
    })
}

/// Assert JSON structure contains required fields
pub fn assert_json_structure(json: &serde_json::Value, required_fields: &[&str]) -> TestResult<()> {
    let obj = json.as_object().ok_or("Response is not a JSON object")?;
    
    for field in required_fields {
        if !obj.contains_key(*field) {
            return Err(format!("Missing required field: {}", field).into());
        }
    }
    
    Ok(())
}

/// Compare two JSON objects ignoring specified fields
pub fn assert_json_equals_ignoring(
    actual: &serde_json::Value,
    expected: &serde_json::Value,
    ignore_fields: &[&str],
) -> TestResult<()> {
    let mut actual_obj = actual.clone();
    let mut expected_obj = expected.clone();
    
    // Remove ignored fields from both objects
    if let Some(obj) = actual_obj.as_object_mut() {
        for field in ignore_fields {
            obj.remove(*field);
        }
    }
    
    if let Some(obj) = expected_obj.as_object_mut() {
        for field in ignore_fields {
            obj.remove(*field);
        }
    }
    
    if actual_obj != expected_obj {
        return Err("JSON objects do not match".into());
    }
    
    Ok(())
}

/// Measure execution time of a function
pub async fn measure_time<F, Fut, T>(f: F) -> (T, std::time::Duration)
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = T>,
{
    let start = std::time::Instant::now();
    let result = f().await;
    let duration = start.elapsed();
    (result, duration)
}

/// Retry mechanism for flaky tests
pub async fn retry_async<F, Fut, T, E>(
    mut f: F,
    max_attempts: u32,
    delay: std::time::Duration,
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
{
    let mut last_error = None;
    
    for attempt in 1..=max_attempts {
        match f().await {
            Ok(result) => return Ok(result),
            Err(e) => {
                last_error = Some(e);
                if attempt < max_attempts {
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }
    
    Err(last_error.unwrap())
}

/// Generate test user data
pub fn generate_test_user(username: &str) -> crate::common::fixtures::ServerPublicKeyCredentialUserEntity {
    crate::common::fixtures::ServerPublicKeyCredentialUserEntity {
        id: crate::common::fixtures::valid_user_id(),
        name: username.to_string(),
        display_name: format!("Test User - {}", username),
    }
}

/// Generate test RP data
pub fn generate_test_rp() -> crate::common::fixtures::PublicKeyCredentialRpEntity {
    crate::common::fixtures::PublicKeyCredentialRpEntity {
        name: "Test RP".to_string(),
        id: Some("localhost".to_string()),
    }
}