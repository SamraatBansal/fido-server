/// FIDO2 Conformance Test Suite
/// 
/// This module contains comprehensive test cases that replicate the FIDO Alliance
/// conformance testing tools requirements. The tests are organized according to
/// the official FIDO2 Server Conformance Test API specification.
/// 
/// Test Categories:
/// - MakeCredential Request Tests
/// - MakeCredential Response Tests  
/// - GetAssertion Request Tests
/// - GetAssertion Response Tests
/// - Metadata Service Tests

pub mod attestation_tests;
pub mod assertion_tests;
pub mod credential_creation_tests;
pub mod credential_request_tests;
pub mod metadata_service_tests;
pub mod test_data;
pub mod test_utils;

use actix_web::{test, web, App};
use fido_server::routes::api::configure_routes;
use fido_server::config::settings::Settings;

/// Initialize test application with FIDO server configuration
pub fn init_test_app() -> actix_web::test::TestServer {
    let settings = Settings::new().expect("Failed to load settings");
    
    test::start(|| {
        App::new()
            .app_data(web::Data::new(settings))
            .configure(configure_routes)
    })
}

/// Common test result type for conformance tests
pub type ConformanceTestResult = Result<(), Box<dyn std::error::Error>>;

/// Test status enum matching FIDO Alliance conformance tools
#[derive(Debug, Clone, PartialEq)]
pub enum TestStatus {
    Ok,
    Failed(String),
}

/// Conformance test metadata
#[derive(Debug, Clone)]
pub struct ConformanceTest {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: TestCategory,
    pub test_type: TestType,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TestCategory {
    MakeCredentialRequest,
    MakeCredentialResponse,
    GetAssertionRequest,
    GetAssertionResponse,
    MetadataService,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TestType {
    Positive, // P-n tests - expect success
    Negative, // F-n tests - expect failure
}
