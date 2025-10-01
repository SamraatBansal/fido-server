/// FIDO2 Conformance Test Utilities
/// 
/// This module provides utility functions for FIDO2 conformance testing,
/// including test runners, result reporting, and common validation helpers.

use super::*;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use serde_json::Value;

/// Test runner configuration
#[derive(Debug, Clone)]
pub struct TestRunnerConfig {
    pub verbose: bool,
    pub timeout: Duration,
    pub parallel: bool,
    pub filter: Option<String>,
}

impl Default for TestRunnerConfig {
    fn default() -> Self {
        Self {
            verbose: true,
            timeout: Duration::from_secs(30),
            parallel: false,
            filter: None,
        }
    }
}

/// Test result aggregator
#[derive(Debug, Clone)]
pub struct TestResults {
    pub total_tests: usize,
    pub passed_tests: usize,
    pub failed_tests: usize,
    pub skipped_tests: usize,
    pub test_details: Vec<TestDetail>,
    pub execution_time: Duration,
}

#[derive(Debug, Clone)]
pub struct TestDetail {
    pub test_id: String,
    pub test_name: String,
    pub category: TestCategory,
    pub status: TestResultStatus,
    pub execution_time: Duration,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TestResultStatus {
    Passed,
    Failed,
    Skipped,
}

/// Comprehensive test runner for all FIDO2 conformance tests
pub async fn run_all_conformance_tests(config: TestRunnerConfig) -> TestResults {
    let start_time = Instant::now();
    let mut results = TestResults {
        total_tests: 0,
        passed_tests: 0,
        failed_tests: 0,
        skipped_tests: 0,
        test_details: Vec::new(),
        execution_time: Duration::from_secs(0),
    };

    println!("🚀 Starting FIDO2 Conformance Test Suite");
    println!("Configuration: {:?}", config);
    println!("{}", "=".repeat(80));

    // Run test categories in sequence
    let test_categories = vec![
        ("MakeCredential Request", run_credential_creation_tests),
        ("MakeCredential Response", run_attestation_tests),
        ("GetAssertion Request", run_credential_request_tests),
        ("GetAssertion Response", run_assertion_tests),
        ("Metadata Service", run_metadata_service_tests),
    ];

    for (category_name, test_runner) in test_categories {
        if should_run_category(&config.filter, category_name) {
            println!("\n🧪 Running {}", category_name);
            println!("{}", "-".repeat(50));
            
            let category_start = Instant::now();
            let category_results = test_runner(config.clone()).await;
            let category_duration = category_start.elapsed();
            
            // Aggregate results
            results.total_tests += category_results.total_tests;
            results.passed_tests += category_results.passed_tests;
            results.failed_tests += category_results.failed_tests;
            results.skipped_tests += category_results.skipped_tests;
            results.test_details.extend(category_results.test_details);
            
            println!("✅ {} completed in {:.2}s", category_name, category_duration.as_secs_f64());
            println!("   Tests: {} passed, {} failed, {} skipped", 
                     category_results.passed_tests, 
                     category_results.failed_tests, 
                     category_results.skipped_tests);
        } else {
            println!("⏭️  Skipping {} (filtered out)", category_name);
        }
    }

    results.execution_time = start_time.elapsed();
    
    println!("\n{}", "=".repeat(80));
    print_test_summary(&results);
    
    results
}

/// Run credential creation tests
async fn run_credential_creation_tests(config: TestRunnerConfig) -> TestResults {
    use crate::conformance::credential_creation_tests::*;
    
    let mut results = TestResults::default();
    let tests = vec![
        ("Server-ServerPublicKeyCredentialCreationOptions-Req-1-Positive", 
         test_server_credential_creation_options_req_1_positive),
        ("Server-ServerPublicKeyCredentialCreationOptions-Req-1-Negative", 
         test_server_credential_creation_options_req_1_negative),
        ("Challenge-Generation-Requirements", 
         test_challenge_generation_requirements),
        ("User-ID-Generation", 
         test_user_id_generation),
        ("PubKeyCredParams-Algorithms", 
         test_pubkey_cred_params_algorithms),
    ];
    
    run_test_group(&mut results, tests, TestCategory::MakeCredentialRequest, config).await;
    results
}

/// Run attestation tests
async fn run_attestation_tests(config: TestRunnerConfig) -> TestResults {
    use crate::conformance::attestation_tests::*;
    
    let mut results = TestResults::default();
    let tests = vec![
        ("Server-ServerAuthenticatorAttestationResponse-Resp-1", 
         test_server_attestation_response_structure),
        ("Server-ServerAuthenticatorAttestationResponse-Resp-2", 
         test_server_client_data_processing),
        ("Server-ServerAuthenticatorAttestationResponse-Resp-3", 
         test_server_attestation_object_processing),
        ("Server-ServerAuthenticatorAttestationResponse-Resp-4", 
         test_server_algorithm_support),
        ("Server-ServerAuthenticatorAttestationResponse-Resp-5", 
         test_server_packed_full_attestation),
        ("Server-ServerAuthenticatorAttestationResponse-Resp-6", 
         test_server_packed_self_attestation),
        ("Server-ServerAuthenticatorAttestationResponse-Resp-7", 
         test_server_none_attestation),
        ("Server-ServerAuthenticatorAttestationResponse-Resp-8", 
         test_server_fido_u2f_attestation),
        ("Server-ServerAuthenticatorAttestationResponse-Resp-9", 
         test_server_tpm_attestation),
        ("Server-ServerAuthenticatorAttestationResponse-Resp-A", 
         test_server_android_key_attestation),
        ("Server-ServerAuthenticatorAttestationResponse-Resp-B", 
         test_server_android_safetynet_attestation),
        ("Attestation-Response-Missing-Fields", 
         test_attestation_response_missing_fields),
    ];
    
    run_test_group(&mut results, tests, TestCategory::MakeCredentialResponse, config).await;
    results
}

/// Run credential request tests
async fn run_credential_request_tests(config: TestRunnerConfig) -> TestResults {
    use crate::conformance::credential_request_tests::*;
    
    let mut results = TestResults::default();
    let tests = vec![
        ("Server-ServerPublicKeyCredentialGetOptionsResponse-Req-1-Positive", 
         test_server_assertion_options_req_1_positive),
        ("Server-ServerPublicKeyCredentialGetOptionsResponse-Req-1-Negative", 
         test_server_assertion_options_req_1_negative),
        ("Assertion-Challenge-Generation", 
         test_assertion_challenge_generation),
        ("User-Verification-Requirements", 
         test_user_verification_requirements),
        ("Allow-Credentials-Filtering", 
         test_allow_credentials_filtering),
        ("RP-ID-Validation", 
         test_rp_id_validation),
        ("Timeout-Parameter", 
         test_timeout_parameter),
        ("Extensions-Parameter", 
         test_extensions_parameter),
    ];
    
    run_test_group(&mut results, tests, TestCategory::GetAssertionRequest, config).await;
    results
}

/// Run assertion tests
async fn run_assertion_tests(config: TestRunnerConfig) -> TestResults {
    use crate::conformance::assertion_tests::*;
    
    let mut results = TestResults::default();
    let tests = vec![
        ("Server-ServerAuthenticatorAssertionResponse-Resp-1", 
         test_server_assertion_response_structure),
        ("Server-ServerAuthenticatorAssertionResponse-Resp-2", 
         test_server_assertion_client_data_processing),
        ("Server-ServerAuthenticatorAssertionResponse-Resp-3", 
         test_server_authenticator_data_processing),
        ("Signature-Verification", 
         test_signature_verification),
        ("User-Handle-Processing", 
         test_user_handle_processing),
        ("Credential-ID-Validation", 
         test_credential_id_validation),
        ("Assertion-Response-Missing-Fields", 
         test_assertion_response_missing_fields),
        ("Counter-Validation", 
         test_counter_validation),
    ];
    
    run_test_group(&mut results, tests, TestCategory::GetAssertionResponse, config).await;
    results
}

/// Run metadata service tests
async fn run_metadata_service_tests(config: TestRunnerConfig) -> TestResults {
    use crate::conformance::metadata_service_tests::*;
    
    let mut results = TestResults::default();
    let tests = vec![
        ("MDS3-Endpoint-Integration", 
         test_mds3_endpoint_integration),
        ("Authenticator-Metadata-Validation", 
         test_authenticator_metadata_validation),
        ("Certificate-Chain-Validation", 
         test_certificate_chain_validation),
        ("MDS-Cache-And-Updates", 
         test_mds_cache_and_updates),
        ("Metadata-Statement-Integrity", 
         test_metadata_statement_integrity),
        ("AAGUID-Lookup-Validation", 
         test_aaguid_lookup_validation),
        ("Attestation-Root-Certificate-Validation", 
         test_attestation_root_certificate_validation),
    ];
    
    run_test_group(&mut results, tests, TestCategory::MetadataService, config).await;
    results
}

/// Generic test group runner
async fn run_test_group<F, Fut>(
    results: &mut TestResults,
    tests: Vec<(&str, F)>,
    category: TestCategory,
    config: TestRunnerConfig,
) where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = ConformanceTestResult>,
{
    for (test_name, test_fn) in tests {
        if should_run_test(&config.filter, test_name) {
            let test_start = Instant::now();
            
            if config.verbose {
                println!("  Running {}", test_name);
            }
            
            let test_result = tokio::time::timeout(config.timeout, test_fn()).await;
            let execution_time = test_start.elapsed();
            
            let (status, error_message) = match test_result {
                Ok(Ok(())) => {
                    results.passed_tests += 1;
                    (TestResultStatus::Passed, None)
                },
                Ok(Err(e)) => {
                    results.failed_tests += 1;
                    let error_msg = format!("{:?}", e);
                    if config.verbose {
                        println!("    ❌ FAILED: {}", error_msg);
                    }
                    (TestResultStatus::Failed, Some(error_msg))
                },
                Err(_) => {
                    results.failed_tests += 1;
                    let error_msg = format!("Test timed out after {:?}", config.timeout);
                    if config.verbose {
                        println!("    ⏱️  TIMEOUT: {}", error_msg);
                    }
                    (TestResultStatus::Failed, Some(error_msg))
                }
            };
            
            results.test_details.push(TestDetail {
                test_id: format!("{:?}-{}", category, test_name),
                test_name: test_name.to_string(),
                category: category.clone(),
                status,
                execution_time,
                error_message,
            });
            
            results.total_tests += 1;
            
            if config.verbose && matches!(status, TestResultStatus::Passed) {
                println!("    ✅ PASSED ({:.2}s)", execution_time.as_secs_f64());
            }
        } else {
            results.skipped_tests += 1;
            results.total_tests += 1;
            
            results.test_details.push(TestDetail {
                test_id: format!("{:?}-{}", category, test_name),
                test_name: test_name.to_string(),
                category: category.clone(),
                status: TestResultStatus::Skipped,
                execution_time: Duration::from_secs(0),
                error_message: Some("Filtered out".to_string()),
            });
        }
    }
}

/// Check if a test category should run based on filter
fn should_run_category(filter: &Option<String>, category_name: &str) -> bool {
    match filter {
        Some(f) => category_name.to_lowercase().contains(&f.to_lowercase()),
        None => true,
    }
}

/// Check if a test should run based on filter
fn should_run_test(filter: &Option<String>, test_name: &str) -> bool {
    match filter {
        Some(f) => test_name.to_lowercase().contains(&f.to_lowercase()),
        None => true,
    }
}

/// Print comprehensive test summary
fn print_test_summary(results: &TestResults) {
    println!("📊 Test Summary");
    println!("   Total Tests: {}", results.total_tests);
    println!("   ✅ Passed: {}", results.passed_tests);
    println!("   ❌ Failed: {}", results.failed_tests);
    println!("   ⏭️  Skipped: {}", results.skipped_tests);
    println!("   ⏱️  Execution Time: {:.2}s", results.execution_time.as_secs_f64());
    
    let success_rate = if results.total_tests > 0 {
        (results.passed_tests as f64 / (results.total_tests - results.skipped_tests) as f64) * 100.0
    } else {
        0.0
    };
    println!("   📈 Success Rate: {:.1}%", success_rate);
    
    // Print failed tests details
    if results.failed_tests > 0 {
        println!("\n❌ Failed Tests:");
        for detail in &results.test_details {
            if matches!(detail.status, TestResultStatus::Failed) {
                println!("   - {}: {}", 
                         detail.test_name, 
                         detail.error_message.as_ref().unwrap_or(&"Unknown error".to_string()));
            }
        }
    }
    
    // Print category breakdown
    println!("\n📂 Test Results by Category:");
    let mut category_stats: HashMap<TestCategory, (usize, usize, usize)> = HashMap::new();
    
    for detail in &results.test_details {
        let entry = category_stats.entry(detail.category.clone()).or_insert((0, 0, 0));
        match detail.status {
            TestResultStatus::Passed => entry.0 += 1,
            TestResultStatus::Failed => entry.1 += 1,
            TestResultStatus::Skipped => entry.2 += 1,
        }
    }
    
    for (category, (passed, failed, skipped)) in category_stats {
        let total = passed + failed + skipped;
        let rate = if total > 0 { (passed as f64 / (total - skipped) as f64) * 100.0 } else { 0.0 };
        println!("   {:?}: {} passed, {} failed, {} skipped ({:.1}%)", 
                 category, passed, failed, skipped, rate);
    }
}

/// Generate JUnit XML report for CI/CD integration
pub fn generate_junit_report(results: &TestResults) -> String {
    let mut xml = String::new();
    xml.push_str(r#"<?xml version="1.0" encoding="UTF-8"?>"#);
    xml.push('\n');
    xml.push_str(&format!(
        r#"<testsuite name="FIDO2 Conformance Tests" tests="{}" failures="{}" skipped="{}" time="{:.3}">"#,
        results.total_tests,
        results.failed_tests,
        results.skipped_tests,
        results.execution_time.as_secs_f64()
    ));
    xml.push('\n');
    
    for detail in &results.test_details {
        xml.push_str(&format!(
            r#"  <testcase classname="{:?}" name="{}" time="{:.3}">"#,
            detail.category,
            detail.test_name,
            detail.execution_time.as_secs_f64()
        ));
        xml.push('\n');
        
        match detail.status {
            TestResultStatus::Failed => {
                xml.push_str(&format!(
                    r#"    <failure message="{}">{}</failure>"#,
                    detail.error_message.as_ref().unwrap_or(&"Unknown error".to_string()),
                    detail.error_message.as_ref().unwrap_or(&"Unknown error".to_string())
                ));
                xml.push('\n');
            },
            TestResultStatus::Skipped => {
                xml.push_str(r#"    <skipped/>"#);
                xml.push('\n');
            },
            _ => {}
        }
        
        xml.push_str("  </testcase>");
        xml.push('\n');
    }
    
    xml.push_str("</testsuite>");
    xml.push('\n');
    
    xml
}

/// Generate JSON report for programmatic consumption
pub fn generate_json_report(results: &TestResults) -> String {
    serde_json::to_string_pretty(&serde_json::json!({
        "summary": {
            "total_tests": results.total_tests,
            "passed_tests": results.passed_tests,
            "failed_tests": results.failed_tests,
            "skipped_tests": results.skipped_tests,
            "execution_time_seconds": results.execution_time.as_secs_f64(),
            "success_rate": if results.total_tests > 0 {
                (results.passed_tests as f64 / (results.total_tests - results.skipped_tests) as f64) * 100.0
            } else {
                0.0
            }
        },
        "test_details": results.test_details.iter().map(|detail| {
            serde_json::json!({
                "test_id": detail.test_id,
                "test_name": detail.test_name,
                "category": format!("{:?}", detail.category),
                "status": format!("{:?}", detail.status),
                "execution_time_seconds": detail.execution_time.as_secs_f64(),
                "error_message": detail.error_message
            })
        }).collect::<Vec<_>>()
    })).unwrap_or_else(|_| "{}".to_string())
}

/// Validation helper for CBOR data
pub fn validate_cbor_structure(data: &[u8]) -> Result<Value, String> {
    // This would use a CBOR library in a real implementation
    // For now, we'll do basic validation
    if data.is_empty() {
        return Err("CBOR data is empty".to_string());
    }
    
    if data.len() < 2 {
        return Err("CBOR data too short".to_string());
    }
    
    // Basic CBOR header validation
    let major_type = (data[0] >> 5) & 0x07;
    match major_type {
        0..=7 => Ok(serde_json::json!({"valid": true, "major_type": major_type})),
        _ => Err("Invalid CBOR major type".to_string()),
    }
}

/// Validation helper for WebAuthn client data
pub fn validate_client_data_json(client_data_b64: &str) -> Result<Value, String> {
    use base64::prelude::*;
    
    // Decode base64
    let decoded = BASE64_URL_SAFE_NO_PAD.decode(client_data_b64)
        .map_err(|_| "Invalid base64url encoding")?;
    
    // Parse as UTF-8
    let client_data_str = String::from_utf8(decoded)
        .map_err(|_| "Invalid UTF-8 encoding")?;
    
    // Parse as JSON
    let client_data: Value = serde_json::from_str(&client_data_str)
        .map_err(|_| "Invalid JSON format")?;
    
    // Validate required fields
    let required_fields = ["type", "challenge", "origin"];
    for field in &required_fields {
        if client_data.get(field).is_none() {
            return Err(format!("Missing required field: {}", field));
        }
    }
    
    // Validate type field
    let type_field = client_data["type"].as_str()
        .ok_or("Type field must be a string")?;
    
    if !["webauthn.create", "webauthn.get"].contains(&type_field) {
        return Err(format!("Invalid type field: {}", type_field));
    }
    
    Ok(client_data)
}

/// Performance measurement utilities
pub struct PerformanceMetrics {
    pub test_times: HashMap<String, Duration>,
    pub memory_usage: HashMap<String, usize>,
}

impl PerformanceMetrics {
    pub fn new() -> Self {
        Self {
            test_times: HashMap::new(),
            memory_usage: HashMap::new(),
        }
    }
    
    pub fn record_test_time(&mut self, test_name: String, duration: Duration) {
        self.test_times.insert(test_name, duration);
    }
    
    pub fn get_average_test_time(&self) -> Duration {
        if self.test_times.is_empty() {
            return Duration::from_secs(0);
        }
        
        let total: Duration = self.test_times.values().sum();
        total / self.test_times.len() as u32
    }
    
    pub fn get_slowest_tests(&self, count: usize) -> Vec<(String, Duration)> {
        let mut tests: Vec<_> = self.test_times.iter()
            .map(|(name, duration)| (name.clone(), *duration))
            .collect();
        
        tests.sort_by(|a, b| b.1.cmp(&a.1));
        tests.truncate(count);
        tests
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_utils_validation() {
        // Test client data validation
        let valid_client_data = "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoidGVzdCIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCJ9";
        assert!(validate_client_data_json(valid_client_data).is_ok());
        
        let invalid_client_data = "invalid-base64";
        assert!(validate_client_data_json(invalid_client_data).is_err());
        
        // Test CBOR validation
        let valid_cbor = vec![0xa1, 0x61, 0x41, 0x01]; // Simple CBOR map
        assert!(validate_cbor_structure(&valid_cbor).is_ok());
        
        let invalid_cbor = vec![];
        assert!(validate_cbor_structure(&invalid_cbor).is_err());
        
        println!("✅ Test utilities validation passed!");
    }
}
