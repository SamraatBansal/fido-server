# FIDO2 Conformance Test Suite

A comprehensive test suite that replicates the FIDO Alliance conformance testing tools for FIDO2 server implementations. This test suite covers all required test cases from the official FIDO2 Server Conformance Test API specification.

## Overview

This test suite implements the same test cases used by the FIDO Alliance's official conformance testing tools, enabling developers to:

- **Validate FIDO2 server implementations** against official requirements
- **Run tests locally** during development without requiring official FIDO Alliance tools access
- **Integrate conformance testing** into CI/CD pipelines
- **Debug and troubleshoot** FIDO2 server issues with detailed test output

## Test Coverage

### 🔐 MakeCredential Request Tests
**Test ID**: `Server-ServerPublicKeyCredentialCreationOptions-Req-1`

- ✅ Valid credential creation options processing
- ✅ Invalid request rejection with proper error messages
- ✅ Challenge generation requirements (16-64 bytes, base64url)
- ✅ User ID generation and uniqueness
- ✅ Algorithm support validation (ES256, RS256, etc.)

### 🔐 MakeCredential Response Tests
**Test IDs**: `Server-ServerAuthenticatorAttestationResponse-Resp-1` through `Resp-B`

- ✅ **Resp-1**: ServerAuthenticatorAttestationResponse structure validation
- ✅ **Resp-2**: CollectClientData processing and validation
- ✅ **Resp-3**: AttestationObject structure and format validation
- ✅ **Resp-4**: Authentication algorithm support verification
- ✅ **Resp-5**: "packed" FULL attestation format support
- ✅ **Resp-6**: "packed" SELF(SURROGATE) attestation format support
- ✅ **Resp-7**: "none" attestation format support
- ✅ **Resp-8**: "fido-u2f" attestation format support
- ✅ **Resp-9**: "tpm" attestation format support
- ✅ **Resp-A**: "android-key" attestation format support
- ✅ **Resp-B**: "android-safetynet" attestation format support

### 🔓 GetAssertion Request Tests
**Test ID**: `Server-ServerPublicKeyCredentialGetOptionsResponse-Req-1`

- ✅ Valid assertion options request processing
- ✅ Invalid request rejection and error handling
- ✅ Challenge generation for assertion requests
- ✅ User verification requirement handling
- ✅ Allow credentials filtering and validation
- ✅ RP ID validation and format checking
- ✅ Timeout parameter validation
- ✅ Extensions parameter support

### 🔓 GetAssertion Response Tests
**Test IDs**: `Server-ServerAuthenticatorAssertionResponse-Resp-1` through `Resp-3`

- ✅ **Resp-1**: ServerAuthenticatorAssertionResponse structure validation
- ✅ **Resp-2**: CollectClientData processing for assertions
- ✅ **Resp-3**: AuthenticatorData processing and validation
- ✅ Signature verification and validation
- ✅ UserHandle processing (optional field handling)
- ✅ Credential ID validation and lookup
- ✅ Counter validation and replay protection

### 📋 Metadata Service Tests

- ✅ MDS3 endpoint integration and connectivity
- ✅ Authenticator metadata validation
- ✅ Certificate chain validation
- ✅ MDS cache and update mechanisms
- ✅ Metadata statement integrity verification
- ✅ AAGUID lookup and validation
- ✅ Attestation root certificate validation

## Quick Start

### Prerequisites

- Rust 1.70 or later
- A FIDO2 server implementation with the required API endpoints

### Running Tests

```bash
# Run all conformance tests
cargo test conformance --release

# Run specific test category
cargo test conformance::credential_creation_tests --release

# Run with verbose output
cargo test conformance -- --nocapture

# Run a specific test
cargo test test_server_credential_creation_options_req_1_positive --release
```

### Using the Test Runner

```rust
use fido_server::tests::conformance::test_utils::*;

#[tokio::main]
async fn main() {
    let config = TestRunnerConfig {
        verbose: true,
        timeout: Duration::from_secs(30),
        parallel: false,
        filter: None, // Run all tests
    };
    
    let results = run_all_conformance_tests(config).await;
    
    // Generate reports
    let junit_xml = generate_junit_report(&results);
    let json_report = generate_json_report(&results);
    
    println!("Success rate: {:.1}%", 
             (results.passed_tests as f64 / results.total_tests as f64) * 100.0);
}
```

## API Endpoints Required

Your FIDO2 server must implement these endpoints for the tests to pass:

### Registration Endpoints

```http
POST /attestation/options
Content-Type: application/json

{
  "username": "user@example.com",
  "displayName": "User Name",
  "authenticatorSelection": {
    "requireResidentKey": false,
    "authenticatorAttachment": "cross-platform",
    "userVerification": "preferred"
  },
  "attestation": "direct"
}
```

```http
POST /attestation/result
Content-Type: application/json

{
  "id": "credential-id-base64url",
  "response": {
    "clientDataJSON": "client-data-base64url",
    "attestationObject": "attestation-object-base64url"
  },
  "type": "public-key"
}
```

### Authentication Endpoints

```http
POST /assertion/options
Content-Type: application/json

{
  "username": "user@example.com",
  "userVerification": "required"
}
```

```http
POST /assertion/result
Content-Type: application/json

{
  "id": "credential-id-base64url",
  "response": {
    "clientDataJSON": "client-data-base64url",
    "authenticatorData": "authenticator-data-base64url",
    "signature": "signature-base64url",
    "userHandle": "user-handle-base64url"
  },
  "type": "public-key"
}
```

## Expected Response Formats

### Success Response
```json
{
  "status": "ok",
  "errorMessage": ""
}
```

### Error Response
```json
{
  "status": "failed",
  "errorMessage": "Descriptive error message"
}
```

### Credential Creation Options Response
```json
{
  "status": "ok",
  "errorMessage": "",
  "rp": {
    "name": "Example Corporation",
    "id": "example.com"
  },
  "user": {
    "id": "user-id-base64url",
    "name": "user@example.com",
    "displayName": "User Name"
  },
  "challenge": "challenge-base64url",
  "pubKeyCredParams": [
    {"type": "public-key", "alg": -7},
    {"type": "public-key", "alg": -257}
  ],
  "timeout": 60000,
  "excludeCredentials": [],
  "authenticatorSelection": {
    "requireResidentKey": false,
    "authenticatorAttachment": "cross-platform",
    "userVerification": "preferred"
  },
  "attestation": "direct"
}
```

### Assertion Options Response
```json
{
  "status": "ok",
  "errorMessage": "",
  "challenge": "challenge-base64url",
  "timeout": 60000,
  "rpId": "example.com",
  "allowCredentials": [
    {
      "id": "credential-id-base64url",
      "type": "public-key",
      "transports": ["usb", "nfc"]
    }
  ],
  "userVerification": "required"
}
```

## Configuration

### Test Configuration

Create a `test_config.toml` file to customize test behavior:

```toml
[server]
base_url = "http://localhost:8080"
timeout_seconds = 30

[tests]
verbose = true
parallel = false
fail_fast = false

[filters]
# Run only specific categories
categories = ["MakeCredential", "GetAssertion"]

# Run only specific tests
tests = ["test_server_credential_creation_options"]
```

### Environment Variables

```bash
# Server endpoint configuration
export FIDO_SERVER_URL="http://localhost:8080"
export FIDO_SERVER_TIMEOUT="30"

# Test configuration
export FIDO_TEST_VERBOSE="true"
export FIDO_TEST_PARALLEL="false"
```

## Integration with CI/CD

### GitHub Actions Example

```yaml
name: FIDO2 Conformance Tests

on: [push, pull_request]

jobs:
  conformance-tests:
    runs-on: ubuntu-latest
    
    services:
      fido-server:
        image: your-fido-server:latest
        ports:
          - 8080:8080
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Setup Rust
      uses: actions-rs/toolchain@v1
      with:
        toolchain: stable
    
    - name: Wait for server
      run: |
        timeout 60 bash -c 'until curl -f http://localhost:8080/health; do sleep 2; done'
    
    - name: Run FIDO2 Conformance Tests
      run: |
        cargo test conformance --release -- --nocapture
    
    - name: Generate Test Reports
      run: |
        cargo run --bin conformance_runner -- --output-junit junit.xml --output-json results.json
    
    - name: Upload Test Results
      uses: actions/upload-artifact@v3
      if: always()
      with:
        name: test-results
        path: |
          junit.xml
          results.json
```

### Jenkins Pipeline Example

```groovy
pipeline {
    agent any
    
    stages {
        stage('Setup') {
            steps {
                sh 'docker-compose up -d fido-server'
                sh 'sleep 10' // Wait for server startup
            }
        }
        
        stage('Conformance Tests') {
            steps {
                sh 'cargo test conformance --release'
            }
            post {
                always {
                    junit 'target/test-results/junit.xml'
                    publishHTML([
                        allowMissing: false,
                        alwaysLinkToLastBuild: true,
                        keepAll: true,
                        reportDir: 'target/test-results',
                        reportFiles: 'index.html',
                        reportName: 'FIDO2 Conformance Report'
                    ])
                }
            }
        }
    }
    
    post {
        always {
            sh 'docker-compose down'
        }
    }
}
```

## Test Data and Fixtures

The test suite includes comprehensive test data generators:

### Valid Test Data
- Properly formatted WebAuthn credentials
- Valid attestation objects for all supported formats
- Compliant client data JSON structures
- Proper base64url encoded challenges and IDs

### Invalid Test Data (Negative Tests)
- Malformed base64url encoding
- Invalid JSON structures
- Missing required fields
- Out-of-spec parameter values
- Boundary condition violations

### Attestation Formats
- **Packed**: Full and self attestation
- **None**: Basic attestation
- **FIDO U2F**: Legacy U2F format
- **TPM**: Trusted Platform Module
- **Android Key**: Android hardware attestation
- **Android SafetyNet**: Google SafetyNet attestation

## Troubleshooting

### Common Issues

#### Server Not Responding
```bash
# Check if server is running
curl -v http://localhost:8080/health

# Check server logs
docker logs fido-server
```

#### Test Failures
```bash
# Run with verbose output
cargo test conformance -- --nocapture

# Run single test for debugging
cargo test test_server_credential_creation_options_req_1_positive -- --nocapture

# Check test logs
RUST_LOG=debug cargo test conformance
```

#### Authentication Issues
- Verify challenge generation is cryptographically secure
- Check that challenges are unique across requests
- Ensure proper base64url encoding (no padding)
- Validate signature verification implementation

#### Attestation Issues
- Verify attestation object CBOR encoding
- Check certificate chain validation
- Ensure proper attestation format support
- Validate metadata service integration

### Debug Mode

Enable debug mode for detailed test output:

```rust
#[tokio::test]
async fn debug_test() {
    env_logger::init();
    
    let config = TestRunnerConfig {
        verbose: true,
        timeout: Duration::from_secs(60), // Longer timeout for debugging
        parallel: false,
        filter: Some("credential_creation".to_string()),
    };
    
    let results = run_all_conformance_tests(config).await;
    
    // Print detailed results
    for detail in &results.test_details {
        if matches!(detail.status, TestResultStatus::Failed) {
            println!("Failed test: {}", detail.test_name);
            println!("Error: {:?}", detail.error_message);
            println!("Execution time: {:?}", detail.execution_time);
        }
    }
}
```

## Contributing

### Adding New Tests

1. **Create test function** following the naming convention:
   ```rust
   #[actix_web::test]
   async fn test_new_functionality() -> ConformanceTestResult {
       // Test implementation
       Ok(())
   }
   ```

2. **Add test data** to `test_data.rs`:
   ```rust
   pub fn generate_new_test_data() -> Value {
       json!({
           // Test data structure
       })
   }
   ```

3. **Update test runner** in `test_utils.rs` to include the new test

4. **Add documentation** explaining the test purpose and expected behavior

### Test Categories

Each test should be categorized appropriately:
- `MakeCredentialRequest`
- `MakeCredentialResponse` 
- `GetAssertionRequest`
- `GetAssertionResponse`
- `MetadataService`

### Code Standards

- Follow Rust naming conventions
- Add comprehensive documentation
- Include both positive and negative test cases
- Use descriptive test names matching FIDO Alliance specifications
- Implement proper error handling and reporting

## Reference Documentation

- [FIDO2 Server Conformance Test API](https://github.com/fido-alliance/conformance-test-tools-resources/blob/master/docs/FIDO2/Server/Conformance-Test-API.md)
- [WebAuthn Specification](https://w3c.github.io/webauthn/)
- [FIDO Alliance Metadata Service](https://fidoalliance.org/metadata/)
- [CTAP 2.1 Specification](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html)

## License

This test suite is provided under the same license as the parent project. The test data and validation logic are based on public FIDO Alliance specifications and are intended for conformance testing purposes only.

---

**Note**: This test suite is designed to replicate the behavior of the official FIDO Alliance conformance testing tools. While comprehensive, it should not be considered a replacement for official certification testing. For official FIDO2 certification, please use the official FIDO Alliance conformance tools available through their certification program.
