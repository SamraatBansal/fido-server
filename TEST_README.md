# FIDO2/WebAuthn Test Suite

This directory contains a comprehensive test suite for the FIDO2/WebAuthn Relying Party Server implementation. The test suite is designed to ensure security, compliance, performance, and reliability of the implementation.

## 📁 Test Structure

```
tests/
├── common/                  # Shared test utilities
│   ├── fixtures.rs         # Test data factories
│   ├── helpers.rs          # Test helper functions
│   └── mod.rs
├── compliance/             # Specification compliance tests
│   ├── security_compliance.rs
│   ├── webauthn_compliance.rs
│   └── mod.rs
├── integration/            # End-to-end integration tests
│   ├── api_test.rs
│   ├── authentication_tests.rs
│   ├── registration_tests.rs
│   └── mod.rs
├── performance/            # Performance and load tests
│   ├── benchmarks.rs       # Criterion benchmarks
│   ├── load_tests.rs       # Load testing
│   └── mod.rs
├── security/               # Security-focused tests
│   ├── replay_protection_test.rs
│   └── mod.rs
├── unit/                   # Unit tests
│   └── services/
│       └── fido_test.rs
└── lib.rs                  # Test library entry point
```

## 🚀 Quick Start

### Running All Tests

```bash
# Simple test run
cargo test

# Comprehensive test run with reporting
./run_tests.sh
```

### Running Specific Test Categories

```bash
# Unit tests only
cargo test --test unit

# Integration tests only
cargo test --test integration

# Security tests only
cargo test --test security

# Performance benchmarks
cargo bench

# Compliance tests only
cargo test --test compliance
```

### Running Individual Test Files

```bash
# Specific test file
cargo test --test fido_test

# Specific test function
cargo test test_registration_challenge_generation
```

## 📊 Test Categories

### 1. Unit Tests (`tests/unit/`)

**Purpose**: Test individual components in isolation

**Coverage**:
- ✅ Service creation and initialization
- ✅ Request validation (registration and authentication)
- ✅ Challenge generation and uniqueness
- ✅ User persistence and retrieval
- ✅ Error handling and edge cases
- ✅ Property-based testing with `proptest`

**Key Tests**:
- `test_registration_challenge_generation`
- `test_authentication_challenge_generation`
- `test_user_persistence`
- `test_challenge_uniqueness`
- `test_error_types`

### 2. Integration Tests (`tests/integration/`)

**Purpose**: Test component interactions and end-to-end flows

**Coverage**:
- ✅ Complete registration workflows
- ✅ Complete authentication workflows
- ✅ Concurrent operations handling
- ✅ State persistence across operations
- ✅ Error propagation through the system

**Key Tests**:
- `test_registration_flow_integration`
- `test_authentication_flow_integration`
- `test_user_persistence_across_operations`
- `test_concurrent_registrations`
- `test_error_handling_integration`

### 3. Security Tests (`tests/security/`)

**Purpose**: Test security mechanisms and attack prevention

**Coverage**:
- ✅ Replay attack prevention
- ✅ Challenge uniqueness and entropy
- ✅ User data isolation
- ✅ Concurrent operation security
- ✅ Malformed input handling
- ✅ State isolation between operations

**Key Tests**:
- `test_challenge_uniqueness_prevents_replay`
- `test_user_data_isolation`
- `test_concurrent_challenge_generation`
- `test_challenge_entropy_quality`
- `test_malformed_input_handling`

### 4. Performance Tests (`tests/performance/`)

**Purpose**: Test performance characteristics and load handling

**Coverage**:
- ✅ Load testing for concurrent operations
- ✅ Memory usage under load
- ✅ Response time measurement
- ✅ Challenge generation performance
- ✅ Benchmarking with Criterion

**Key Tests**:
- `test_concurrent_registration_load`
- `test_concurrent_authentication_load`
- `test_mixed_workload_load`
- `test_memory_usage_under_load`
- `challenge_generation` (benchmark)

### 5. Compliance Tests (`tests/compliance/`)

**Purpose**: Test compliance with WebAuthn/FIDO2 specifications

**Coverage**:
- ✅ WebAuthn specification compliance
- ✅ Security requirement compliance
- ✅ Data format validation
- ✅ Error handling compliance
- ✅ Timing attack resistance

**Key Tests**:
- `test_challenge_length_compliance`
- `test_user_id_format_compliance`
- `test_authentication_flow_compliance`
- `test_timing_attack_resistance`
- `test_error_information_leakage`

## 🛠️ Test Utilities

### Fixtures (`tests/common/fixtures.rs`)

Provides test data factories for creating:
- Valid registration requests
- Valid authentication requests
- Invalid requests for negative testing
- Random test data

Example usage:
```rust
use tests::common::fixtures::*;

let request = valid_registration_request();
let invalid_request = invalid_registration_request_empty_username();
```

### Helpers (`tests/common/helpers.rs`)

Provides utility functions for:
- Creating users and retrieving IDs
- Generating unique challenges
- Verifying challenge format
- Performance measurement
- Error message validation

Example usage:
```rust
use tests::common::helpers::*;

let user_id = create_user(&mut service, "user@example.com", "User").await;
let challenges = generate_unique_challenges(&mut service, 10, "user@example.com", "User").await;
```

## 📈 Performance Benchmarks

The test suite includes Criterion benchmarks for measuring:

- **Registration Creation**: Time to create FidoService instances
- **Challenge Generation**: Time to generate cryptographically secure challenges
- **User Lookup**: Time to retrieve user information
- **Concurrent Operations**: Performance under concurrent load

Running benchmarks:
```bash
cargo bench
```

Benchmark results are saved to `target/criterion/` with detailed HTML reports.

## 🔒 Security Testing

The security test suite focuses on:

### Replay Attack Prevention
- Tests that challenges cannot be reused
- Verifies challenge uniqueness across generations
- Validates challenge expiration mechanisms

### Input Validation
- Tests malformed input handling
- Verifies input sanitization
- Tests buffer overflow prevention

### Timing Attack Resistance
- Measures response times for existing vs non-existing users
- Ensures consistent timing to prevent information leakage

### Information Leakage
- Verifies error messages don't contain sensitive information
- Tests that error responses are appropriately generic

## 📋 Compliance Testing

### WebAuthn Specification Compliance
- **Challenge Format**: 32-byte challenges, base64url encoded
- **User ID Format**: Proper UUID format (16 bytes)
- **Username Handling**: Accepts valid email formats and identifiers
- **Error Responses**: Appropriate error codes and messages

### Security Compliance
- **Cryptographic Randomness**: Challenges use cryptographically secure random generation
- **User Isolation**: Users cannot access each other's data
- **State Management**: Proper state isolation between operations

## 🧪 Property-Based Testing

The test suite uses `proptest` for property-based testing:

```rust
proptest! {
    #[test]
    fn test_username_format_validation(
        username in "[a-zA-Z0-9._%+-]{3,50}@[a-zA-Z0-9.-]{3,50}\\.[a-zA-Z]{2,10}"
    ) {
        // Test properties of valid usernames
        prop_assert!(!username.is_empty());
        prop_assert!(username.contains('@'));
    }
}
```

This approach tests many different input combinations automatically.

## 📊 Test Coverage

The test suite aims for comprehensive coverage:

- **Service Layer**: 100% of public methods
- **Error Handling**: All error paths tested
- **Input Validation**: Comprehensive validation testing
- **Security Mechanisms**: All security features tested
- **Performance Paths**: Critical performance paths tested

## 🔄 Continuous Integration

### Test Automation
All tests are designed to run automatically in CI/CD pipelines:

```yaml
# Example GitHub Actions workflow
- name: Run tests
  run: |
    cargo test --all-features
    cargo bench
    ./run_tests.sh
```

### Test Reporting
- Test results are saved to `test_results/`
- Coverage reports generated when `cargo-tarpaulin` is available
- Performance benchmarks tracked over time

## 🐛 Debugging Tests

### Running Tests with Output

```bash
# Show test output
cargo test -- --nocapture

# Run specific test with output
cargo test test_name -- --nocapture

# Run tests with logging
RUST_LOG=debug cargo test
```

### Debugging Failed Tests

```bash
# Run only failed tests
cargo test -- --ignored

# Run tests with backtrace
RUST_BACKTRACE=1 cargo test

# Run tests with full backtrace
RUST_BACKTRACE=full cargo test
```

### Test Performance Profiling

```bash
# Run tests with perf profiling
perf record --call-graph=dwarf cargo test
perf report

# Or use flamegraph
cargo install flamegraph
cargo flamegraph --test test_name
```

## 📝 Writing New Tests

### Unit Test Template

```rust
#[tokio::test]
async fn test_your_feature() {
    // Arrange
    let mut service = FidoService::new();
    let request = create_test_request();
    
    // Act
    let result = service.your_method(request).await;
    
    // Assert
    assert!(result.is_ok(), "Feature should work");
    
    let response = result.unwrap();
    assert!(!response.challenge.is_empty(), "Challenge should not be empty");
}
```

### Integration Test Template

```rust
#[tokio::test]
async fn test_your_integration() {
    // Setup
    let mut service = FidoService::new();
    
    // Test complete flow
    let reg_response = service.start_registration(reg_request).await.unwrap();
    let auth_response = service.start_authentication(auth_request).await.unwrap();
    
    // Verify integration
    assert_eq!(reg_response.user_id, auth_response.user_id);
}
```

### Security Test Template

```rust
#[tokio::test]
async fn test_your_security_feature() {
    // Test security property
    let challenges = generate_many_challenges().await;
    
    // Verify security property
    let unique_challenges: HashSet<_> = challenges.iter().collect();
    assert_eq!(unique_challenges.len(), challenges.len(), "Should be unique");
}
```

## 🚨 Troubleshooting

### Common Issues

1. **Tests Fail with "Borrow Checker" Errors**
   - Ensure proper async/await usage
   - Check for mutable borrow conflicts

2. **Performance Tests Are Flaky**
   - Run tests multiple times to establish baseline
   - Consider system load when interpreting results

3. **Security Tests Take Too Long**
   - Reduce test data size for development
   - Use conditional compilation for expensive tests

4. **Integration Tests Fail Isolation**
   - Ensure proper test isolation
   - Check for shared state between tests

### Getting Help

- Check the test logs in `test_results/`
- Review the test documentation in this file
- Look at existing test patterns for guidance
- Use `cargo test --help` for available options

## 📚 Additional Resources

- [Rust Testing Book](https://doc.rust-lang.org/book/ch11-00-testing.html)
- [Tokio Testing Documentation](https://tokio.rs/tokio/topics/testing)
- [Criterion Benchmarking](https://bheisler.github.io/criterion.rs/book/)
- [Proptest Documentation](https://altsysrq.github.io/proptest-book/)
- [WebAuthn Specification](https://www.w3.org/TR/webauthn/)

---

**Note**: This test suite is continuously evolving. Check back regularly for updates and new test categories as the FIDO2/WebAuthn implementation grows.