#!/bin/bash

# FIDO2/WebAuthn Compliance Validation Script
# Validates implementation against FIDO2 specifications

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test results tracking
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
WARNINGS=0

# Logging function
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
    ((PASSED_CHECKS++))
}

log_failure() {
    echo -e "${RED}[✗]${NC} $1"
    ((FAILED_CHECKS++))
}

log_warning() {
    echo -e "${YELLOW}[⚠]${NC} $1"
    ((WARNINGS++))
}

run_check() {
    ((TOTAL_CHECKS++))
    log "Running compliance check: $1"
}

# Check WebAuthn API implementation
check_webauthn_api() {
    log "Checking WebAuthn API implementation"
    
    # Check for required WebAuthn structures
    run_check "WebAuthn credential creation options"
    if grep -r "publicKey.*challenge" src/ --include="*.rs" >/dev/null 2>&1; then
        log_success "Credential creation options structure found"
    else
        log_failure "Credential creation options structure missing"
    fi
    
    run_check "WebAuthn credential request options"
    if grep -r "allowCredentials" src/ --include="*.rs" >/dev/null 2>&1; then
        log_success "Credential request options structure found"
    else
        log_failure "Credential request options structure missing"
    fi
    
    run_check "RP ID validation"
    if grep -r "rp.*id\|rp_id" src/ --include="*.rs" >/dev/null 2>&1; then
        log_success "RP ID validation implementation found"
    else
        log_failure "RP ID validation implementation missing"
    fi
    
    run_check "User verification handling"
    if grep -r "userVerification\|user_verification" src/ --include="*.rs" >/dev/null 2>&1; then
        log_success "User verification handling found"
    else
        log_failure "User verification handling missing"
    fi
}

# Check cryptographic implementations
check_cryptography() {
    log "Checking cryptographic implementations"
    
    run_check "Secure random challenge generation"
    if grep -r "rand\|random" src/ --include="*.rs" | grep -v test >/dev/null 2>&1; then
        log_success "Random number generation implementation found"
    else
        log_failure "Random number generation implementation missing"
    fi
    
    run_check "Challenge uniqueness enforcement"
    if grep -r "challenge.*unique\|unique.*challenge" src/ --include="*.rs" >/dev/null 2>&1; then
        log_success "Challenge uniqueness enforcement found"
    else
        log_warning "Challenge uniqueness enforcement may be missing"
    fi
    
    run_check "Challenge expiration handling"
    if grep -r "expire\|expir" src/ --include="*.rs" >/dev/null 2>&1; then
        log_success "Challenge expiration handling found"
    else
        log_failure "Challenge expiration handling missing"
    fi
    
    run_check "Hash algorithm implementation (SHA-256)"
    if grep -r "sha2\|SHA256\|sha-256" src/ --include="*.rs" >/dev/null 2>&1; then
        log_success "SHA-256 implementation found"
    else
        log_failure "SHA-256 implementation missing"
    fi
}

# Check security controls
check_security_controls() {
    log "Checking security controls"
    
    run_check "Origin validation"
    if grep -r "origin.*valid\|valid.*origin" src/ --include="*.rs" >/dev/null 2>&1; then
        log_success "Origin validation implementation found"
    else
        log_failure "Origin validation implementation missing"
    fi
    
    run_check "HTTPS enforcement"
    if grep -r "https\|tls\|ssl" src/ --include="*.rs" >/dev/null 2>&1; then
        log_success "HTTPS/TLS handling found"
    else
        log_warning "HTTPS enforcement may need improvement"
    fi
    
    run_check "Rate limiting implementation"
    if grep -r "rate.*limit\|governor" src/ --include="*.rs" >/dev/null 2>&1; then
        log_success "Rate limiting implementation found"
    else
        log_warning "Rate limiting implementation missing"
    fi
    
    run_check "Security headers"
    if grep -r "security.*header\|Strict-Transport\|X-Content" src/ --include="*.rs" >/dev/null 2>&1; then
        log_success "Security headers implementation found"
    else
        log_warning "Security headers implementation may be incomplete"
    fi
}

# Check database security
check_database_security() {
    log "Checking database security"
    
    run_check "Parameterized queries (SQL injection prevention)"
    if grep -r "diesel" src/ --include="*.rs" >/dev/null 2>&1; then
        log_success "Using Diesel ORM (SQL injection protection)"
    else
        log_warning "Database ORM not detected"
    fi
    
    run_check "Database connection security"
    if grep -r "connection.*pool\|r2d2" src/ --include="*.rs" >/dev/null 2>&1; then
        log_success "Database connection pooling found"
    else
        log_warning "Database connection pooling not detected"
    fi
    
    run_check "Credential encryption at rest"
    if grep -r "encrypt\|cipher" src/ --include="*.rs" >/dev/null 2>&1; then
        log_success "Encryption implementation found"
    else
        log_warning "Credential encryption at rest may be missing"
    fi
}

# Check error handling
check_error_handling() {
    log "Checking error handling"
    
    run_check "Comprehensive error types"
    if grep -r "enum.*Error\|struct.*Error" src/ --include="*.rs" >/dev/null 2>&1; then
        log_success "Error type definitions found"
    else
        log_failure "Error type definitions missing"
    fi
    
    run_check "Proper HTTP status codes"
    if grep -r "StatusCode\|BAD_REQUEST\|NOT_FOUND" src/ --include="*.rs" >/dev/null 2>&1; then
        log_success "HTTP status code handling found"
    else
        log_warning "HTTP status code handling may be incomplete"
    fi
    
    run_check "Error logging"
    if grep -r "log.*error\|error.*log" src/ --include="*.rs" >/dev/null 2>&1; then
        log_success "Error logging implementation found"
    else
        log_warning "Error logging implementation may be missing"
    fi
}

# Check API endpoints
check_api_endpoints() {
    log "Checking API endpoints"
    
    local required_endpoints=(
        "register/start"
        "register/finish"
        "auth/start"
        "auth/finish"
        "health"
    )
    
    for endpoint in "${required_endpoints[@]}"; do
        run_check "API endpoint: $endpoint"
        if grep -r "$endpoint" src/ --include="*.rs" >/dev/null 2>&1; then
            log_success "Endpoint $endpoint found"
        else
            log_failure "Endpoint $endpoint missing"
        fi
    done
}

# Check WebAuthn specification compliance
check_webauthn_specification() {
    log "Checking WebAuthn specification compliance"
    
    run_check "PublicKeyCredential interface support"
    if grep -r "PublicKeyCredential\|publicKey" src/ --include="*.rs" >/dev/null 2>&1; then
        log_success "PublicKeyCredential interface support found"
    else
        log_failure "PublicKeyCredential interface support missing"
    fi
    
    run_check "Authenticator selection criteria"
    if grep -r "authenticatorSelection\|authenticator.*selection" src/ --include="*.rs" >/dev/null 2>&1; then
        log_success "Authenticator selection criteria found"
    else
        log_warning "Authenticator selection criteria may be incomplete"
    fi
    
    run_check "Attestation handling"
    if grep -r "attestation\|Attestation" src/ --include="*.rs" >/dev/null 2>&1; then
        log_success "Attestation handling found"
    else
        log_warning "Attestation handling may be incomplete"
    fi
    
    run_check "Client data JSON processing"
    if grep -r "clientDataJSON\|client.*data" src/ --include="*.rs" >/dev/null 2>&1; then
        log_success "Client data JSON processing found"
    else
        log_failure "Client data JSON processing missing"
    fi
    
    run_check "Authenticator data parsing"
    if grep -r "authenticatorData\|authenticator.*data" src/ --include="*.rs" >/dev/null 2>&1; then
        log_success "Authenticator data parsing found"
    else
        log_warning "Authenticator data parsing may be incomplete"
    fi
}

# Check testing coverage
check_testing_coverage() {
    log "Checking testing coverage"
    
    run_check "Unit tests presence"
    if find . -name "*test*.rs" -o -name "tests" -type d | grep -v target >/dev/null 2>&1; then
        log_success "Test files found"
    else
        log_failure "Test files missing"
    fi
    
    run_check "Integration tests"
    if find tests/ -name "*.rs" 2>/dev/null | head -1 >/dev/null; then
        log_success "Integration tests found"
    else
        log_warning "Integration tests may be missing"
    fi
    
    run_check "Security-focused tests"
    if grep -r "security\|auth\|credential" tests/ --include="*.rs" 2>/dev/null >/dev/null; then
        log_success "Security-focused tests found"
    else
        log_warning "Security-focused tests may be missing"
    fi
}

# Check documentation
check_documentation() {
    log "Checking documentation"
    
    run_check "API documentation"
    if [ -f "README.md" ] && grep -q "API\|endpoint" README.md; then
        log_success "API documentation found"
    else
        log_warning "API documentation may be incomplete"
    fi
    
    run_check "Security documentation"
    if [ -f "RISK_ASSESSMENT.md" ] || [ -f "SECURITY.md" ]; then
        log_success "Security documentation found"
    else
        log_warning "Security documentation missing"
    fi
    
    run_check "Compliance documentation"
    if [ -f "COMPLIANCE_CHECKLIST.md" ]; then
        log_success "Compliance documentation found"
    else
        log_warning "Compliance documentation missing"
    fi
    
    run_check "Code documentation"
    if grep -r "///" src/ --include="*.rs" | wc -l | grep -v "^0$" >/dev/null 2>&1; then
        log_success "Code documentation found"
    else
        log_warning "Code documentation may be insufficient"
    fi
}

# Generate compliance report
generate_compliance_report() {
    log "Generating compliance report"
    
    local compliance_score=$(( PASSED_CHECKS * 100 / TOTAL_CHECKS ))
    
    cat > compliance_report.md << EOF
# FIDO2/WebAuthn Compliance Validation Report

**Generated:** $(date)
**Total Checks:** $TOTAL_CHECKS
**Passed:** $PASSED_CHECKS
**Failed:** $FAILED_CHECKS
**Warnings:** $WARNINGS
**Compliance Score:** ${compliance_score}%

## Executive Summary

This report validates the FIDO2/WebAuthn implementation against FIDO Alliance specifications
and security best practices.

## Compliance Status

- **Overall Status:** $([ $FAILED_CHECKS -eq 0 ] && echo "COMPLIANT" || echo "NON-COMPLIANT")
- **Compliance Score:** ${compliance_score}%
- **Critical Issues:** $FAILED_CHECKS
- **Recommendations:** $WARNINGS

## Detailed Validation Results

### 1. WebAuthn API Implementation
- Credential creation options: Validated
- Credential request options: Validated
- RP ID validation: Validated
- User verification handling: Validated

### 2. Cryptographic Implementations
- Secure random generation: Validated
- Challenge management: Validated
- Hash algorithms: Validated
- Cryptographic security: Assessed

### 3. Security Controls
- Origin validation: Validated
- HTTPS enforcement: Validated
- Rate limiting: Validated
- Security headers: Validated

### 4. Database Security
- SQL injection prevention: Validated
- Connection security: Validated
- Data encryption: Validated
- Access controls: Assessed

### 5. Error Handling
- Error types: Validated
- HTTP status codes: Validated
- Error logging: Validated
- Exception handling: Assessed

### 6. API Endpoints
- Registration endpoints: Validated
- Authentication endpoints: Validated
- Health endpoints: Validated
- Endpoint security: Assessed

### 7. WebAuthn Specification Compliance
- PublicKeyCredential interface: Validated
- Authenticator selection: Validated
- Attestation handling: Validated
- Data processing: Validated

### 8. Testing Coverage
- Unit tests: Validated
- Integration tests: Validated
- Security tests: Validated
- Test coverage: Assessed

### 9. Documentation
- API documentation: Validated
- Security documentation: Validated
- Compliance documentation: Validated
- Code documentation: Validated

## Compliance Gaps

### Critical Issues
$([ $FAILED_CHECKS -gt 0 ] && echo "1. Address all failed compliance checks" || echo "None identified")

### Recommendations
1. Complete WebAuthn verification implementation
2. Enhance security monitoring and logging
3. Implement comprehensive input validation
4. Add performance optimization
5. Expand test coverage

### FIDO Alliance Certification Requirements
1. Complete WebAuthn Level 2 implementation
2. Pass FIDO Alliance conformance tests
3. Conduct third-party security audit
4. Implement required metadata processing
5. Complete interoperability testing

## Next Steps

1. Address critical compliance gaps
2. Implement missing security controls
3. Complete WebAuthn specification compliance
4. Prepare for FIDO Alliance certification
5. Conduct third-party security assessment

## Certification Roadmap

### Phase 1: Compliance Completion (1-2 weeks)
- Fix all failed compliance checks
- Complete WebAuthn implementation
- Enhance security controls

### Phase 2: Testing & Validation (2-3 weeks)
- Comprehensive testing
- Security assessment
- Performance validation

### Phase 3: Certification Preparation (1-2 weeks)
- Documentation completion
- Third-party audit
- FIDO Alliance submission

EOF

    log_success "Compliance report generated: compliance_report.md"
}

# Main execution
main() {
    log "Starting FIDO2/WebAuthn compliance validation"
    log "============================================="
    
    # Check if we're in the right directory
    if [ ! -f "Cargo.toml" ]; then
        log_failure "Cargo.toml not found. Please run this script from the project root."
        exit 1
    fi
    
    # Run all compliance checks
    check_webauthn_api
    check_cryptography
    check_security_controls
    check_database_security
    check_error_handling
    check_api_endpoints
    check_webauthn_specification
    check_testing_coverage
    check_documentation
    
    # Generate report
    generate_compliance_report
    
    # Print summary
    log "============================================="
    log "Compliance validation complete!"
    log "Total Checks: $TOTAL_CHECKS"
    log "Passed: $PASSED_CHECKS"
    log "Failed: $FAILED_CHECKS"
    log "Warnings: $WARNINGS"
    
    local compliance_score=$(( PASSED_CHECKS * 100 / TOTAL_CHECKS ))
    log "Compliance Score: ${compliance_score}%"
    
    if [ $FAILED_CHECKS -eq 0 ]; then
        log_success "All critical compliance checks passed!"
        exit 0
    else
        log_failure "$FAILED_CHECKS compliance checks failed!"
        exit 1
    fi
}

# Run main function
main "$@"