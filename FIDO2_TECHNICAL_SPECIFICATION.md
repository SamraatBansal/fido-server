# FIDO2/WebAuthn Relying Party Server Technical Specification

## Executive Summary

This document provides a comprehensive technical specification for implementing a FIDO2/WebAuthn conformant Relying Party Server in Rust using the webauthn-rs library. The implementation must be production-ready with comprehensive test coverage and full FIDO Alliance specification compliance.

## 1. System Architecture

### 1.1 Core Components

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Web Client    │    │  Actix-Web API  │    │   PostgreSQL    │
│                 │◄──►│                 │◄──►│                 │
│ WebAuthn API    │    │  Controllers    │    │   Database      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌─────────────────┐
                       │  webauthn-rs    │
                       │   Library       │
                       └─────────────────┘
```

### 1.2 Data Flow

1. **Registration Flow**: Client → /attestation/options → /attestation/result → Database
2. **Authentication Flow**: Client → /assertion/options → /assertion/result → Database

## 2. Mandatory API Endpoints

### 2.1 Registration (Attestation) Endpoints

#### POST /attestation/options
- **Purpose**: Generate registration challenge for new credential
- **Request**: `{ "username": "string", "displayName": "string" }`
- **Response**: WebAuthn credential creation options
- **Status**: Must return 200 with valid challenge

#### POST /attestation/result
- **Purpose**: Verify registration attestation and store credential
- **Request**: WebAuthn credential creation response
- **Response**: `{ "status": "success", "credentialId": "string" }`
- **Status**: Must return 200 after successful verification

### 2.2 Authentication (Assertion) Endpoints

#### POST /assertion/options
- **Purpose**: Generate authentication challenge for existing user
- **Request**: `{ "username": "string" }`
- **Response**: WebAuthn credential request options
- **Status**: Must return 200 with valid challenge

#### POST /assertion/result
- **Purpose**: Verify authentication assertion
- **Request**: WebAuthn credential assertion response
- **Response**: `{ "status": "success", "authenticated": true }`
- **Status**: Must return 200 after successful verification

## 3. Security Requirements

### 3.1 Cryptographic Security
- **Challenge Generation**: Cryptographically secure random challenges (minimum 16 bytes)
- **Challenge Expiration**: Challenges expire within 5 minutes
- **Origin Validation**: Strict origin validation for all requests
- **Replay Attack Prevention**: One-time use challenges with immediate invalidation

### 3.2 Transport Security
- **TLS Enforcement**: HTTPS-only in production
- **CORS Configuration**: Secure CORS with specific allowed origins (not allow_any_origin)
- **Content Security**: Proper content-type headers and validation

### 3.3 Input Validation
- **Request Size Limits**: Maximum 1MB request payload
- **Input Sanitization**: All user inputs validated and sanitized
- **Rate Limiting**: Prevent brute force attacks

## 4. Database Schema

### 4.1 Users Table
```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) UNIQUE NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

### 4.2 Credentials Table
```sql
CREATE TABLE credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BYTEA UNIQUE NOT NULL,
    public_key BYTEA NOT NULL,
    sign_count BIGINT NOT NULL DEFAULT 0,
    attestation_type VARCHAR(50) NOT NULL,
    aaguid BYTEA,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

### 4.3 Challenges Table
```sql
CREATE TABLE challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    challenge_id VARCHAR(255) UNIQUE NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    challenge_data BYTEA NOT NULL,
    challenge_type VARCHAR(20) NOT NULL, -- 'registration' or 'authentication'
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

## 5. Implementation Requirements

### 5.1 WebAuthn Integration
- **Library**: webauthn-rs 0.5+ with actual Webauthn struct instantiation
- **Configuration**: Proper Relying Party configuration (ID, name, origins)
- **Attestation**: Support for multiple attestation formats (packed, fido-u2f, none)
- **User Verification**: Support for required, preferred, and discouraged UV

### 5.2 Error Handling
- **No Panics**: All errors handled gracefully with proper HTTP status codes
- **Error Types**: Comprehensive error enum with specific error messages
- **Logging**: Structured logging for security events and errors

### 5.3 Session Management
- **Challenge Storage**: Secure challenge storage with expiration
- **Session Binding**: Optional session binding for enhanced security
- **Cleanup**: Automatic cleanup of expired challenges

## 6. Testing Requirements

### 6.1 Unit Testing (95%+ Coverage)
- **Service Layer**: All WebAuthn operations tested
- **Database Operations**: CRUD operations with edge cases
- **Utility Functions**: Cryptographic and validation functions
- **Error Handling**: All error paths tested

### 6.2 Integration Testing
- **API Endpoints**: All 4 mandatory endpoints tested end-to-end
- **Database Integration**: Full database operations tested
- **WebAuthn Flow**: Complete registration and authentication flows
- **Security Scenarios**: Attack scenarios and edge cases

### 6.3 Compliance Testing
- **FIDO Alliance**: Compliance with FIDO2 specification
- **WebAuthn Level 1**: Full compliance with WebAuthn Level 1
- **Interoperability**: Test with various authenticators
- **Security**: OWASP security testing guidelines

### 6.4 Performance Testing
- **Concurrent Users**: Support for 1000+ concurrent users
- **Response Times**: <100ms for challenge generation, <200ms for verification
- **Memory Usage**: Efficient memory usage under load
- **Database Performance**: Optimized queries with proper indexing

## 7. Production Checklist

### 7.1 API Endpoints Verification
- ✅ POST /attestation/options returns 200 status
- ✅ POST /attestation/result returns 200 status
- ✅ POST /assertion/options returns 200 status
- ✅ POST /assertion/result returns 200 status

### 7.2 Code Quality
- ✅ No TODO comments in final code
- ✅ No unimplemented! macros
- ✅ Real webauthn-rs integration (not just imports)
- ✅ Database operations fully functional
- ✅ Complete registration and authentication flows

### 7.3 Security Verification
- ✅ Secure CORS configuration
- ✅ Input validation on all endpoints
- ✅ Proper error handling without panics
- ✅ Replay attack prevention
- ✅ Session management implemented

## 8. Development Phases

### Phase 1: Core Infrastructure (Week 1)
- Database models and migrations
- WebAuthn service foundation
- Basic error handling
- Project structure completion

### Phase 2: API Implementation (Week 2)
- All 4 mandatory endpoints
- Request/response schemas
- Input validation
- CORS configuration

### Phase 3: Security & Testing (Week 3)
- Security hardening
- Unit test implementation
- Integration test development
- Performance optimization

### Phase 4: Compliance & Production (Week 4)
- FIDO compliance testing
- Security audit
- Documentation
- Production deployment preparation

## 9. Success Metrics

### 9.1 Functional Metrics
- 100% API endpoint availability
- 95%+ test coverage
- Zero security vulnerabilities
- FIDO2 specification compliance

### 9.2 Performance Metrics
- <100ms challenge generation
- <200ms verification time
- 99.9% uptime
- Support for 1000+ concurrent users

### 9.3 Security Metrics
- Zero successful replay attacks
- Proper challenge expiration
- Secure credential storage
- Comprehensive audit logging

## 10. References

- [FIDO Alliance Conformance Test API](https://github.com/fido-alliance/conformance-test-tools-resources/blob/main/docs/FIDO2/Server/Conformance-Test-API.md)
- [WebAuthn Specification](https://www.w3.org/TR/webauthn/)
- [FIDO2 Specification](https://fidoalliance.org/specifications/)
- [webauthn-rs Documentation](https://docs.rs/webauthn-rs/)

---

**Note**: This specification must be implemented exactly as described. No shortcuts, stubs, or incomplete implementations are acceptable for production deployment.