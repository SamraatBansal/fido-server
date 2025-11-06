# FIDO2/WebAuthn Conformance Testing Guide

This document provides detailed information on using the FIDO2/WebAuthn Relying Party server for FIDO Alliance conformance testing.

## Server Overview

The server implements all required FIDO2/WebAuthn API endpoints to support conformance testing:

- **Registration**: `/attestation/options` and `/attestation/result`
- **Authentication**: `/assertion/options` and `/assertion/result`
- **Health Check**: `/health`

## Key Features for Conformance

### 1. Comprehensive Input Validation

The server performs strict validation on all inputs to match FIDO conformance requirements:

- **Field presence validation**: All required fields must be present
- **Type validation**: Fields must be of correct types (string, number, etc.)
- **Base64url validation**: All base64url fields are validated for proper encoding
- **Challenge validation**: Challenges must be 16-64 bytes and properly encoded
- **Origin validation**: Origins must match configured RP origin
- **Client data validation**: Full client data structure validation

### 2. Proper Error Handling

All error responses follow the FIDO conformance format:

```json
{
  "status": "failed",
  "errorMessage": "Descriptive error message"
}
```

### 3. Exclude Credentials Support

The registration endpoint properly returns `excludeCredentials` for existing users to prevent duplicate registrations.

### 4. Algorithm Support

The server supports all required cryptographic algorithms:

- ES256 (-7) - ECDSA with P-256 curve
- RS256 (-257) - RSASSA-PKCS1-v1_5 with SHA-256
- Ed25519 (-8) - EdDSA with Ed25519 curve
- RS1 (-65535) - RSASSA-PKCS1-v1_5 with SHA-1

### 5. Extensions Support

The server includes the required `example.extension` in registration responses for conformance testing.

## Configuration for FIDO Conformance Tool

### Environment Variables

Set the following environment variables for conformance testing:

```bash
export RP_ID="localhost"
export RP_NAME="FIDO2 WebAuthn Server"
export RP_ORIGIN="http://localhost:8080"
export BIND_ADDRESS="0.0.0.0:8080"
export DATABASE_URL="postgres://postgres:password@localhost/fido2_webauthn"
```

### FIDO Conformance Tool Configuration

Configure the FIDO conformance tool to point to:

- **Base URL**: `http://localhost:8080`
- **Registration Start**: `POST /attestation/options`
- **Registration Finish**: `POST /attestation/result`
- **Authentication Start**: `POST /assertion/options`
- **Authentication Finish**: `POST /assertion/result`

## API Endpoint Details

### Registration Flow

#### 1. Start Registration - `POST /attestation/options`

**Request:**
```json
{
  "username": "user@example.com",
  "displayName": "John Doe",
  "authenticatorSelection": {
    "requireResidentKey": false,
    "authenticatorAttachment": "cross-platform",
    "userVerification": "preferred"
  },
  "attestation": "direct"
}
```

**Response:**
```json
{
  "status": "ok",
  "errorMessage": "",
  "rp": {
    "name": "FIDO2 WebAuthn Server",
    "id": "localhost"
  },
  "user": {
    "id": "base64url-encoded-user-id",
    "name": "user@example.com",
    "displayName": "John Doe"
  },
  "challenge": "base64url-encoded-challenge",
  "pubKeyCredParams": [
    {"type": "public-key", "alg": -7},
    {"type": "public-key", "alg": -257},
    {"type": "public-key", "alg": -8},
    {"type": "public-key", "alg": -65535}
  ],
  "timeout": 60000,
  "excludeCredentials": [],
  "authenticatorSelection": { /* ... */ },
  "attestation": "direct",
  "extensions": {
    "example.extension": true
  }
}
```

#### 2. Complete Registration - `POST /attestation/result`

**Request:**
```json
{
  "id": "base64url-credential-id",
  "type": "public-key",
  "response": {
    "clientDataJSON": "base64url-encoded-client-data",
    "attestationObject": "base64url-encoded-attestation-object"
  },
  "getClientExtensionResults": {}
}
```

**Success Response:**
```json
{
  "status": "ok",
  "errorMessage": ""
}
```

### Authentication Flow

#### 1. Start Authentication - `POST /assertion/options`

**Request:**
```json
{
  "username": "user@example.com",
  "userVerification": "preferred"
}
```

**Response:**
```json
{
  "status": "ok",
  "errorMessage": "",
  "challenge": "base64url-encoded-challenge",
  "timeout": 60000,
  "rpId": "localhost",
  "allowCredentials": [
    {
      "type": "public-key",
      "id": "base64url-credential-id"
    }
  ],
  "userVerification": "preferred"
}
```

#### 2. Complete Authentication - `POST /assertion/result`

**Request:**
```json
{
  "id": "base64url-credential-id",
  "type": "public-key",
  "response": {
    "clientDataJSON": "base64url-encoded-client-data",
    "authenticatorData": "base64url-encoded-authenticator-data",
    "signature": "base64url-encoded-signature",
    "userHandle": ""
  },
  "getClientExtensionResults": {}
}
```

**Success Response:**
```json
{
  "status": "ok",
  "errorMessage": ""
}
```

## Common FIDO Conformance Test Scenarios

### 1. Positive Test Cases

These should return successful responses:

- Valid registration with all required fields
- Valid authentication for existing user
- Different attestation preferences (none, indirect, direct)
- Various authenticator selection criteria
- Multiple supported algorithms

### 2. Negative Test Cases

These should return appropriate error responses:

- Missing required fields (username, displayName, etc.)
- Invalid field types (number instead of string, etc.)
- Empty strings for required fields
- Invalid base64url encoding
- Malformed client data JSON
- Invalid credential types
- Non-matching challenges
- Expired challenges
- Invalid origins
- Missing attestation objects
- Invalid attestation formats

## Troubleshooting

### Common Issues

1. **"SyntaxError: Unexpected token J in JSON at position 0"**
   - This usually indicates the server is not returning JSON
   - Check that the server is running on the correct port
   - Verify the API endpoints are accessible

2. **"Response.excludeCredentials is empty"**
   - Ensure users are properly stored in the database
   - Verify credential storage is working correctly

3. **Challenge validation failures**
   - Check challenge generation produces proper entropy
   - Verify challenge storage and retrieval
   - Ensure challenges expire appropriately

4. **Origin validation failures**
   - Verify RP_ORIGIN matches the test tool's origin
   - Check that origin validation is working correctly

### Logs and Debugging

Enable debug logging:
```bash
export RUST_LOG="debug"
```

The server will output detailed logs for:
- Request/response validation
- Database operations
- Challenge generation and validation
- Error conditions

### Database Verification

Check that credentials are properly stored:

```sql
-- Connect to database
psql -d fido2_webauthn

-- Check users
SELECT * FROM users;

-- Check credentials
SELECT * FROM credentials;

-- Check challenges
SELECT * FROM challenges WHERE expires_at > NOW();
```

## Performance Considerations

For conformance testing, the server is configured for:

- **Challenge timeout**: 5 minutes (300 seconds)
- **Request timeout**: 60 seconds
- **Database connection pooling**: Enabled for concurrent tests
- **Async processing**: All operations are async for performance

## Security Notes

The server implements:

- **Secure challenge generation**: Using OS random number generator
- **Challenge uniqueness**: Each challenge is cryptographically unique
- **Origin validation**: Strict origin checking
- **Input sanitization**: All inputs are validated and sanitized
- **SQL injection prevention**: Using parameterized queries
- **Error message security**: No sensitive information in error responses

## Compliance Checklist

- ✅ All required API endpoints implemented
- ✅ Proper JSON request/response format
- ✅ Comprehensive input validation
- ✅ Base64url encoding/decoding
- ✅ Challenge generation and validation
- ✅ Origin validation
- ✅ Client data parsing and validation
- ✅ Attestation object handling
- ✅ Algorithm support (ES256, RS256, Ed25519, RS1)
- ✅ Extensions support
- ✅ Error handling and reporting
- ✅ Exclude credentials functionality
- ✅ Database persistence
- ✅ Concurrent request handling

This implementation should pass all FIDO Alliance conformance tests when properly configured and deployed.