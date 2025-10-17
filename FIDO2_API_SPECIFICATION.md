# FIDO2/WebAuthn API Specification

## Overview

This document provides a detailed API specification for the FIDO2/WebAuthn Relying Party Server, following the FIDO Alliance Conformance Test API reference and ensuring full compliance with WebAuthn specifications.

## 1. API Architecture

### 1.1 Base Configuration
```
Base URL: https://rp.example.com/webauthn
API Version: v1
Content-Type: application/json
Character Encoding: UTF-8
```

### 1.2 Security Headers
```
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'self'
```

### 1.3 Authentication
- No authentication required for WebAuthn endpoints (they authenticate users)
- Admin endpoints require Bearer token authentication
- Rate limiting: 100 requests per minute per IP

## 2. Registration (Attestation) API

### 2.1 Attestation Options Endpoint

#### POST /webauthn/attestation/options

**Purpose**: Generate attestation options for credential registration

**Request Headers**:
```
Content-Type: application/json
Accept: application/json
```

**Request Body**:
```json
{
  "username": "user@example.com",
  "displayName": "John Doe",
  "userVerification": "required|preferred|discouraged",
  "attestation": "none|direct|enterprise|indirect",
  "authenticatorSelection": {
    "authenticatorAttachment": "platform|cross-platform",
    "requireResidentKey": false,
    "userVerification": "required|preferred|discouraged"
  },
  "extensions": {
    "credProps": true,
    "largeBlob": {
      "support": "required|preferred"
    },
    "minPinLength": true,
    "uvm": true
  },
  "timeout": 60000
}
```

**Request Validation**:
- `username`: Required, 3-255 characters, valid email or alphanumeric
- `displayName`: Required, 1-255 characters, no control characters
- `userVerification`: Optional, defaults to "preferred"
- `attestation`: Optional, defaults to "none"
- `timeout`: Optional, range 30000-300000 milliseconds

**Response Headers**:
```
Content-Type: application/json
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
```

**Success Response (200 OK)**:
```json
{
  "status": "ok",
  "errorMessage": "",
  "challenge": "Y2hhbGxlbmdlLXZhbHVlLWJhc2U2NHVybC1lbmNvZGVk",
  "rp": {
    "id": "example.com",
    "name": "Example Service"
  },
  "user": {
    "id": "dXNlci1pZC1iYXNlNjR1cmwtZW5jb2RlZA",
    "name": "user@example.com",
    "displayName": "John Doe"
  },
  "pubKeyCredParams": [
    {
      "type": "public-key",
      "alg": -7
    },
    {
      "type": "public-key",
      "alg": -257
    },
    {
      "type": "public-key",
      "alg": -37
    },
    {
      "type": "public-key",
      "alg": -8
    }
  ],
  "timeout": 60000,
  "excludeCredentials": [
    {
      "type": "public-key",
      "id": "ZXhpc3RpbmctY3JlZGVudGlhbC1pZA",
      "transports": ["internal", "usb", "nfc", "ble"]
    }
  ],
  "authenticatorSelection": {
    "authenticatorAttachment": "platform",
    "requireResidentKey": false,
    "userVerification": "preferred"
  },
  "attestation": "none",
  "extensions": {
    "credProps": true,
    "largeBlob": {
      "support": "preferred"
    }
  }
}
```

**Error Responses**:

400 Bad Request:
```json
{
  "status": "error",
  "errorMessage": "Invalid username format",
  "errorCode": "INVALID_USERNAME"
}
```

409 Conflict:
```json
{
  "status": "error",
  "errorMessage": "User already exists",
  "errorCode": "USER_EXISTS"
}
```

429 Too Many Requests:
```json
{
  "status": "error",
  "errorMessage": "Rate limit exceeded",
  "errorCode": "RATE_LIMIT_EXCEEDED",
  "retryAfter": 60
}
```

### 2.2 Attestation Result Endpoint

#### POST /webauthn/attestation/result

**Purpose**: Process attestation result and register credential

**Request Headers**:
```
Content-Type: application/json
Accept: application/json
```

**Request Body**:
```json
{
  "id": "Y3JlZGVudGlhbC1pZC1iYXNlNjR1cmwtZW5jb2RlZA",
  "rawId": "Y3JlZGVudGlhbC1pZC1iYXNlNjR1cmwtZW5jb2RlZA",
  "response": {
    "attestationObject": "b2JqZWN0LWF0dGVzdGF0aW9uLWJhc2U2NHVybC1lbmNvZGVk",
    "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoi..."
  },
  "type": "public-key",
  "clientExtensionResults": {
    "credProps": {
      "rk": true
    },
    "largeBlob": {
      "supported": true
    }
  },
  "transports": ["internal", "usb", "nfc", "ble"]
}
```

**Request Validation**:
- `id`: Required, Base64URL encoded credential ID
- `rawId`: Required, must match `id`
- `response.attestationObject`: Required, valid CBOR-encoded attestation object
- `response.clientDataJSON`: Required, valid JSON with required fields
- `type`: Required, must be "public-key"

**Success Response (200 OK)**:
```json
{
  "status": "ok",
  "errorMessage": "",
  "credentialId": "Y3JlZGVudGlhbC1pZC1iYXNlNjR1cmwtZW5jb2RlZA",
  "registrationTime": "2024-01-01T12:00:00Z",
  "aaguid": "00000000-0000-0000-0000-000000000000",
  "signCount": 0,
  "credProps": {
    "rk": true,
    "authenticator": {
      "displayName": "Platform Authenticator",
      "icon": "data:image/png;base64,..."
    }
  }
}
```

**Error Responses**:

400 Bad Request:
```json
{
  "status": "error",
  "errorMessage": "Invalid attestation object",
  "errorCode": "INVALID_ATTESTATION"
}
```

401 Unauthorized:
```json
{
  "status": "error",
  "errorMessage": "Invalid challenge",
  "errorCode": "INVALID_CHALLENGE"
}
```

409 Conflict:
```json
{
  "status": "error",
  "errorMessage": "Credential already registered",
  "errorCode": "CREDENTIAL_EXISTS"
}
```

## 3. Authentication (Assertion) API

### 3.1 Assertion Options Endpoint

#### POST /webauthn/assertion/options

**Purpose**: Generate assertion options for authentication

**Request Headers**:
```
Content-Type: application/json
Accept: application/json
```

**Request Body**:
```json
{
  "username": "user@example.com",
  "userVerification": "required|preferred|discouraged",
  "extensions": {
    "largeBlob": {
      "read": true,
      "write": true
    },
    "uvm": true,
    "credProps": true
  },
  "timeout": 60000,
  "allowCredentials": [
    {
      "type": "public-key",
      "id": "Y3JlZGVudGlhbC1pZC1iYXNlNjR1cmwtZW5jb2RlZA",
      "transports": ["internal", "usb", "nfc", "ble"]
    }
  ]
}
```

**Request Validation**:
- `username`: Optional, if provided must be valid
- `userVerification`: Optional, defaults to "preferred"
- `allowCredentials`: Optional, array of credential descriptors
- `timeout`: Optional, range 30000-300000 milliseconds

**Success Response (200 OK)**:
```json
{
  "status": "ok",
  "errorMessage": "",
  "challenge": "Y2hhbGxlbmdlLXZhbHVlLWJhc2U2NHVybC1lbmNvZGVk",
  "timeout": 60000,
  "rpId": "example.com",
  "allowCredentials": [
    {
      "type": "public-key",
      "id": "Y3JlZGVudGlhbC1pZC1iYXNlNjR1cmwtZW5jb2RlZA",
      "transports": ["internal", "usb", "nfc", "ble"]
    }
  ],
  "userVerification": "preferred",
  "extensions": {
    "largeBlob": {
      "read": true,
      "write": true
    },
    "uvm": true
  }
}
```

**Error Responses**:

400 Bad Request:
```json
{
  "status": "error",
  "errorMessage": "Invalid username format",
  "errorCode": "INVALID_USERNAME"
}
```

404 Not Found:
```json
{
  "status": "error",
  "errorMessage": "User not found",
  "errorCode": "USER_NOT_FOUND"
}
```

### 3.2 Assertion Result Endpoint

#### POST /webauthn/assertion/result

**Purpose**: Process assertion result and authenticate user

**Request Headers**:
```
Content-Type: application/json
Accept: application/json
```

**Request Body**:
```json
{
  "id": "Y3JlZGVudGlhbC1pZC1iYXNlNjR1cmwtZW5jb2RlZA",
  "rawId": "Y3JlZGVudGlhbC1pZC1iYXNlNjR1cmwtZW5jb2RlZA",
  "response": {
    "authenticatorData": "YXV0aGVudGljYXRvci1kYXRhLWJhc2U2NHVybC1lbmNvZGVk",
    "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoi...",
    "signature": "c2lnbmF0dXJlLWJhc2U2NHVybC1lbmNvZGVk",
    "userHandle": "dXNlci1oYW5kbGUtYmFzZTY0dXJsLWVuY29kZWQ="
  },
  "type": "public-key",
  "clientExtensionResults": {
    "largeBlob": {
      "blob": "bG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQ=",
      "written": true
    },
    "uvm": [
      [1, 1, 2],
      [2, 2, 1]
    ]
  }
}
```

**Request Validation**:
- `id`: Required, Base64URL encoded credential ID
- `rawId`: Required, must match `id`
- `response.authenticatorData`: Required, valid authenticator data
- `response.clientDataJSON`: Required, valid JSON with required fields
- `response.signature`: Required, valid signature
- `response.userHandle`: Optional, Base64URL encoded user handle

**Success Response (200 OK)**:
```json
{
  "status": "ok",
  "errorMessage": "",
  "credentialId": "Y3JlZGVudGlhbC1pZC1iYXNlNjR1cmwtZW5jb2RlZA",
  "authenticationTime": "2024-01-01T12:00:00Z",
  "signCount": 15,
  "userVerified": true,
  "userHandle": "dXNlci1oYW5kbGUtYmFzZTY0dXJsLWVuY29kZWQ=",
  "credential": {
    "id": "Y3JlZGVudGlhbC1pZC1iYXNlNjR1cmwtZW5jb2RlZA",
    "type": "public-key",
    "authenticator": {
      "displayName": "Platform Authenticator",
      "icon": "data:image/png;base64,..."
    }
  },
  "clientExtensionResults": {
    "largeBlob": {
      "blob": "bG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQ=",
      "written": true
    },
    "uvm": [
      [1, 1, 2],
      [2, 2, 1]
    ]
  }
}
```

**Error Responses**:

400 Bad Request:
```json
{
  "status": "error",
  "errorMessage": "Invalid signature",
  "errorCode": "INVALID_SIGNATURE"
}
```

401 Unauthorized:
```json
{
  "status": "error",
  "errorMessage": "Invalid challenge",
  "errorCode": "INVALID_CHALLENGE"
}
```

404 Not Found:
```json
{
  "status": "error",
  "errorMessage": "Credential not found",
  "errorCode": "CREDENTIAL_NOT_FOUND"
}
```

## 4. Management API

### 4.1 Credential Management

#### GET /webauthn/credentials

**Purpose**: List user's registered credentials

**Request Headers**:
```
Authorization: Bearer <token>
Accept: application/json
```

**Success Response (200 OK)**:
```json
{
  "status": "ok",
  "credentials": [
    {
      "id": "Y3JlZGVudGlhbC1pZC1iYXNlNjR1cmwtZW5jb2RlZA",
      "type": "public-key",
      "name": "My Security Key",
      "created_at": "2024-01-01T12:00:00Z",
      "last_used_at": "2024-01-01T15:30:00Z",
      "sign_count": 15,
      "is_backup_eligible": true,
      "is_backed_up": false,
      "transports": ["usb", "nfc"],
      "authenticator": {
        "aaguid": "00000000-0000-0000-0000-000000000000",
        "displayName": "YubiKey 5 NFC"
      }
    }
  ]
}
```

#### DELETE /webauthn/credentials/{credentialId}

**Purpose**: Delete a specific credential

**Request Headers**:
```
Authorization: Bearer <token>
Accept: application/json
```

**Success Response (200 OK)**:
```json
{
  "status": "ok",
  "message": "Credential deleted successfully"
}
```

### 4.2 User Management

#### GET /webauthn/users/{userId}

**Purpose**: Get user information

**Request Headers**:
```
Authorization: Bearer <token>
Accept: application/json
```

**Success Response (200 OK)**:
```json
{
  "status": "ok",
  "user": {
    "id": "dXNlci1pZC1iYXNlNjR1cmwtZW5jb2RlZA",
    "username": "user@example.com",
    "display_name": "John Doe",
    "created_at": "2024-01-01T12:00:00Z",
    "updated_at": "2024-01-01T12:00:00Z",
    "is_active": true,
    "credential_count": 3
  }
}
```

## 5. Health and Status API

### 5.1 Health Check

#### GET /webauthn/health

**Purpose**: Check service health status

**Success Response (200 OK)**:
```json
{
  "status": "healthy",
  "timestamp": "2024-01-01T12:00:00Z",
  "version": "1.0.0",
  "checks": {
    "database": "healthy",
    "webauthn": "healthy",
    "memory": "healthy"
  }
}
```

### 5.2 Service Info

#### GET /webauthn/info

**Purpose**: Get service information and capabilities

**Success Response (200 OK)**:
```json
{
  "version": "1.0.0",
  "webauthn_version": "FIDO2_1_2",
  "supported_algorithms": [
    { "alg": -7, "type": "public-key" },
    { "alg": -257, "type": "public-key" },
    { "alg": -37, "type": "public-key" },
    { "alg": -8, "type": "public-key" }
  ],
  "supported_attestation_formats": [
    "none",
    "packed",
    "fido-u2f",
    "android-key",
    "android-safetynet"
  ],
  "supported_extensions": [
    "credProps",
    "largeBlob",
    "minPinLength",
    "uvm"
  ],
  "rp": {
    "id": "example.com",
    "name": "Example Service"
  }
}
```

## 6. Error Codes Reference

### 6.1 Client Error Codes (4xx)

| Code | Description | HTTP Status |
|------|-------------|-------------|
| INVALID_REQUEST | Malformed request body | 400 |
| INVALID_USERNAME | Invalid username format | 400 |
| INVALID_DISPLAY_NAME | Invalid display name | 400 |
| INVALID_CHALLENGE | Invalid or expired challenge | 401 |
| INVALID_SIGNATURE | Invalid signature | 400 |
| INVALID_ATTESTATION | Invalid attestation object | 400 |
| INVALID_CREDENTIAL_ID | Invalid credential ID format | 400 |
| USER_NOT_FOUND | User does not exist | 404 |
| CREDENTIAL_NOT_FOUND | Credential does not exist | 404 |
| USER_EXISTS | User already exists | 409 |
| CREDENTIAL_EXISTS | Credential already registered | 409 |
| RATE_LIMIT_EXCEEDED | Too many requests | 429 |

### 6.2 Server Error Codes (5xx)

| Code | Description | HTTP Status |
|------|-------------|-------------|
| INTERNAL_ERROR | Internal server error | 500 |
| DATABASE_ERROR | Database operation failed | 500 |
| CRYPTOGRAPHIC_ERROR | Cryptographic operation failed | 500 |
| CHALLENGE_GENERATION_ERROR | Failed to generate challenge | 500 |
| CREDENTIAL_STORAGE_ERROR | Failed to store credential | 500 |

## 7. Security Considerations

### 7.1 Request Validation
- All JSON payloads validated against strict schemas
- Input length limits enforced
- Character set restrictions applied
- SQL injection prevention

### 7.2 Response Security
- No sensitive data in error messages
- Consistent error response format
- No information leakage in error codes
- Secure headers applied to all responses

### 7.3 Rate Limiting
- Per-IP rate limiting
- Per-user rate limiting
- Exponential backoff for repeated failures
- DDoS protection measures

### 7.4 Audit Logging
- All authentication attempts logged
- Credential registration/deletion logged
- Administrative actions logged
- Security events logged with timestamps

## 8. Testing Endpoints

### 8.1 Test Data Generation

#### POST /webauthn/test/generate-challenge
**Purpose**: Generate test challenge for testing
**Response**: Test challenge with known properties

#### POST /webauthn/test/validate-credential
**Purpose**: Validate credential format without storing
**Response**: Validation result with detailed errors

### 8.2 Compliance Testing

#### POST /webauthn/test/conformance
**Purpose**: Run FIDO2 conformance tests
**Response**: Detailed conformance test results

This API specification provides a comprehensive foundation for implementing a FIDO2/WebAuthn compliant server with full testability and security considerations.