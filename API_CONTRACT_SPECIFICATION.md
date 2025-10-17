# FIDO2/WebAuthn Server - API Contract Specification

## Overview

This document defines the complete API contract for the FIDO2/WebAuthn Relying Party Server, aligned with FIDO Alliance conformance test requirements. All endpoints follow REST principles and include comprehensive error handling.

## 1. API Architecture

### 1.1 Base Configuration
```
Base URL: https://api.example.com
API Version: v1
Content-Type: application/json
Character Encoding: UTF-8
Transport Security: TLS 1.2+
```

### 1.2 Common Headers
```http
Content-Type: application/json
Accept: application/json
X-API-Version: 1.0
X-Request-ID: <uuid>
Authorization: Bearer <token> (for protected endpoints)
```

### 1.3 Common Response Format
```json
{
    "status": "ok|error",
    "message": "Human-readable message",
    "data": {
        // Response-specific data
    },
    "errors": [
        {
            "code": "ERROR_CODE",
            "message": "Error description",
            "field": "field_name" (optional)
        }
    ],
    "timestamp": "2024-01-01T00:00:00Z",
    "requestId": "uuid"
}
```

## 2. WebAuthn Registration API

### 2.1 Begin Registration

#### Endpoint
```http
POST /api/v1/webauthn/register/begin
```

#### Request Headers
```http
Content-Type: application/json
Accept: application/json
```

#### Request Body
```json
{
    "username": "user@example.com",
    "displayName": "User Display Name",
    "userVerification": "required|preferred|discouraged",
    "attestation": "none|direct|enterprise|indirect",
    "authenticatorSelection": {
        "authenticatorAttachment": "platform|cross-platform",
        "requireResidentKey": false,
        "userVerification": "required|preferred|discouraged",
        "residentKey": "required|preferred|discouraged"
    },
    "extensions": {
        "credProps": true,
        "largeBlob": {
            "support": "required|preferred"
        },
        "minPinLength": true,
        "uvm": true
    }
}
```

#### Request Validation
| Field | Type | Required | Validation |
|-------|------|----------|------------|
| username | string | Yes | Email format or 3-255 chars alphanumeric |
| displayName | string | Yes | 1-255 chars, no control characters |
| userVerification | string | No | Enum: required, preferred, discouraged |
| attestation | string | No | Enum: none, direct, enterprise, indirect |
| authenticatorSelection | object | No | Valid authenticator selection criteria |
| extensions | object | No | Valid WebAuthn extensions |

#### Success Response (200 OK)
```json
{
    "status": "ok",
    "message": "Registration challenge created",
    "data": {
        "challenge": "base64url-encoded-challenge",
        "user": {
            "id": "base64url-encoded-user-id",
            "name": "user@example.com",
            "displayName": "User Display Name"
        },
        "rp": {
            "id": "example.com",
            "name": "Example Application"
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
        "attestation": "none",
        "authenticatorSelection": {
            "authenticatorAttachment": "cross-platform",
            "requireResidentKey": false,
            "userVerification": "preferred",
            "residentKey": "preferred"
        },
        "extensions": {
            "credProps": true,
            "largeBlob": {
                "support": "preferred"
            }
        }
    },
    "timestamp": "2024-01-01T00:00:00Z",
    "requestId": "550e8400-e29b-41d4-a716-446655440000"
}
```

#### Error Responses

**400 Bad Request - Invalid Input**
```json
{
    "status": "error",
    "message": "Invalid request format",
    "errors": [
        {
            "code": "INVALID_USERNAME",
            "message": "Username must be a valid email or 3-255 alphanumeric characters",
            "field": "username"
        }
    ],
    "timestamp": "2024-01-01T00:00:00Z",
    "requestId": "550e8400-e29b-41d4-a716-446655440000"
}
```

**409 Conflict - User Exists**
```json
{
    "status": "error",
    "message": "User already exists",
    "errors": [
        {
            "code": "USER_EXISTS",
            "message": "A user with this username already exists",
            "field": "username"
        }
    ],
    "timestamp": "2024-01-01T00:00:00Z",
    "requestId": "550e8400-e29b-41d4-a716-446655440000"
}
```

**429 Too Many Requests**
```json
{
    "status": "error",
    "message": "Rate limit exceeded",
    "errors": [
        {
            "code": "RATE_LIMIT_EXCEEDED",
            "message": "Too many registration attempts. Please try again later."
        }
    ],
    "timestamp": "2024-01-01T00:00:00Z",
    "requestId": "550e8400-e29b-41d4-a716-446655440000"
}
```

### 2.2 Complete Registration

#### Endpoint
```http
POST /api/v1/webauthn/register/complete
```

#### Request Body
```json
{
    "username": "user@example.com",
    "credential": {
        "id": "base64url-encoded-credential-id",
        "rawId": "base64url-encoded-raw-id",
        "type": "public-key",
        "response": {
            "attestationObject": "base64url-encoded-attestation-object",
            "clientDataJSON": "base64url-encoded-client-data-json",
            "transports": ["usb", "nfc", "ble", "internal", "hybrid"]
        },
        "authenticatorAttachment": "platform|cross-platform",
        "clientExtensionResults": {
            "credProps": {
                "rk": true
            },
            "largeBlob": {
                "supported": true
            }
        }
    },
    "transports": ["usb", "nfc", "ble", "internal", "hybrid"],
    "clientExtensionResults": {
        "credProps": {
            "rk": true
        }
    }
}
```

#### Request Validation
| Field | Type | Required | Validation |
|-------|------|----------|------------|
| username | string | Yes | Must match existing user |
| credential | object | Yes | Valid WebAuthn credential |
| credential.id | string | Yes | Base64URL, max 1023 bytes |
| credential.type | string | Yes | Must be "public-key" |
| credential.response | object | Yes | Valid attestation response |
| transports | array | No | Valid transport values |

#### Success Response (200 OK)
```json
{
    "status": "ok",
    "message": "Registration completed successfully",
    "data": {
        "credentialId": "base64url-encoded-credential-id",
        "userId": "550e8400-e29b-41d4-a716-446655440000",
        "registeredAt": "2024-01-01T00:00:00Z",
        "aaguid": "550e8400-e29b-41d4-a716-446655440000",
        "signCount": 0,
        "backupEligible": true,
        "backupState": false,
        "transports": ["usb", "nfc", "ble", "internal"],
        "extensions": {
            "credProps": {
                "rk": true
            }
        }
    },
    "timestamp": "2024-01-01T00:00:00Z",
    "requestId": "550e8400-e29b-41d4-a716-446655440000"
}
```

#### Error Responses

**400 Bad Request - Invalid Credential**
```json
{
    "status": "error",
    "message": "Invalid credential format",
    "errors": [
        {
            "code": "INVALID_CREDENTIAL",
            "message": "Credential format is invalid or missing required fields",
            "field": "credential"
        }
    ],
    "timestamp": "2024-01-01T00:00:00Z",
    "requestId": "550e8400-e29b-41d4-a716-446655440000"
}
```

**401 Unauthorized - Invalid Attestation**
```json
{
    "status": "error",
    "message": "Invalid attestation",
    "errors": [
        {
            "code": "INVALID_ATTESTATION",
            "message": "Attestation verification failed"
        }
    ],
    "timestamp": "2024-01-01T00:00:00Z",
    "requestId": "550e8400-e29b-41d4-a716-446655440000"
}
```

**404 Not Found - User Not Found**
```json
{
    "status": "error",
    "message": "User not found",
    "errors": [
        {
            "code": "USER_NOT_FOUND",
            "message": "No user found with the provided username",
            "field": "username"
        }
    ],
    "timestamp": "2024-01-01T00:00:00Z",
    "requestId": "550e8400-e29b-41d4-a716-446655440000"
}
```

## 3. WebAuthn Authentication API

### 3.1 Begin Authentication

#### Endpoint
```http
POST /api/v1/webauthn/authenticate/begin
```

#### Request Body
```json
{
    "username": "user@example.com",
    "userVerification": "required|preferred|discouraged",
    "authenticatorSelection": {
        "authenticatorAttachment": "platform|cross-platform",
        "userVerification": "required|preferred|discouraged",
        "residentKey": "required|preferred|discouraged"
    },
    "extensions": {
        "largeBlob": {
            "read": true,
            "write": true
        },
        "uvm": true,
        "credProps": true
    }
}
```

#### Success Response (200 OK)
```json
{
    "status": "ok",
    "message": "Authentication challenge created",
    "data": {
        "challenge": "base64url-encoded-challenge",
        "allowCredentials": [
            {
                "type": "public-key",
                "id": "base64url-encoded-credential-id",
                "transports": ["usb", "nfc", "ble", "internal"]
            }
        ],
        "userVerification": "preferred",
        "timeout": 60000,
        "rpId": "example.com",
        "extensions": {
            "largeBlob": {
                "read": true,
                "write": true
            },
            "uvm": true
        }
    },
    "timestamp": "2024-01-01T00:00:00Z",
    "requestId": "550e8400-e29b-41d4-a716-446655440000"
}
```

#### Error Responses

**404 Not Found - User Not Found**
```json
{
    "status": "error",
    "message": "User not found",
    "errors": [
        {
            "code": "USER_NOT_FOUND",
            "message": "No user found with the provided username",
            "field": "username"
        }
    ],
    "timestamp": "2024-01-01T00:00:00Z",
    "requestId": "550e8400-e29b-41d4-a716-446655440000"
}
```

**404 Not Found - No Credentials**
```json
{
    "status": "error",
    "message": "No credentials found",
    "errors": [
        {
            "code": "NO_CREDENTIALS",
            "message": "User has no registered credentials"
        }
    ],
    "timestamp": "2024-01-01T00:00:00Z",
    "requestId": "550e8400-e29b-41d4-a716-446655440000"
}
```

### 3.2 Complete Authentication

#### Endpoint
```http
POST /api/v1/webauthn/authenticate/complete
```

#### Request Body
```json
{
    "username": "user@example.com",
    "credential": {
        "id": "base64url-encoded-credential-id",
        "rawId": "base64url-encoded-raw-id",
        "type": "public-key",
        "response": {
            "authenticatorData": "base64url-encoded-authenticator-data",
            "clientDataJSON": "base64url-encoded-client-data-json",
            "signature": "base64url-encoded-signature",
            "userHandle": "base64url-encoded-user-handle"
        },
        "authenticatorAttachment": "platform|cross-platform",
        "clientExtensionResults": {
            "largeBlob": {
                "blob": "base64url-encoded-blob-data",
                "written": true
            },
            "uvm": [
                [1, 1, 2],
                [2, 2, 3]
            ]
        }
    },
    "clientExtensionResults": {
        "largeBlob": {
            "blob": "base64url-encoded-blob-data",
            "written": true
        }
    }
}
```

#### Success Response (200 OK)
```json
{
    "status": "ok",
    "message": "Authentication successful",
    "data": {
        "authenticated": true,
        "userId": "550e8400-e29b-41d4-a716-446655440000",
        "credentialId": "base64url-encoded-credential-id",
        "authenticationTime": "2024-01-01T00:00:00Z",
        "userVerified": true,
        "authenticatorInfo": {
            "aaguid": "550e8400-e29b-41d4-a716-446655440000",
            "signCount": 42,
            "backupEligible": true,
            "backupState": true,
            "transports": ["usb", "nfc", "ble", "internal"]
        },
        "extensions": {
            "largeBlob": {
                "blob": "base64url-encoded-blob-data",
                "written": true
            },
            "uvm": [
                [1, 1, 2],
                [2, 2, 3]
            ]
        }
    },
    "timestamp": "2024-01-01T00:00:00Z",
    "requestId": "550e8400-e29b-41d4-a716-446655440000"
}
```

#### Error Responses

**400 Bad Request - Invalid Assertion**
```json
{
    "status": "error",
    "message": "Invalid assertion",
    "errors": [
        {
            "code": "INVALID_ASSERTION",
            "message": "Assertion format is invalid or missing required fields",
            "field": "credential"
        }
    ],
    "timestamp": "2024-01-01T00:00:00Z",
    "requestId": "550e8400-e29b-41d4-a716-446655440000"
}
```

**401 Unauthorized - Invalid Signature**
```json
{
    "status": "error",
    "message": "Invalid signature",
    "errors": [
        {
            "code": "INVALID_SIGNATURE",
            "message": "Signature verification failed"
        }
    ],
    "timestamp": "2024-01-01T00:00:00Z",
    "requestId": "550e8400-e29b-41d4-a716-446655440000"
}
```

**401 Unauthorized - Challenge Expired**
```json
{
    "status": "error",
    "message": "Challenge expired",
    "errors": [
        {
            "code": "CHALLENGE_EXPIRED",
            "message": "Authentication challenge has expired"
        }
    ],
    "timestamp": "2024-01-01T00:00:00Z",
    "requestId": "550e8400-e29b-41d4-a716-446655440000"
}
```

## 4. Credential Management API

### 4.1 List User Credentials

#### Endpoint
```http
GET /api/v1/users/{userId}/credentials
```

#### Success Response (200 OK)
```json
{
    "status": "ok",
    "message": "Credentials retrieved",
    "data": {
        "credentials": [
            {
                "credentialId": "base64url-encoded-credential-id",
                "type": "public-key",
                "name": "Security Key",
                "createdAt": "2024-01-01T00:00:00Z",
                "lastUsedAt": "2024-01-01T12:00:00Z",
                "backupEligible": true,
                "backupState": true,
                "transports": ["usb", "nfc", "ble"],
                "aaguid": "550e8400-e29b-41d4-a716-446655440000"
            }
        ],
        "total": 1
    },
    "timestamp": "2024-01-01T00:00:00Z",
    "requestId": "550e8400-e29b-41d4-a716-446655440000"
}
```

### 4.2 Delete Credential

#### Endpoint
```http
DELETE /api/v1/users/{userId}/credentials/{credentialId}
```

#### Success Response (200 OK)
```json
{
    "status": "ok",
    "message": "Credential deleted successfully",
    "data": {
        "credentialId": "base64url-encoded-credential-id",
        "deletedAt": "2024-01-01T00:00:00Z"
    },
    "timestamp": "2024-01-01T00:00:00Z",
    "requestId": "550e8400-e29b-41d4-a716-446655440000"
}
```

## 5. User Management API

### 5.1 Get User Info

#### Endpoint
```http
GET /api/v1/users/{userId}
```

#### Success Response (200 OK)
```json
{
    "status": "ok",
    "message": "User information retrieved",
    "data": {
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "username": "user@example.com",
        "displayName": "User Display Name",
        "createdAt": "2024-01-01T00:00:00Z",
        "updatedAt": "2024-01-01T00:00:00Z",
        "credentialCount": 2,
        "lastAuthentication": "2024-01-01T12:00:00Z"
    },
    "timestamp": "2024-01-01T00:00:00Z",
    "requestId": "550e8400-e29b-41d4-a716-446655440000"
}
```

### 5.2 Update User

#### Endpoint
```http
PUT /api/v1/users/{userId}
```

#### Request Body
```json
{
    "displayName": "Updated Display Name"
}
```

#### Success Response (200 OK)
```json
{
    "status": "ok",
    "message": "User updated successfully",
    "data": {
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "username": "user@example.com",
        "displayName": "Updated Display Name",
        "updatedAt": "2024-01-01T00:00:00Z"
    },
    "timestamp": "2024-01-01T00:00:00Z",
    "requestId": "550e8400-e29b-41d4-a716-446655440000"
}
```

## 6. Health and Status API

### 6.1 Health Check

#### Endpoint
```http
GET /api/v1/health
```

#### Success Response (200 OK)
```json
{
    "status": "ok",
    "message": "Service is healthy",
    "data": {
        "status": "healthy",
        "timestamp": "2024-01-01T00:00:00Z",
        "version": "1.0.0",
        "uptime": 3600,
        "checks": {
            "database": "healthy",
            "redis": "healthy",
            "webauthn": "healthy"
        }
    },
    "timestamp": "2024-01-01T00:00:00Z",
    "requestId": "550e8400-e29b-41d4-a716-446655440000"
}
```

### 6.2 Service Info

#### Endpoint
```http
GET /api/v1/info
```

#### Success Response (200 OK)
```json
{
    "status": "ok",
    "message": "Service information",
    "data": {
        "name": "FIDO2 WebAuthn Server",
        "version": "1.0.0",
        "description": "FIDO2/WebAuthn Relying Party Server",
        "webauthnVersion": "FIDO2_1_2",
        "supportedAlgorithms": [
            {"alg": -7, "name": "ES256"},
            {"alg": -257, "name": "RS256"},
            {"alg": -37, "name": "PS256"},
            {"alg": -8, "name": "EdDSA"}
        ],
        "supportedExtensions": [
            "credProps",
            "largeBlob",
            "minPinLength",
            "uvm"
        ],
        "rp": {
            "id": "example.com",
            "name": "Example Application"
        }
    },
    "timestamp": "2024-01-01T00:00:00Z",
    "requestId": "550e8400-e29b-41d4-a716-446655440000"
}
```

## 7. Error Code Reference

### 7.1 Client Errors (4xx)

| Code | HTTP Status | Description |
|------|-------------|-------------|
| INVALID_REQUEST | 400 | Request format is invalid |
| INVALID_USERNAME | 400 | Username format is invalid |
| INVALID_DISPLAY_NAME | 400 | Display name format is invalid |
| INVALID_CREDENTIAL | 400 | Credential format is invalid |
| INVALID_ASSERTION | 400 | Assertion format is invalid |
| INVALID_USER_VERIFICATION | 400 | User verification value is invalid |
| INVALID_ATTESTATION | 400 | Attestation format is invalid |
| MISSING_REQUIRED_FIELD | 400 | Required field is missing |
| USER_EXISTS | 409 | User already exists |
| CREDENTIAL_EXISTS | 409 | Credential already exists |
| USER_NOT_FOUND | 404 | User not found |
| CREDENTIAL_NOT_FOUND | 404 | Credential not found |
| NO_CREDENTIALS | 404 | User has no credentials |
| CHALLENGE_NOT_FOUND | 404 | Challenge not found |
| CHALLENGE_EXPIRED | 401 | Challenge has expired |
| INVALID_SIGNATURE | 401 | Signature verification failed |
| INVALID_ORIGIN | 401 | Origin validation failed |
| INVALID_RP_ID | 401 | RP ID validation failed |
| USER_NOT_VERIFIED | 401 | User verification failed |
| RATE_LIMIT_EXCEEDED | 429 | Rate limit exceeded |

### 7.2 Server Errors (5xx)

| Code | HTTP Status | Description |
|------|-------------|-------------|
| INTERNAL_ERROR | 500 | Internal server error |
| DATABASE_ERROR | 500 | Database operation failed |
| CRYPTO_ERROR | 500 | Cryptographic operation failed |
| CONFIGURATION_ERROR | 500 | Configuration error |
| SERVICE_UNAVAILABLE | 503 | Service temporarily unavailable |

## 8. Rate Limiting

### 8.1 Rate Limit Rules
- Registration: 5 requests per minute per IP
- Authentication: 20 requests per minute per user
- Credential management: 10 requests per minute per user
- General API: 100 requests per minute per IP

### 8.2 Rate Limit Headers
```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1640995200
```

### 8.3 Rate Limit Response (429)
```json
{
    "status": "error",
    "message": "Rate limit exceeded",
    "errors": [
        {
            "code": "RATE_LIMIT_EXCEEDED",
            "message": "Too many requests. Try again in 60 seconds."
        }
    ],
    "timestamp": "2024-01-01T00:00:00Z",
    "requestId": "550e8400-e29b-41d4-a716-446655440000"
}
```

## 9. Security Headers

### 9.1 Required Security Headers
```http
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'self'
Referrer-Policy: strict-origin-when-cross-origin
```

## 10. API Versioning

### 10.1 Version Strategy
- URL path versioning: `/api/v1/`
- Backward compatibility maintained for at least 2 versions
- Deprecation notices sent 6 months before removal
- Version negotiation via `Accept` header

### 10.2 Version Response Headers
```http
API-Version: 1.0
Supported-Versions: 1.0, 1.1
Deprecated-Versions: 
```

This API contract specification provides a comprehensive foundation for implementing the FIDO2/WebAuthn server with full compliance to FIDO Alliance requirements and modern API best practices.