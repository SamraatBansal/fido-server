# FIDO2/WebAuthn Server - API Specification

## Overview

This API specification defines the REST endpoints for the FIDO2/WebAuthn Relying Party Server, aligned with FIDO Alliance conformance test requirements and WebAuthn specification.

## 1. API Architecture

### 1.1 Base Configuration
- **Base URL**: `https://rp.example.com`
- **API Version**: `v1`
- **Content-Type**: `application/json`
- **Character Encoding**: UTF-8
- **Authentication**: Bearer tokens for admin operations

### 1.2 Response Format
All responses follow a consistent structure:
```json
{
  "status": "ok|error",
  "errorMessage": "string",
  "data": {}
}
```

### 1.3 Error Handling
HTTP Status Codes:
- `200 OK`: Successful operation
- `400 Bad Request`: Invalid request parameters
- `401 Unauthorized`: Authentication required
- `403 Forbidden`: Insufficient permissions
- `404 Not Found`: Resource not found
- `409 Conflict`: Resource conflict (e.g., duplicate)
- `422 Unprocessable Entity`: Validation failed
- `429 Too Many Requests`: Rate limit exceeded
- `500 Internal Server Error`: Server error

## 2. WebAuthn API Endpoints

### 2.1 Registration (Attestation) Endpoints

#### POST /webauthn/register/begin
Initiates the registration ceremony by generating attestation options.

**Request Body:**
```json
{
  "username": "string",
  "displayName": "string",
  "id": "base64url-string",
  "authenticatorSelection": {
    "authenticatorAttachment": "platform|cross-platform",
    "requireResidentKey": false,
    "userVerification": "required|preferred|discouraged",
    "residentKey": "required|preferred|discouraged"
  },
  "attestation": "none|direct|enterprise|indirect",
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

**Response (200 OK):**
```json
{
  "status": "ok",
  "errorMessage": "",
  "challenge": "base64url-string",
  "rp": {
    "name": "FIDO Test Server",
    "id": "rp.example.com"
  },
  "user": {
    "id": "base64url-string",
    "name": "user@example.com",
    "displayName": "Test User"
  },
  "pubKeyCredParams": [
    {
      "type": "public-key",
      "alg": -7
    },
    {
      "type": "public-key",
      "alg": -257
    }
  ],
  "timeout": 60000,
  "excludeCredentials": [
    {
      "type": "public-key",
      "id": "base64url-string",
      "transports": ["usb", "nfc", "ble", "internal", "hybrid"]
    }
  ],
  "authenticatorSelection": {
    "authenticatorAttachment": "platform|cross-platform",
    "requireResidentKey": false,
    "userVerification": "required|preferred|discouraged",
    "residentKey": "required|preferred|discouraged"
  },
  "attestation": "none|direct|enterprise|indirect",
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

**Error Response (400 Bad Request):**
```json
{
  "status": "error",
  "errorMessage": "Invalid username format",
  "errorCode": "INVALID_USERNAME"
}
```

#### POST /webauthn/register/complete
Completes the registration ceremony by processing the attestation response.

**Request Body:**
```json
{
  "id": "base64url-string",
  "rawId": "base64url-string",
  "type": "public-key",
  "response": {
    "attestationObject": "base64url-string",
    "clientDataJSON": "base64url-string",
    "transports": ["usb", "nfc", "ble", "internal", "hybrid"]
  },
  "clientExtensionResults": {
    "credProps": {
      "rk": true
    },
    "largeBlob": {
      "supported": true
    },
    "minPinLength": true,
    "uvm": [
      [1, 1, 1]
    ]
  }
}
```

**Response (200 OK):**
```json
{
  "status": "ok",
  "errorMessage": "",
  "credentialId": "base64url-string",
  "newUser": false,
  "publicKey": "base64url-string",
  "signCount": 0,
  "aaguid": "base64url-string",
  "userVerified": true,
  "backupEligible": false,
  "backupState": false,
  "transports": ["usb", "nfc", "ble", "internal", "hybrid"],
  "extensions": {
    "credProps": {
      "rk": true
    },
    "largeBlob": {
      "supported": true
    },
    "minPinLength": true,
    "uvm": [
      [1, 1, 1]
    ]
  }
}
```

**Error Response (422 Unprocessable Entity):**
```json
{
  "status": "error",
  "errorMessage": "Invalid attestation format",
  "errorCode": "INVALID_ATTESTATION"
}
```

### 2.2 Authentication (Assertion) Endpoints

#### POST /webauthn/authenticate/begin
Initiates the authentication ceremony by generating assertion options.

**Request Body:**
```json
{
  "username": "string",
  "userVerification": "required|preferred|discouraged",
  "allowCredentials": [
    {
      "type": "public-key",
      "id": "base64url-string",
      "transports": ["usb", "nfc", "ble", "internal", "hybrid"]
    }
  ],
  "extensions": {
    "largeBlob": {
      "read": true,
      "write": true
    },
    "uvm": true
  },
  "timeout": 60000
}
```

**Response (200 OK):**
```json
{
  "status": "ok",
  "errorMessage": "",
  "challenge": "base64url-string",
  "allowCredentials": [
    {
      "type": "public-key",
      "id": "base64url-string",
      "transports": ["usb", "nfc", "ble", "internal", "hybrid"]
    }
  ],
  "userVerification": "required|preferred|discouraged",
  "rpId": "rp.example.com",
  "timeout": 60000,
  "extensions": {
    "largeBlob": {
      "read": true,
      "write": true
    },
    "uvm": true
  }
}
```

#### POST /webauthn/authenticate/complete
Completes the authentication ceremony by processing the assertion response.

**Request Body:**
```json
{
  "id": "base64url-string",
  "rawId": "base64url-string",
  "type": "public-key",
  "response": {
    "authenticatorData": "base64url-string",
    "clientDataJSON": "base64url-string",
    "signature": "base64url-string",
    "userHandle": "base64url-string"
  },
  "clientExtensionResults": {
    "largeBlob": {
      "blob": "base64url-string",
      "written": true
    },
    "uvm": [
      [1, 1, 1]
    ]
  }
}
```

**Response (200 OK):**
```json
{
  "status": "ok",
  "errorMessage": "",
  "credentialId": "base64url-string",
  "user": {
    "id": "base64url-string",
    "name": "user@example.com",
    "displayName": "Test User"
  },
  "signCount": 12345,
  "userVerified": true,
  "backupEligible": false,
  "backupState": false,
  "extensions": {
    "largeBlob": {
      "blob": "base64url-string",
      "written": true
    },
    "uvm": [
      [1, 1, 1]
    ]
  }
}
```

## 3. User Management API

### 3.1 User Creation

#### POST /users
Creates a new user account.

**Request Body:**
```json
{
  "username": "string",
  "displayName": "string",
  "id": "base64url-string"
}
```

**Response (201 Created):**
```json
{
  "status": "ok",
  "errorMessage": "",
  "user": {
    "id": "base64url-string",
    "username": "user@example.com",
    "displayName": "Test User",
    "createdAt": "2024-01-01T00:00:00Z",
    "updatedAt": "2024-01-01T00:00:00Z",
    "isActive": true
  }
}
```

### 3.2 User Retrieval

#### GET /users/{userId}
Retrieves user information.

**Response (200 OK):**
```json
{
  "status": "ok",
  "errorMessage": "",
  "user": {
    "id": "base64url-string",
    "username": "user@example.com",
    "displayName": "Test User",
    "createdAt": "2024-01-01T00:00:00Z",
    "updatedAt": "2024-01-01T00:00:00Z",
    "isActive": true,
    "credentials": [
      {
        "id": "base64url-string",
        "type": "public-key",
        "createdAt": "2024-01-01T00:00:00Z",
        "lastUsedAt": "2024-01-01T12:00:00Z",
        "transports": ["usb", "nfc", "ble", "internal"],
        "backupEligible": false,
        "backupState": false
      }
    ]
  }
}
```

### 3.3 User Update

#### PUT /users/{userId}
Updates user information.

**Request Body:**
```json
{
  "displayName": "string",
  "isActive": true
}
```

**Response (200 OK):**
```json
{
  "status": "ok",
  "errorMessage": "",
  "user": {
    "id": "base64url-string",
    "username": "user@example.com",
    "displayName": "Updated Test User",
    "createdAt": "2024-01-01T00:00:00Z",
    "updatedAt": "2024-01-01T12:00:00Z",
    "isActive": true
  }
}
```

### 3.4 User Deletion

#### DELETE /users/{userId}
Deletes a user and all associated credentials.

**Response (204 No Content):**
```json
{}
```

## 4. Credential Management API

### 4.1 Credential Listing

#### GET /users/{userId}/credentials
Lists all credentials for a user.

**Response (200 OK):**
```json
{
  "status": "ok",
  "errorMessage": "",
  "credentials": [
    {
      "id": "base64url-string",
      "type": "public-key",
      "createdAt": "2024-01-01T00:00:00Z",
      "lastUsedAt": "2024-01-01T12:00:00Z",
      "transports": ["usb", "nfc", "ble", "internal"],
      "backupEligible": false,
      "backupState": false,
      "aaguid": "base64url-string",
      "signCount": 12345,
      "userVerified": true,
      "isActive": true
    }
  ]
}
```

### 4.2 Credential Deletion

#### DELETE /users/{userId}/credentials/{credentialId}
Deletes a specific credential.

**Response (204 No Content):**
```json
{}
```

### 4.3 Credential Update

#### PUT /users/{userId}/credentials/{credentialId}
Updates credential metadata.

**Request Body:**
```json
{
  "isActive": false,
  "nickname": "string"
}
```

**Response (200 OK):**
```json
{
  "status": "ok",
  "errorMessage": "",
  "credential": {
    "id": "base64url-string",
    "type": "public-key",
    "createdAt": "2024-01-01T00:00:00Z",
    "lastUsedAt": "2024-01-01T12:00:00Z",
    "transports": ["usb", "nfc", "ble", "internal"],
    "backupEligible": false,
    "backupState": false,
    "aaguid": "base64url-string",
    "signCount": 12345,
    "userVerified": true,
    "isActive": false,
    "nickname": "My Security Key"
  }
}
```

## 5. Server Configuration API

### 5.1 Server Information

#### GET /info
Retrieves server configuration and capabilities.

**Response (200 OK):**
```json
{
  "status": "ok",
  "errorMessage": "",
  "info": {
    "version": "1.0.0",
    "rp": {
      "name": "FIDO Test Server",
      "id": "rp.example.com",
      "origins": ["https://rp.example.com"]
    },
    "algorithms": [
      {
        "alg": -7,
        "type": "public-key"
      },
      {
        "alg": -257,
        "type": "public-key"
      }
    ],
    "attestationFormats": ["none", "packed", "fido-u2f"],
    "extensions": {
      "credProps": true,
      "largeBlob": true,
      "minPinLength": true,
      "uvm": true
    },
    "userVerification": ["required", "preferred", "discouraged"],
    "authenticatorAttachment": ["platform", "cross-platform"],
    "residentKey": ["required", "preferred", "discouraged"],
    "transports": ["usb", "nfc", "ble", "internal", "hybrid"]
  }
}
```

### 5.2 Health Check

#### GET /health
Performs health check on server components.

**Response (200 OK):**
```json
{
  "status": "ok",
  "errorMessage": "",
  "health": {
    "status": "healthy",
    "timestamp": "2024-01-01T12:00:00Z",
    "uptime": 3600,
    "database": {
      "status": "healthy",
      "connectionPool": {
        "active": 5,
        "idle": 15,
        "max": 20
      }
    },
    "memory": {
      "used": "256MB",
      "available": "768MB"
    },
    "version": "1.0.0"
  }
}
```

## 6. FIDO Conformance Test API

### 6.1 Test Configuration

#### POST /conformance/configure
Configures the server for FIDO conformance testing.

**Request Body:**
```json
{
  "rp": {
    "name": "FIDO Conformance Test RP",
    "id": "localhost"
  },
  "origins": ["https://localhost:8443"],
  "attestation": "direct",
  "userVerification": "required",
  "extensions": {
    "credProps": true,
    "largeBlob": true,
    "minPinLength": true,
    "uvm": true
  }
}
```

**Response (200 OK):**
```json
{
  "status": "ok",
  "errorMessage": "",
  "configured": true
}
```

### 6.2 Test Data Management

#### POST /conformance/reset
Resets all test data for conformance testing.

**Response (200 OK):**
```json
{
  "status": "ok",
  "errorMessage": "",
  "reset": true
}
```

#### GET /conformance/users
Lists all test users for conformance testing.

**Response (200 OK):**
```json
{
  "status": "ok",
  "errorMessage": "",
  "users": [
    {
      "id": "base64url-string",
      "name": "testuser1",
      "displayName": "Test User 1",
      "credentials": [
        {
          "id": "base64url-string",
          "type": "public-key"
        }
      ]
    }
  ]
}
```

## 7. Security Headers and CORS

### 7.1 Security Headers
All responses include the following security headers:
```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'
Referrer-Policy: strict-origin-when-cross-origin
```

### 7.2 CORS Configuration
```
Access-Control-Allow-Origin: https://rp.example.com
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
Access-Control-Allow-Headers: Content-Type, Authorization
Access-Control-Allow-Credentials: true
Access-Control-Max-Age: 86400
```

## 8. Rate Limiting

### 8.1 Rate Limit Configuration
- **Registration endpoints**: 5 requests per minute per IP
- **Authentication endpoints**: 20 requests per minute per IP
- **User management**: 10 requests per minute per user
- **Admin endpoints**: 100 requests per minute per admin

### 8.2 Rate Limit Response
```json
{
  "status": "error",
  "errorMessage": "Rate limit exceeded",
  "errorCode": "RATE_LIMIT_EXCEEDED",
  "retryAfter": 60
}
```

## 9. Request Validation

### 9.1 Input Validation Rules
- **Username**: 3-64 characters, alphanumeric + @._-
- **Display Name**: 1-128 characters, UTF-8
- **User ID**: Base64URL encoded, 1-64 bytes when decoded
- **Challenge**: Base64URL encoded, minimum 16 bytes when decoded
- **Credential ID**: Base64URL encoded, maximum 1023 bytes when decoded

### 9.2 JSON Schema Validation
All request bodies are validated against JSON schemas:
```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": {
    "username": {
      "type": "string",
      "minLength": 3,
      "maxLength": 64,
      "pattern": "^[a-zA-Z0-9@._-]+$"
    },
    "displayName": {
      "type": "string",
      "minLength": 1,
      "maxLength": 128
    }
  },
  "required": ["username", "displayName"]
}
```

## 10. Error Codes Reference

### 10.1 Client Error Codes
- `INVALID_REQUEST`: Malformed request
- `INVALID_USERNAME`: Invalid username format
- `INVALID_DISPLAY_NAME`: Invalid display name
- `INVALID_USER_ID`: Invalid user ID format
- `INVALID_CHALLENGE`: Invalid challenge format
- `INVALID_CREDENTIAL_ID`: Invalid credential ID format
- `INVALID_ATTESTATION`: Invalid attestation data
- `INVALID_ASSERTION`: Invalid assertion data
- `CHALLENGE_EXPIRED`: Challenge has expired
- `CHALLENGE_USED`: Challenge already used
- `CREDENTIAL_NOT_FOUND`: Credential does not exist
- `USER_NOT_FOUND`: User does not exist
- `DUPLICATE_USERNAME`: Username already exists
- `DUPLICATE_CREDENTIAL`: Credential ID already exists
- `UNSUPPORTED_ALGORITHM`: Unsupported cryptographic algorithm
- `UNSUPPORTED_ATTESTATION`: Unsupported attestation format

### 10.2 Server Error Codes
- `INTERNAL_ERROR`: Internal server error
- `DATABASE_ERROR`: Database operation failed
- `CRYPTOGRAPHIC_ERROR`: Cryptographic operation failed
- `CONFIGURATION_ERROR`: Server configuration error
- `DEPENDENCY_ERROR`: External dependency error

This API specification provides a comprehensive interface for FIDO2/WebAuthn operations, ensuring compliance with FIDO Alliance standards and supporting extensive testing scenarios.