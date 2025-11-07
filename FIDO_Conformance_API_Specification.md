# FIDO2 Conformance API Specification

## Overview

This document defines the API endpoints required for FIDO Alliance conformance testing, based on the FIDO2 Server Conformance Test API specification.

## Base URL Structure

```
https://your-server.com/fido2/attestation/
https://your-server.com/fido2/assertion/
```

## 1. Registration (Attestation) Endpoints

### 1.1 Begin Registration

**Endpoint:** `POST /fido2/attestation/options`

**Purpose:** Initiate registration ceremony by generating PublicKeyCredentialCreationOptions

**Request Body:**
```json
{
  "username": "string",
  "displayName": "string", 
  "authenticatorSelection": {
    "authenticatorAttachment": "platform|cross-platform",
    "userVerification": "required|preferred|discouraged",
    "residentKey": "required|preferred|discouraged",
    "requireResidentKey": boolean
  },
  "attestation": "none|indirect|direct|enterprise",
  "excludeCredentials": [
    {
      "type": "public-key",
      "id": "base64url_credential_id",
      "transports": ["usb", "nfc", "ble", "internal", "hybrid"]
    }
  ],
  "extensions": {
    "appid": "string",
    "credProps": boolean,
    "hmacCreateSecret": boolean,
    "minPinLength": boolean
  }
}
```

**Response (200 OK):**
```json
{
  "challenge": "base64url_string",
  "rp": {
    "id": "relying-party.com",
    "name": "Relying Party Name"
  },
  "user": {
    "id": "base64url_user_id",
    "name": "username@example.com", 
    "displayName": "User Display Name"
  },
  "pubKeyCredParams": [
    {"type": "public-key", "alg": -7},   // ES256
    {"type": "public-key", "alg": -257}, // RS256
    {"type": "public-key", "alg": -8},   // EdDSA
    {"type": "public-key", "alg": -37}   // PS256
  ],
  "timeout": 60000,
  "authenticatorSelection": {
    "authenticatorAttachment": "platform|cross-platform",
    "userVerification": "required|preferred|discouraged", 
    "residentKey": "required|preferred|discouraged",
    "requireResidentKey": boolean
  },
  "attestation": "none|indirect|direct|enterprise",
  "excludeCredentials": [],
  "extensions": {}
}
```

**Error Responses:**
```json
// 400 Bad Request
{
  "error": "invalid_request",
  "error_description": "Invalid username format"
}

// 429 Too Many Requests  
{
  "error": "rate_limit_exceeded",
  "error_description": "Too many registration attempts"
}

// 500 Internal Server Error
{
  "error": "server_error", 
  "error_description": "Internal server error"
}
```

### 1.2 Complete Registration

**Endpoint:** `POST /fido2/attestation/result`

**Purpose:** Complete registration ceremony by verifying the attestation response

**Request Body:**
```json
{
  "id": "base64url_credential_id",
  "rawId": "base64url_credential_id",
  "response": {
    "clientDataJSON": "base64url_client_data", 
    "attestationObject": "base64url_attestation_object",
    "transports": ["usb", "nfc", "ble", "internal", "hybrid"]
  },
  "type": "public-key",
  "clientExtensionResults": {
    "credProps": {
      "rk": boolean
    },
    "hmacCreateSecret": boolean
  }
}
```

**Response (200 OK):**
```json
{
  "status": "ok",
  "errorMessage": "",
  "credentialId": "base64url_credential_id",
  "attestationObject": "base64url_attestation_object",
  "clientDataJSON": "base64url_client_data"
}
```

**Error Responses:**
```json
// 400 Bad Request - Verification Failed
{
  "status": "failed",
  "errorMessage": "Attestation verification failed: invalid signature"
}

// 400 Bad Request - Invalid Challenge
{
  "status": "failed", 
  "errorMessage": "Challenge mismatch or expired"
}

// 400 Bad Request - Origin Mismatch
{
  "status": "failed",
  "errorMessage": "Origin validation failed"
}
```

## 2. Authentication (Assertion) Endpoints

### 2.1 Begin Authentication

**Endpoint:** `POST /fido2/assertion/options`

**Purpose:** Initiate authentication ceremony by generating PublicKeyCredentialRequestOptions

**Request Body:**
```json
{
  "username": "string",
  "userVerification": "required|preferred|discouraged",
  "extensions": {
    "appid": "string",
    "txAuthSimple": "string",
    "txAuthGeneric": {
      "contentType": "string",
      "content": "base64url"
    }
  }
}
```

**Response (200 OK):**
```json
{
  "challenge": "base64url_string",
  "timeout": 60000,
  "rpId": "relying-party.com", 
  "allowCredentials": [
    {
      "type": "public-key",
      "id": "base64url_credential_id",
      "transports": ["usb", "nfc", "ble", "internal", "hybrid"]
    }
  ],
  "userVerification": "required|preferred|discouraged",
  "extensions": {}
}
```

**Special Case - Discoverable Credentials (username omitted):**
```json
// Request with no username for resident key authentication
{}

// Response with empty allowCredentials
{
  "challenge": "base64url_string",
  "timeout": 60000,
  "rpId": "relying-party.com",
  "allowCredentials": [],
  "userVerification": "required|preferred|discouraged"
}
```

### 2.2 Complete Authentication

**Endpoint:** `POST /fido2/assertion/result`

**Purpose:** Complete authentication ceremony by verifying the assertion response

**Request Body:**
```json
{
  "id": "base64url_credential_id",
  "rawId": "base64url_credential_id", 
  "response": {
    "clientDataJSON": "base64url_client_data",
    "authenticatorData": "base64url_authenticator_data",
    "signature": "base64url_signature",
    "userHandle": "base64url_user_handle"
  },
  "type": "public-key",
  "clientExtensionResults": {}
}
```

**Response (200 OK):**
```json
{
  "status": "ok",
  "errorMessage": "",
  "credentialId": "base64url_credential_id",
  "userHandle": "base64url_user_handle",
  "signatureCounter": 42
}
```

**Error Responses:**
```json
// 400 Bad Request - Verification Failed
{
  "status": "failed",
  "errorMessage": "Assertion verification failed: invalid signature"
}

// 400 Bad Request - Counter Error
{
  "status": "failed",
  "errorMessage": "Signature counter decreased - possible cloned authenticator"
}

// 404 Not Found - Unknown Credential
{
  "status": "failed", 
  "errorMessage": "Credential not found"
}
```

## 3. Conformance Test Specific Endpoints

### 3.1 Metadata Endpoint

**Endpoint:** `GET /fido2/attestation/metadata`

**Purpose:** Provide server metadata for conformance testing

**Response:**
```json
{
  "versions": ["FIDO2_0", "FIDO2_1"],
  "extensions": [
    "appid",
    "credProps", 
    "hmac-secret",
    "minPinLength"
  ],
  "aaguidAcceptList": [
    "adce0002-35bc-c60a-648b-0b25f1f05503",
    "90a3ccdf-635c-4729-a248-9b92aae4976c"
  ],
  "attestationFormats": [
    "packed",
    "tpm", 
    "android-key",
    "android-safetynet",
    "fido-u2f",
    "none"
  ],
  "algorithms": [
    -7,   // ES256
    -257, // RS256  
    -8,   // EdDSA
    -37   // PS256
  ]
}
```

### 3.2 Reset Endpoint (Test Only)

**Endpoint:** `POST /fido2/test/reset`

**Purpose:** Reset server state for conformance testing

**Request Body:**
```json
{
  "username": "string"
}
```

**Response:**
```json
{
  "status": "ok",
  "message": "User data reset successfully"
}
```

## 4. Request/Response Validation Rules

### 4.1 Common Validation Rules

| Field | Validation Rule | Error Response |
|-------|----------------|----------------|
| `challenge` | 32+ bytes, base64url encoded | "Invalid challenge format" |
| `origin` | Must match RP ID | "Origin validation failed" |
| `username` | 1-255 chars, valid UTF-8 | "Invalid username" |
| `credentialId` | Base64url, 16+ bytes | "Invalid credential ID" |
| `signature` | Valid DER or raw format | "Invalid signature format" |

### 4.2 FIDO2 Specific Validations

#### Registration Validations
- [ ] **Attestation Object**: Valid CBOR structure
- [ ] **Client Data**: Valid JSON with required fields
- [ ] **Auth Data**: Proper structure with credential data
- [ ] **Public Key**: Supported algorithm and valid format
- [ ] **AAGUID**: Valid UUID format if present
- [ ] **Extensions**: Proper format for requested extensions

#### Authentication Validations  
- [ ] **Authenticator Data**: Valid structure and flags
- [ ] **Signature**: Verifies against stored public key
- [ ] **Counter**: Equal or greater than stored value
- [ ] **User Handle**: Matches stored user ID if present
- [ ] **Client Data**: Type="webauthn.get" and valid challenge

## 5. Error Handling Standards

### 5.1 HTTP Status Codes

| Status | Usage | Example |
|--------|-------|---------|
| `200` | Successful operation | Valid registration/authentication |
| `400` | Client error | Invalid request format, verification failure |
| `401` | Unauthorized | Invalid credentials |
| `404` | Not found | Unknown user/credential |
| `409` | Conflict | Credential already exists |
| `429` | Rate limited | Too many requests |
| `500` | Server error | Internal processing error |

### 5.2 Error Response Format

```json
{
  "status": "failed|error",
  "errorMessage": "Human readable error description",
  "errorCode": "machine_readable_error_code",
  "details": {
    "field": "additional_context",
    "expectedFormat": "description"
  },
  "timestamp": "2024-01-01T00:00:00Z"
}
```

## 6. Security Headers Requirements

### 6.1 Required Security Headers

```http
Content-Type: application/json
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'
Referrer-Policy: strict-origin-when-cross-origin
Cache-Control: no-store, no-cache, must-revalidate
```

### 6.2 CORS Configuration

```http
Access-Control-Allow-Origin: https://trusted-client.com
Access-Control-Allow-Methods: GET, POST, OPTIONS
Access-Control-Allow-Headers: Content-Type, Authorization
Access-Control-Allow-Credentials: true
Access-Control-Max-Age: 86400
```

## 7. Test Data Requirements

### 7.1 Test User Accounts

```json
{
  "testUsers": [
    {
      "username": "conformance-test-user-1",
      "displayName": "FIDO Conformance Test User 1",
      "id": "base64url_encoded_user_id"
    },
    {
      "username": "conformance-test-user-2", 
      "displayName": "FIDO Conformance Test User 2",
      "id": "base64url_encoded_user_id"
    }
  ]
}
```

### 7.2 Test Authenticator Data

```json
{
  "testAuthenticators": [
    {
      "aaguid": "adce0002-35bc-c60a-648b-0b25f1f05503",
      "description": "Security Key by Yubico",
      "transport": ["usb", "nfc"],
      "userVerification": "supported"
    },
    {
      "aaguid": "90a3ccdf-635c-4729-a248-9b92aae4976c",
      "description": "Touch ID",
      "transport": ["internal"],
      "userVerification": "required"
    }
  ]
}
```

## 8. Compliance Testing Checklist

### 8.1 Registration Flow Tests
- [ ] Valid registration with platform authenticator
- [ ] Valid registration with cross-platform authenticator  
- [ ] Registration with user verification required
- [ ] Registration with resident key required
- [ ] Registration with exclude credentials
- [ ] Invalid origin rejection
- [ ] Challenge replay rejection
- [ ] Malformed request rejection

### 8.2 Authentication Flow Tests
- [ ] Valid authentication with stored credential
- [ ] Authentication with user verification
- [ ] Authentication with resident key (discoverable)
- [ ] Authentication counter validation
- [ ] Invalid signature rejection
- [ ] Unknown credential rejection
- [ ] Challenge replay rejection

### 8.3 Security Tests
- [ ] Rate limiting enforcement
- [ ] Origin validation
- [ ] Challenge entropy verification
- [ ] Session management
- [ ] Error information disclosure prevention
- [ ] Input validation and sanitization

This specification ensures full compatibility with FIDO Alliance conformance testing tools while maintaining security best practices.