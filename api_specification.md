# FIDO Server3 - API Specification

## Overview
This document defines the REST API specification for FIDO Server3, based on the FIDO Alliance Conformance Test API requirements and WebAuthn specifications.

Reference: [FIDO2 Server Conformance Test API](https://github.com/fido-alliance/conformance-test-tools-resources/blob/main/docs/FIDO2/Server/Conformance-Test-API.md)

---

## Base Configuration

**Base URL**: `https://your-domain.com/api/v1`  
**Content-Type**: `application/json`  
**Authentication**: Bearer token (for management endpoints)  
**TLS**: Required (TLS 1.2+)

---

## 1. Registration (Attestation) Endpoints

### 1.1 Begin Registration

**Endpoint**: `POST /webauthn/register/begin`

**Description**: Initiates the WebAuthn registration process by generating a challenge and returning PublicKeyCredentialCreationOptions.

#### Request Body
```json
{
  "username": "user@example.com",
  "displayName": "John Doe",
  "userVerification": "preferred",
  "authenticatorSelection": {
    "authenticatorAttachment": "platform",
    "userVerification": "preferred",
    "residentKey": "preferred",
    "requireResidentKey": false
  },
  "attestation": "direct",
  "excludeCredentials": [
    {
      "type": "public-key",
      "id": "base64url-encoded-credential-id"
    }
  ]
}
```

#### Response (200 OK)
```json
{
  "status": "ok",
  "errorMessage": "",
  "publicKey": {
    "challenge": "base64url-encoded-challenge",
    "rp": {
      "name": "FIDO Server3",
      "id": "example.com"
    },
    "user": {
      "id": "base64url-encoded-user-id",
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
        "alg": -8
      }
    ],
    "timeout": 60000,
    "excludeCredentials": [
      {
        "type": "public-key",
        "id": "base64url-encoded-credential-id",
        "transports": ["usb", "nfc", "ble", "internal"]
      }
    ],
    "authenticatorSelection": {
      "authenticatorAttachment": "platform",
      "userVerification": "preferred",
      "residentKey": "preferred",
      "requireResidentKey": false
    },
    "attestation": "direct",
    "extensions": {
      "credProps": true,
      "hmacCreateSecret": true
    }
  }
}
```

#### Error Response (400 Bad Request)
```json
{
  "status": "failed",
  "errorMessage": "Invalid username format"
}
```

### 1.2 Complete Registration

**Endpoint**: `POST /webauthn/register/complete`

**Description**: Completes the WebAuthn registration process by verifying the attestation response.

#### Request Body
```json
{
  "id": "base64url-encoded-credential-id",
  "rawId": "base64url-encoded-credential-id",
  "type": "public-key",
  "response": {
    "clientDataJSON": "base64url-encoded-client-data",
    "attestationObject": "base64url-encoded-attestation-object",
    "transports": ["usb", "nfc", "ble", "internal"]
  },
  "clientExtensionResults": {
    "credProps": {
      "rk": true
    }
  }
}
```

#### Response (200 OK)
```json
{
  "status": "ok",
  "errorMessage": "",
  "verified": true,
  "registrationInfo": {
    "credentialID": "base64url-encoded-credential-id",
    "credentialPublicKey": "base64url-encoded-public-key",
    "counter": 0,
    "aaguid": "00000000-0000-0000-0000-000000000000",
    "fmt": "packed",
    "credentialDeviceType": "singleDevice",
    "credentialBackedUp": false
  }
}
```

#### Error Response (400 Bad Request)
```json
{
  "status": "failed",
  "errorMessage": "Attestation verification failed",
  "verified": false
}
```

---

## 2. Authentication (Assertion) Endpoints

### 2.1 Begin Authentication

**Endpoint**: `POST /webauthn/authenticate/begin`

**Description**: Initiates the WebAuthn authentication process by generating a challenge and returning PublicKeyCredentialRequestOptions.

#### Request Body
```json
{
  "username": "user@example.com",
  "userVerification": "preferred"
}
```

#### Response (200 OK)
```json
{
  "status": "ok",
  "errorMessage": "",
  "publicKey": {
    "challenge": "base64url-encoded-challenge",
    "timeout": 60000,
    "rpId": "example.com",
    "allowCredentials": [
      {
        "type": "public-key",
        "id": "base64url-encoded-credential-id",
        "transports": ["usb", "nfc", "ble", "internal"]
      }
    ],
    "userVerification": "preferred",
    "extensions": {
      "appid": "https://example.com/app-id.json"
    }
  }
}
```

#### Error Response (404 Not Found)
```json
{
  "status": "failed",
  "errorMessage": "User not found"
}
```

### 2.2 Complete Authentication

**Endpoint**: `POST /webauthn/authenticate/complete`

**Description**: Completes the WebAuthn authentication process by verifying the assertion response.

#### Request Body
```json
{
  "id": "base64url-encoded-credential-id",
  "rawId": "base64url-encoded-credential-id",
  "type": "public-key",
  "response": {
    "clientDataJSON": "base64url-encoded-client-data",
    "authenticatorData": "base64url-encoded-authenticator-data",
    "signature": "base64url-encoded-signature",
    "userHandle": "base64url-encoded-user-handle"
  },
  "clientExtensionResults": {}
}
```

#### Response (200 OK)
```json
{
  "status": "ok",
  "errorMessage": "",
  "verified": true,
  "authenticationInfo": {
    "credentialID": "base64url-encoded-credential-id",
    "newCounter": 1,
    "userVerified": true,
    "credentialDeviceType": "singleDevice",
    "credentialBackedUp": false
  }
}
```

#### Error Response (401 Unauthorized)
```json
{
  "status": "failed",
  "errorMessage": "Authentication verification failed",
  "verified": false
}
```

---

## 3. User Management Endpoints

### 3.1 Register User

**Endpoint**: `POST /users/register`

**Description**: Creates a new user account in the system.

#### Request Body
```json
{
  "username": "user@example.com",
  "displayName": "John Doe"
}
```

#### Response (201 Created)
```json
{
  "status": "ok",
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "username": "user@example.com",
    "displayName": "John Doe",
    "userHandle": "base64url-encoded-user-handle",
    "createdAt": "2024-01-15T10:30:00Z"
  }
}
```

### 3.2 Get User

**Endpoint**: `GET /users/{userId}`

**Description**: Retrieves user information by user ID.

#### Response (200 OK)
```json
{
  "status": "ok",
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "username": "user@example.com",
    "displayName": "John Doe",
    "userHandle": "base64url-encoded-user-handle",
    "createdAt": "2024-01-15T10:30:00Z",
    "credentialCount": 2
  }
}
```

---

## 4. Credential Management Endpoints

### 4.1 List User Credentials

**Endpoint**: `GET /webauthn/credentials/{userId}`

**Description**: Retrieves all credentials associated with a user.

#### Response (200 OK)
```json
{
  "status": "ok",
  "credentials": [
    {
      "id": "base64url-encoded-credential-id",
      "publicKey": "base64url-encoded-public-key",
      "signCount": 5,
      "aaguid": "00000000-0000-0000-0000-000000000000",
      "fmt": "packed",
      "createdAt": "2024-01-15T10:30:00Z",
      "lastUsedAt": "2024-01-16T14:22:00Z",
      "transports": ["usb", "nfc"]
    }
  ]
}
```

### 4.2 Delete Credential

**Endpoint**: `DELETE /webauthn/credentials/{credentialId}`

**Description**: Removes a specific credential from the system.

#### Response (200 OK)
```json
{
  "status": "ok",
  "message": "Credential deleted successfully"
}
```

---

## 5. System Information Endpoints

### 5.1 Server Information

**Endpoint**: `GET /info`

**Description**: Returns server configuration and capabilities.

#### Response (200 OK)
```json
{
  "status": "ok",
  "serverInfo": {
    "name": "FIDO Server3",
    "version": "1.0.0",
    "fido2Compliant": true,
    "supportedAlgorithms": [-7, -257, -8],
    "supportedAttestationFormats": ["packed", "tpm", "android-key", "android-safetynet", "fido-u2f", "none"],
    "maxTimeout": 300000,
    "rpId": "example.com",
    "rpName": "FIDO Server3"
  }
}
```

### 5.2 Health Check

**Endpoint**: `GET /health`

**Description**: Returns server health status.

#### Response (200 OK)
```json
{
  "status": "healthy",
  "timestamp": "2024-01-16T15:30:00Z",
  "database": "connected",
  "memory": "normal"
}
```

---

## 6. Error Handling

### Standard Error Response Format
```json
{
  "status": "failed",
  "errorMessage": "Human-readable error description",
  "errorCode": "ERROR_CODE",
  "timestamp": "2024-01-16T15:30:00Z"
}
```

### HTTP Status Codes
- `200 OK`: Successful operation
- `201 Created`: Resource created successfully
- `400 Bad Request`: Invalid request data
- `401 Unauthorized`: Authentication required
- `403 Forbidden`: Insufficient permissions
- `404 Not Found`: Resource not found
- `409 Conflict`: Resource already exists
- `422 Unprocessable Entity`: Validation failed
- `500 Internal Server Error`: Server error

### Error Codes
- `INVALID_REQUEST`: Malformed request data
- `USER_NOT_FOUND`: User does not exist
- `CREDENTIAL_NOT_FOUND`: Credential does not exist
- `CHALLENGE_EXPIRED`: Challenge has expired
- `VERIFICATION_FAILED`: Cryptographic verification failed
- `DUPLICATE_CREDENTIAL`: Credential already exists
- `INVALID_ORIGIN`: Origin validation failed
- `COUNTER_ERROR`: Invalid counter value

---

## 7. Security Headers

All responses include the following security headers:

```http
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'self'
```

---

## 8. Rate Limiting

- **Registration**: 5 attempts per minute per IP
- **Authentication**: 10 attempts per minute per IP
- **Management**: 100 requests per minute per authenticated user

Rate limit headers:
```http
X-RateLimit-Limit: 10
X-RateLimit-Remaining: 8
X-RateLimit-Reset: 1642348200
```

---

## 9. CORS Configuration

```http
Access-Control-Allow-Origin: https://your-frontend-domain.com
Access-Control-Allow-Methods: GET, POST, DELETE, OPTIONS
Access-Control-Allow-Headers: Content-Type, Authorization
Access-Control-Max-Age: 86400
```

---

## 10. WebAuthn Extensions Support

### Supported Extensions
- `credProps`: Credential properties
- `hmacCreateSecret`: HMAC secret creation
- `appid`: Legacy U2F AppID support
- `credProtect`: Credential protection policy

### Extension Usage Example
```json
{
  "extensions": {
    "credProps": true,
    "hmacCreateSecret": true,
    "credProtect": {
      "credentialProtectionPolicy": "userVerificationOptional",
      "enforceCredentialProtectionPolicy": false
    }
  }
}
```

This API specification ensures full FIDO2/WebAuthn compliance while providing a secure and developer-friendly interface for implementing passwordless authentication.