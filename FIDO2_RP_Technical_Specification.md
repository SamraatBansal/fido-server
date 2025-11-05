
# FIDO2/WebAuthn Relying Party (RP) Server - Technical Specification

**Project ID:** FIDO_29_0sdvq,lefjh3ajhghascgnhbsdhnasasasccdcsc

## 1. Security Requirements

This section outlines the core security requirements derived from the FIDO Alliance specifications. Each requirement is paired with testable criteria.

| Requirement ID | Description | Testable Criteria |
| :--- | :--- | :--- |
| **SR-01** | **Origin Validation** | The server MUST validate that the `origin` in the client data JSON matches the expected Relying Party origin. The test will involve sending requests with mismatched origins and verifying the server rejects them. |
| **SR-02** | **Challenge Freshness & Uniqueness** | The server MUST generate a cryptographically random challenge for each registration and authentication ceremony. The challenge MUST be unique per operation. Tests will verify that challenges are not repeated and that a used challenge cannot be replayed. |
| **SR-03** | **Signature Verification** | The server MUST cryptographically verify the authenticator's signature during both attestation and assertion using the stored public key. Tests will include valid signatures, invalid signatures (wrong key, tampered data), and signatures from different algorithms. |
| **SR-04** | **Credential Storage** | The server MUST store the credential public key, credential ID, and signature count securely. The credential ID must be unique per user. Tests will verify that this data is stored correctly upon registration and retrieved for authentication. |
| **SR-05** | **User Handle Validation** | The server MUST validate that the user handle (`user.id`) provided during registration corresponds to an existing and authenticated user in the system. Tests will attempt registration with non-existent or unauthenticated user handles. |
| **SR-06** | **Signature Counter Protection** | The server MUST store and check the signature counter (`signCount`) for each authentication. The server MUST reject any authentication where the counter is less than or equal to the last known value. Tests will simulate replay attacks by sending the same assertion twice and also by sending an assertion with an old counter value. |
| **SR-07** | **Attestation Verification (Optional but Recommended)** | The server should have a configurable policy for verifying attestation statements to ensure the authenticator's trustworthiness. Tests will involve different attestation types (`none`, `indirect`, `direct`) and metadata validation. |
| **SR-08** | **TLS Enforcement** | All communication between the client and the server MUST be over a secure (TLS) channel. Tests will attempt to connect over plain HTTP and verify that the connection is rejected or redirected to HTTPS. |

## 2. Technical Scope

This section defines the core WebAuthn operations and their success/failure conditions.

### 2.1. Registration (Attestation) Flow

*   **Success Condition:**
    1.  User initiates registration.
    2.  RP Server generates `PublicKeyCredentialCreationOptions` (including a fresh challenge, RP info, and user info) and sends them to the client.
    3.  Client uses `navigator.credentials.create()` to create a new credential.
    4.  Client sends the `PublicKeyCredential` (containing `attestationObject` and `clientDataJSON`) back to the server.
    5.  Server validates the `attestationObject` (including client data hash, origin, and signature) and stores the new public key credential.
    6.  Server returns a success status.

*   **Failure Conditions:**
    *   Mismatched origin.
    *   Invalid or replayed challenge.
    *   Invalid attestation signature.
    *   User handle does not exist.
    *   Credential ID already exists.

### 2.2. Authentication (Assertion) Flow

*   **Success Condition:**
    1.  User initiates authentication.
    2.  RP Server generates `PublicKeyCredentialRequestOptions` (including a fresh challenge and `allowCredentials` list) and sends them to the client.
    3.  Client uses `navigator.credentials.get()` to generate an assertion.
    4.  Client sends the `PublicKeyCredential` (containing `assertionObject`, `authenticatorData`, `signature`, and `userHandle`) back to the server.
    5.  Server retrieves the stored credential, verifies the signature and `clientDataJSON`.
    6.  Server validates the signature counter to prevent replay attacks.
    7.  Server updates the stored signature counter.
    8.  Server returns a success status, establishing the user session.

*   **Failure Conditions:**
    *   Mismatched origin.
    *   Invalid or replayed challenge.
    *   Invalid assertion signature.
    *   Unknown credential ID.
    *   Signature counter is not strictly greater than the stored value.

## 3. Rust Architecture (`webauthn-rs`)

A layered architecture is recommended for clarity and testability.

```
fido2_rp_server/
├── Cargo.toml
└── src/
    ├── main.rs         # Application entry point, web server setup (e.g., Actix, Axum)
    ├── api/
    │   ├── mod.rs
    │   ├── registration.rs # Handlers for /attestation/* endpoints
    │   └── authentication.rs # Handlers for /assertion/* endpoints
    ├── webauthn/
    │   ├── mod.rs
    │   └── core.rs       # Business logic wrapping webauthn-rs library
    ├── storage/
    │   ├── mod.rs
    │   ├── user_store.rs # User management logic
    │   └── cred_store.rs # Credential persistence logic (in-memory, PostgreSQL)
    └── models.rs         # Data models (User, Credential)
tests/
├── registration_flow.rs
├── authentication_flow.rs
└── security_tests.rs
```

*   **Testing Considerations:**
    *   **Unit Tests:** Each module in `src/` should have an inline `#[cfg(test)]` module. The `storage` and `webauthn::core` layers should be unit tested extensively.
    *   **Integration Tests:** The `tests/` directory will contain integration tests that spin up the server and test the API endpoints from `src/api/`. These tests will simulate a full FIDO2 flow.
    *   **Mocking:** Use traits for storage (`UserStore`, `CredentialStore`) to allow for in-memory mock implementations during testing.

## 4. API Design (REST/JSON)

The API will adhere to the FIDO Alliance Conformance Test API specifications.

### Registration Endpoints

#### `POST /attestation/options`
*   **Description:** Starts the registration ceremony.
*   **Request Body:**
    ```json
    {
      "username": "testuser",
      "displayName": "Test User"
    }
    ```
*   **Response Body (Success):** `PublicKeyCredentialCreationOptions`
    ```json
    {
      "rp": {
        "name": "FIDO2 RP Server",
        "id": "localhost"
      },
      "user": {
        "id": "<user_handle_base64url>",
        "name": "testuser",
        "displayName": "Test User"
      },
      "challenge": "<challenge_base64url>",
      "pubKeyCredParams": [ ... ],
      "timeout": 60000,
      "attestation": "direct",
      "excludeCredentials": [ ... ]
    }
    ```

#### `POST /attestation/result`
*   **Description:** Completes the registration ceremony.
*   **Request Body:** `PublicKeyCredential` as sent by the client.
*   **Response Body (Success):**
    ```json
    {
      "status": "ok",
      "errorMessage": ""
    }
    ```
*   **Response Body (Failure):**
    ```json
    {
      "status": "failed",
      "errorMessage": "A descriptive error message."
    }
    ```

### Authentication Endpoints

#### `POST /assertion/options`
*   **Description:** Starts the authentication ceremony.
*   **Request Body:**
    ```json
    {
      "username": "testuser"
    }
    ```
*   **Response Body (Success):** `PublicKeyCredentialRequestOptions`
    ```json
    {
      "challenge": "<challenge_base64url>",
      "timeout": 60000,
      "rpId": "localhost",
      "allowCredentials": [ ... ]
    }
    ```

#### `POST /assertion/result`
*   **Description:** Completes the authentication ceremony.
*   **Request Body:** `PublicKeyCredential` as sent by the client.
*   **Response Body (Success):**
    ```json
    {
      "status": "ok",
      "errorMessage": ""
    }
    ```
*   **Response Body (Failure):**
    ```json
    {
      "status": "failed",
      "errorMessage": "A descriptive error message."
    }
    ```

## 5. Storage Requirements

### 5.1. User Table
*   `id`: Primary Key (e.g., UUID)
*   `username`: Unique, Indexed
*   `display_name`: String

### 5.2. Credential Table
*   `id`: Primary Key (e.g., UUID)
*   `user_id`: Foreign Key to `users.id`
*   `credential_id_base64url`: String, Unique - The `rawId` from the authenticator.
*   `public_key_cbor_base64url`: String - The COSE public key.
*   `signature_count`: BigInt / u64
*   `transports`: Array of strings (e.g., `["usb", "nfc", "ble"]`)

### 5.3. Data Validation
*   `credential_id_base64url` must be unique across all users to prevent cross-user credential binding.
*   The combination of `user_id` and `credential_id_base64url` must be unique.
*   Input data for all storage operations must be validated to prevent injection attacks (though this is less of a concern with parameterized queries).

## 6. Compliance Checklist

This checklist will be used to verify FIDO2 specification compliance through testing.

| ID | Specification Point | Test Case |
|:---|:---|:---|
| **C-01** | RP ID is correctly set and verified. | Test with valid, invalid, and missing `rpId`. |
| **C-02** | Challenge is cryptographically random and at least 16 bytes. | Analyze challenge generation and test for uniqueness and size. |
| **C-03** | `clientDataJSON.type` is `webauthn.create` for registration. | Send incorrect `type` and verify rejection. |
| **C-04** | `clientDataJSON.type` is `webauthn.get` for authentication. | Send incorrect `type` and verify rejection. |
| **C-05** | `clientDataJSON.challenge` matches the server-sent challenge. | Send mismatched, empty, or replayed challenges. |
| **C-06** | `clientDataJSON.origin` matches the RP's origin. | Send requests from a different origin. |
| **C-07** | `authData.signCount` is validated and updated. | Send assertions with `signCount` of 0, `signCount` equal to stored value, and `signCount` less than stored value. |
| **C-08**| `authData.flags` `UP` (User Present) bit is checked. | Test with simulated authenticator data where UP flag is not set. |
| **C-09**| `authData.flags` `UV` (User Verified) bit is checked according to RP policy. | Test with `userVerification` set to `required` and a simulated response where UV is false. |
| **C-10**| `excludeCredentials` is used to prevent re-registration of the same authenticator. | Attempt to register an already registered credential and verify failure. |


## 7. Risk Assessment

| Risk | Description | Mitigation Strategy | Test Plan |
| :--- | :--- | :--- | :--- |
| **Replay Attack** | An attacker intercepts a valid assertion and replays it to gain access. | **Challenge-Response:** Use a unique, single-use challenge for each authentication. **Signature Counter:** Enforce a strictly increasing signature counter. | Create tests that attempt to reuse a valid assertion response. Create tests that send an assertion with a stale signature counter. |
| **Credential Theft (Server-side)** | An attacker breaches the server and steals the credential database. | **Store only Public Keys:** The server never sees or stores private keys. **Database Security:** Enforce strong access controls and encryption at rest for the database. | N/A for runtime testing, but database configuration and access policies should be audited. |
| **Phishing** | A user is tricked into authenticating on a malicious site that impersonates the RP. | **Origin Binding:** The FIDO2 protocol inherently mitigates this by binding credentials to a specific RP origin. The server MUST validate the origin on every request. | Integration tests must send requests with invalid `origin` headers and verify they are rejected. |
| **Cross-Site Request Forgery (CSRF)** | An attacker forces a logged-in user's browser to send a request to the RP. | Standard CSRF protection (e.g., SameSite cookies, anti-CSRF tokens) should be used for session management *after* FIDO2 authentication. The FIDO2 ceremony itself is resistant due to the challenge-response mechanism. | Implement and test standard CSRF token validation on authenticated (non-FIDO) endpoints. |
| **Man-in-the-Middle (MitM)** | An attacker intercepts and modifies traffic between the client and server. | **TLS Enforcement:** Mandate HTTPS for all communication. | A proxy tool (e.g., Burp Suite) can be used to manually test if plain HTTP requests are accepted. Automated tests should verify redirection or rejection of HTTP. |

