#!/usr/bin/env python3
"""
FIDO2 WebAuthn Server Conformance Test Script

This script tests the key failing cases from the FIDO conformance tool
to ensure our implementation handles them correctly.
"""

import requests
import json
import base64
import cbor2
import sys

SERVER_URL = "http://localhost:8080"

def test_registration_start_validation():
    """Test registration start endpoint validation"""
    print("Testing registration start validation...")
    
    # Test 1: Missing username
    response = requests.post(f"{SERVER_URL}/attestation/options", json={
        "displayName": "Test User",
        "attestation": "direct"
    })
    assert response.status_code == 400, f"Expected 400, got {response.status_code}"
    assert "username" in response.json().get("errorMessage", ""), "Should mention missing username"
    print("✓ Missing username validation works")
    
    # Test 2: Empty username
    response = requests.post(f"{SERVER_URL}/attestation/options", json={
        "username": "",
        "displayName": "Test User",
        "attestation": "direct"
    })
    assert response.status_code == 400, f"Expected 400, got {response.status_code}"
    print("✓ Empty username validation works")
    
    # Test 3: Missing displayName
    response = requests.post(f"{SERVER_URL}/attestation/options", json={
        "username": "testuser",
        "attestation": "direct"
    })
    assert response.status_code == 400, f"Expected 400, got {response.status_code}"
    assert "displayName" in response.json().get("errorMessage", ""), "Should mention missing displayName"
    print("✓ Missing displayName validation works")
    
    # Test 4: Valid request
    response = requests.post(f"{SERVER_URL}/attestation/options", json={
        "username": "testuser",
        "displayName": "Test User",
        "attestation": "direct",
        "authenticatorSelection": {
            "userVerification": "required"
        }
    })
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    data = response.json()
    assert data["status"] == "ok", f"Expected status 'ok', got {data.get('status')}"
    assert "rp" in data and data["rp"]["name"], "Response should contain rp.name"
    assert "user" in data and data["user"]["name"] == "testuser", "Response should contain correct user.name"
    assert "challenge" in data and len(data["challenge"]) >= 22, "Challenge should be at least 16 bytes base64url encoded"
    assert "pubKeyCredParams" in data and len(data["pubKeyCredParams"]) > 0, "Should contain pubKeyCredParams"
    assert "extensions" in data and "example.extension" in data["extensions"], "Should contain example.extension"
    print("✓ Valid registration start request works")
    
    return data  # Return for use in next test

def test_registration_finish_validation():
    """Test registration finish endpoint validation"""
    print("\nTesting registration finish validation...")
    
    # Test 1: Missing id field
    response = requests.post(f"{SERVER_URL}/attestation/result", json={
        "type": "public-key",
        "response": {
            "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoidGVzdCIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCJ9",
            "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVhEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQAAAAA"
        }
    })
    assert response.status_code == 400, f"Expected 400, got {response.status_code}"
    assert "id" in response.json().get("errorMessage", ""), "Should mention missing id"
    print("✓ Missing id validation works")
    
    # Test 2: Empty id field
    response = requests.post(f"{SERVER_URL}/attestation/result", json={
        "id": "",
        "type": "public-key",
        "response": {
            "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoidGVzdCIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCJ9",
            "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVhEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQAAAAA"
        }
    })
    assert response.status_code == 400, f"Expected 400, got {response.status_code}"
    print("✓ Empty id validation works")
    
    # Test 3: Invalid type field
    response = requests.post(f"{SERVER_URL}/attestation/result", json={
        "id": "dGVzdGlk",
        "type": "avocado-toast",
        "response": {
            "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoidGVzdCIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCJ9",
            "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVhEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQAAAAA"
        }
    })
    assert response.status_code == 400, f"Expected 400, got {response.status_code}"
    print("✓ Invalid type validation works")
    
    # Test 4: Missing clientDataJSON
    response = requests.post(f"{SERVER_URL}/attestation/result", json={
        "id": "dGVzdGlk",
        "type": "public-key",
        "response": {
            "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVhEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQAAAAA"
        }
    })
    assert response.status_code == 400, f"Expected 400, got {response.status_code}"
    assert "clientDataJSON" in response.json().get("errorMessage", ""), "Should mention missing clientDataJSON"
    print("✓ Missing clientDataJSON validation works")
    
    # Test 5: Invalid base64url in id
    response = requests.post(f"{SERVER_URL}/attestation/result", json={
        "id": "invalid+base64/with=padding",
        "type": "public-key",
        "response": {
            "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoidGVzdCIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCJ9",
            "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVhEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQAAAAA"
        }
    })
    assert response.status_code == 400, f"Expected 400, got {response.status_code}"
    print("✓ Invalid base64url validation works")

def test_authentication_validation():
    """Test authentication endpoint validation"""
    print("\nTesting authentication validation...")
    
    # Test 1: Missing username
    response = requests.post(f"{SERVER_URL}/assertion/options", json={
        "userVerification": "required"
    })
    assert response.status_code == 400, f"Expected 400, got {response.status_code}"
    print("✓ Missing username in authentication works")
    
    # Test 2: User not found
    response = requests.post(f"{SERVER_URL}/assertion/options", json={
        "username": "nonexistentuser",
        "userVerification": "required"
    })
    assert response.status_code == 404, f"Expected 404, got {response.status_code}"
    print("✓ User not found validation works")

def create_valid_cbor_attestation_object():
    """Create a valid CBOR attestation object for testing"""
    # Create a minimal valid attestation object
    auth_data = b'\\x00' * 37  # Minimal auth data (32 + 1 + 4 bytes)
    # Set AT flag (bit 6)
    auth_data = auth_data[:32] + bytes([0x40]) + auth_data[33:]
    
    attestation_object = {
        "fmt": "none",
        "attStmt": {},
        "authData": auth_data
    }
    
    return base64.urlsafe_b64encode(cbor2.dumps(attestation_object)).decode().rstrip('=')

def test_cbor_validation():
    """Test CBOR attestation object validation"""
    print("\nTesting CBOR validation...")
    
    # First get a valid challenge
    reg_response = requests.post(f"{SERVER_URL}/attestation/options", json={
        "username": "testuser",
        "displayName": "Test User",
        "attestation": "direct"
    })
    assert reg_response.status_code == 200
    challenge = reg_response.json()["challenge"]
    
    # Create valid clientDataJSON
    client_data = {
        "type": "webauthn.create",
        "challenge": challenge,
        "origin": "http://localhost:8080"
    }
    client_data_json = base64.urlsafe_b64encode(
        json.dumps(client_data).encode()
    ).decode().rstrip('=')
    
    # Test 1: Invalid CBOR (not a map)
    invalid_cbor = base64.urlsafe_b64encode(b"invalid cbor data").decode().rstrip('=')
    response = requests.post(f"{SERVER_URL}/attestation/result", json={
        "id": "dGVzdGlk",
        "type": "public-key",
        "response": {
            "clientDataJSON": client_data_json,
            "attestationObject": invalid_cbor
        }
    })
    assert response.status_code == 400, f"Expected 400, got {response.status_code}"
    print("✓ Invalid CBOR validation works")
    
    # Test 2: Valid CBOR attestation object
    valid_attestation_object = create_valid_cbor_attestation_object()
    response = requests.post(f"{SERVER_URL}/attestation/result", json={
        "id": "dGVzdGlk",
        "type": "public-key",
        "response": {
            "clientDataJSON": client_data_json,
            "attestationObject": valid_attestation_object
        }
    })
    # This should succeed (200) or fail with a different reason (not CBOR parsing)
    assert response.status_code in [200, 401, 400], f"Unexpected status code: {response.status_code}"
    if response.status_code == 400:
        error_msg = response.json().get("errorMessage", "")
        assert "CBOR" not in error_msg, f"Should not fail on CBOR parsing: {error_msg}"
    print("✓ Valid CBOR validation works")

def main():
    """Run all conformance tests"""
    print("Starting FIDO2 WebAuthn Server Conformance Tests")
    print("=" * 50)
    
    try:
        # Test basic connectivity
        response = requests.get(f"{SERVER_URL}/health", timeout=5)
        assert response.status_code == 200, "Server health check failed"
        print("✓ Server is running and accessible")
        
        # Run test suites
        reg_data = test_registration_start_validation()
        test_registration_finish_validation()
        test_authentication_validation()
        test_cbor_validation()
        
        print("\n" + "=" * 50)
        print("🎉 All conformance tests passed!")
        print("The server properly handles the key FIDO conformance requirements.")
        
    except AssertionError as e:
        print(f"\n❌ Test failed: {e}")
        sys.exit(1)
    except requests.exceptions.RequestException as e:
        print(f"\n❌ Connection error: {e}")
        print("Make sure the server is running on http://localhost:8080")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()