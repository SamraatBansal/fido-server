#!/usr/bin/env python3
"""
FIDO2 Conformance Test Simulation

This script simulates some of the key failing conformance tests to verify our fixes.
"""

import requests
import json
import base64
import struct
import hashlib
import os
from typing import Dict, Any, Optional

# Server configuration
SERVER_URL = "http://localhost:8080"

def base64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).decode('ascii').rstrip('=')

def base64url_decode(data: str) -> bytes:
    """Base64url decode with padding."""
    # Add padding if needed
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)
    return base64.urlsafe_b64decode(data)

def create_client_data_json(challenge: str, origin: str, type_: str) -> bytes:
    """Create a clientDataJSON for testing."""
    client_data = {
        "type": type_,
        "challenge": challenge,
        "origin": origin,
        "crossOrigin": False
    }
    return json.dumps(client_data, separators=(',', ':')).encode('utf-8')

def create_mock_attestation_object(challenge: str, rp_id: str = "localhost") -> bytes:
    """Create a mock attestation object for testing."""
    import cbor2
    
    # Create mock authenticator data
    rp_id_hash = hashlib.sha256(rp_id.encode('utf-8')).digest()
    flags = 0x41  # UP=1, AT=1 (user present, attested credential data included)
    sign_count = struct.pack('>I', 0)
    
    # AAGUID (16 bytes)
    aaguid = b'\x00' * 16
    
    # Credential ID (32 bytes for example)
    cred_id_len = struct.pack('>H', 32)
    cred_id = os.urandom(32)
    
    # Mock COSE key (simplified)
    cose_key = {
        1: 2,  # kty: EC2
        3: -7, # alg: ES256
        -1: 1, # crv: P-256
        -2: os.urandom(32),  # x coordinate
        -3: os.urandom(32),  # y coordinate
    }
    cose_key_bytes = cbor2.dumps(cose_key)
    
    # Build authenticator data
    auth_data = rp_id_hash + struct.pack('B', flags) + sign_count + aaguid + cred_id_len + cred_id + cose_key_bytes
    
    # Create attestation statement
    att_stmt = {
        "alg": -7,
        "sig": os.urandom(64),  # Mock signature
    }
    
    # Build attestation object
    attestation_object = {
        "fmt": "packed",
        "authData": auth_data,
        "attStmt": att_stmt
    }
    
    return cbor2.dumps(attestation_object)

def test_registration_p1():
    """Test Server-ServerPublicKeyCredentialCreationOptions-Req-1 P-1"""
    print("Testing P-1: ServerPublicKeyCredentialCreationOptionsRequest validation...")
    
    # Test with extensions (P-1 requirement)
    request_data = {
        "username": "testuser@example.com",
        "displayName": "Test User",
        "authenticatorSelection": {
            "requireResidentKey": False,
            "authenticatorAttachment": "cross-platform",
            "userVerification": "preferred"
        },
        "attestation": "direct",
        "extensions": {
            "example.extension": True
        }
    }
    
    response = requests.post(f"{SERVER_URL}/attestation/options", 
                           json=request_data, 
                           headers={"Content-Type": "application/json"})
    
    print(f"Status: {response.status_code}")
    
    if response.status_code == 200:
        data = response.json()
        
        # Validate required fields per P-1 test
        assert data["status"] == "ok", f"Expected status 'ok', got {data['status']}"
        assert data["errorMessage"] == "", f"Expected empty errorMessage, got {data['errorMessage']}"
        
        # User validation
        assert "user" in data, "Missing user field"
        user = data["user"]
        assert "name" in user and user["name"] == request_data["username"], "User name mismatch"
        assert "displayName" in user and user["displayName"] == request_data["displayName"], "User displayName mismatch"
        assert "id" in user and user["id"], "User id missing or empty"
        
        # RP validation
        assert "rp" in data, "Missing rp field"
        rp = data["rp"]
        assert "name" in rp and rp["name"], "RP name missing or empty"
        assert "id" in rp and rp["id"], "RP id missing or empty"
        
        # Challenge validation
        assert "challenge" in data and data["challenge"], "Challenge missing or empty"
        challenge_bytes = base64url_decode(data["challenge"])
        assert len(challenge_bytes) >= 16, f"Challenge too short: {len(challenge_bytes)} bytes"
        
        # Extensions validation
        assert "extensions" in data, "Missing extensions field"
        assert data["extensions"] == request_data["extensions"], "Extensions don't match"
        
        print("✅ P-1 test passed!")
        return data["challenge"], data["user"]["id"]
    else:
        print(f"❌ P-1 test failed: {response.text}")
        return None, None

def test_registration_with_mock_attestation(challenge: str):
    """Test attestation object processing for P-1 in Resp-3"""
    print("Testing P-1 from Resp-3: attestation object with extension data...")
    
    # Create mock client data
    client_data_json = create_client_data_json(challenge, "http://localhost:8080", "webauthn.create")
    
    # Create mock attestation object
    attestation_object = create_mock_attestation_object(challenge)
    
    # Create credential response
    credential_data = {
        "id": base64url_encode(os.urandom(32)),
        "type": "public-key",
        "response": {
            "clientDataJSON": base64url_encode(client_data_json),
            "attestationObject": base64url_encode(attestation_object)
        },
        "getClientExtensionResults": {}
    }
    
    response = requests.post(f"{SERVER_URL}/attestation/result",
                           json=credential_data,
                           headers={"Content-Type": "application/json"})
    
    print(f"Status: {response.status_code}")
    print(f"Response: {response.text}")
    
    if response.status_code == 200:
        data = response.json()
        assert data["status"] == "ok", f"Expected status 'ok', got {data['status']}"
        print("✅ Attestation object processing passed!")
        return True
    else:
        print(f"❌ Attestation object processing failed: {response.text}")
        return False

def test_invalid_scenarios():
    """Test some F-* scenarios that should fail"""
    print("Testing F-* scenarios that should fail...")
    
    # F-1: Missing id field
    request_data = {
        "username": "testuser",
        "displayName": "Test User"
    }
    
    response = requests.post(f"{SERVER_URL}/attestation/options", json=request_data)
    challenge = response.json()["challenge"] if response.status_code == 200 else "dummy"
    
    # Test with missing id field
    invalid_credential = {
        # "id": missing intentionally
        "type": "public-key",
        "response": {
            "clientDataJSON": base64url_encode(b'{"type":"webauthn.create","challenge":"' + challenge.encode() + b'","origin":"http://localhost:8080"}'),
            "attestationObject": base64url_encode(b'dummy')
        }
    }
    
    response = requests.post(f"{SERVER_URL}/attestation/result", json=invalid_credential)
    
    if response.status_code != 200:
        print("✅ F-1 test passed (correctly rejected missing id)")
    else:
        print("❌ F-1 test failed (should have rejected missing id)")

def main():
    """Run conformance test simulation"""
    print("🧪 FIDO2 Conformance Test Simulation")
    print("=" * 50)
    
    try:
        # Test P-1 registration options
        challenge, user_id = test_registration_p1()
        
        if challenge:
            # Test P-1 attestation processing
            test_registration_with_mock_attestation(challenge)
        
        # Test some failure scenarios
        test_invalid_scenarios()
        
        print("\n" + "=" * 50)
        print("🎯 Conformance test simulation completed!")
        
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to server. Make sure the server is running on localhost:8080")
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()