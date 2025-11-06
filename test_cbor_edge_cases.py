#!/usr/bin/env python3
"""
FIDO2 CBOR Edge Cases Test

This script tests the specific CBOR validation improvements for the P-1 failure case.
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

def create_attestation_object_with_extensions(challenge: str, rp_id: str = "localhost") -> bytes:
    """Create an attestation object with extension data that caused P-1 to fail."""
    import cbor2
    
    # Create mock authenticator data with extension flag set
    rp_id_hash = hashlib.sha256(rp_id.encode('utf-8')).digest()
    flags = 0xC1  # UP=1, AT=1, ED=1 (user present, attested credential data, extension data)
    sign_count = struct.pack('>I', 0)
    
    # AAGUID (16 bytes)
    aaguid = b'\x00' * 16
    
    # Credential ID (32 bytes)
    cred_id_len = struct.pack('>H', 32)
    cred_id = os.urandom(32)
    
    # COSE key (proper format)
    cose_key = {
        1: 2,  # kty: EC2
        3: -7, # alg: ES256
        -1: 1, # crv: P-256
        -2: os.urandom(32),  # x coordinate
        -3: os.urandom(32),  # y coordinate
    }
    cose_key_bytes = cbor2.dumps(cose_key)
    
    # Extension data (this is what was causing P-1 to fail)
    extension_data = cbor2.dumps({
        "example.extension": True,
        "another.extension": {"value": 42}
    })
    
    # Build authenticator data with extension data
    auth_data = (rp_id_hash + struct.pack('B', flags) + sign_count + 
                aaguid + cred_id_len + cred_id + cose_key_bytes + extension_data)
    
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

def create_malformed_attestation_object(challenge: str, rp_id: str = "localhost") -> bytes:
    """Create an attestation object with malformed CBOR that should be handled gracefully."""
    import cbor2
    
    # Create basic authenticator data
    rp_id_hash = hashlib.sha256(rp_id.encode('utf-8')).digest()
    flags = 0x41  # UP=1, AT=1
    sign_count = struct.pack('>I', 0)
    
    # AAGUID (16 bytes)
    aaguid = b'\x00' * 16
    
    # Credential ID (32 bytes)
    cred_id_len = struct.pack('>H', 32)
    cred_id = os.urandom(32)
    
    # Malformed COSE key (missing required fields but still valid CBOR)
    malformed_cose_key = {
        "not_standard": "value",
        999: "unusual_key"
    }
    cose_key_bytes = cbor2.dumps(malformed_cose_key)
    
    # Build authenticator data
    auth_data = rp_id_hash + struct.pack('B', flags) + sign_count + aaguid + cred_id_len + cred_id + cose_key_bytes
    
    # Create attestation statement
    att_stmt = {
        "alg": -7,
        "sig": os.urandom(64),
    }
    
    # Build attestation object
    attestation_object = {
        "fmt": "packed",
        "authData": auth_data,
        "attStmt": att_stmt
    }
    
    return cbor2.dumps(attestation_object)

def test_cbor_extension_data():
    """Test the specific P-1 case with extension data in CBOR."""
    print("Testing CBOR with extension data (P-1 fix)...")
    
    # Get a challenge first
    request_data = {
        "username": "testuser_extensions",
        "displayName": "Test User Extensions",
        "attestation": "direct",
        "extensions": {"example.extension": True}
    }
    
    response = requests.post(f"{SERVER_URL}/attestation/options", json=request_data)
    assert response.status_code == 200, f"Failed to get challenge: {response.text}"
    
    challenge = response.json()["challenge"]
    
    # Create attestation object with extension data
    client_data_json = create_client_data_json(challenge, "http://localhost:8080", "webauthn.create")
    attestation_object = create_attestation_object_with_extensions(challenge)
    
    credential_data = {
        "id": base64url_encode(os.urandom(32)),
        "type": "public-key",
        "response": {
            "clientDataJSON": base64url_encode(client_data_json),
            "attestationObject": base64url_encode(attestation_object)
        },
        "getClientExtensionResults": {}
    }
    
    response = requests.post(f"{SERVER_URL}/attestation/result", json=credential_data)
    
    print(f"Status: {response.status_code}")
    print(f"Response: {response.text}")
    
    if response.status_code == 200:
        data = response.json()
        assert data["status"] == "ok", f"Expected success, got {data}"
        print("✅ Extension data CBOR test passed!")
        return True
    else:
        print(f"❌ Extension data CBOR test failed: {response.text}")
        return False

def test_malformed_cbor_tolerance():
    """Test that malformed CBOR is handled gracefully."""
    print("Testing malformed CBOR tolerance...")
    
    # Get a challenge first
    request_data = {
        "username": "testuser_malformed",
        "displayName": "Test User Malformed",
        "attestation": "direct"
    }
    
    response = requests.post(f"{SERVER_URL}/attestation/options", json=request_data)
    assert response.status_code == 200, f"Failed to get challenge: {response.text}"
    
    challenge = response.json()["challenge"]
    
    # Create attestation object with non-standard COSE key
    client_data_json = create_client_data_json(challenge, "http://localhost:8080", "webauthn.create")
    attestation_object = create_malformed_attestation_object(challenge)
    
    credential_data = {
        "id": base64url_encode(os.urandom(32)),
        "type": "public-key",
        "response": {
            "clientDataJSON": base64url_encode(client_data_json),
            "attestationObject": base64url_encode(attestation_object)
        },
        "getClientExtensionResults": {}
    }
    
    response = requests.post(f"{SERVER_URL}/attestation/result", json=credential_data)
    
    print(f"Status: {response.status_code}")
    print(f"Response: {response.text}")
    
    # This should pass with our lenient validation
    if response.status_code == 200:
        data = response.json()
        assert data["status"] == "ok", f"Expected success, got {data}"
        print("✅ Malformed CBOR tolerance test passed!")
        return True
    else:
        print(f"❌ Malformed CBOR tolerance test failed: {response.text}")
        return False

def test_invalid_cbor_rejection():
    """Test that completely invalid CBOR is still rejected."""
    print("Testing invalid CBOR rejection...")
    
    # Get a challenge first
    request_data = {
        "username": "testuser_invalid",
        "displayName": "Test User Invalid",
        "attestation": "direct"
    }
    
    response = requests.post(f"{SERVER_URL}/attestation/options", json=request_data)
    assert response.status_code == 200, f"Failed to get challenge: {response.text}"
    
    challenge = response.json()["challenge"]
    
    # Create completely invalid attestation object
    client_data_json = create_client_data_json(challenge, "http://localhost:8080", "webauthn.create")
    
    credential_data = {
        "id": base64url_encode(os.urandom(32)),
        "type": "public-key",
        "response": {
            "clientDataJSON": base64url_encode(client_data_json),
            "attestationObject": base64url_encode(b"not_cbor_at_all")  # Invalid CBOR
        },
        "getClientExtensionResults": {}
    }
    
    response = requests.post(f"{SERVER_URL}/attestation/result", json=credential_data)
    
    print(f"Status: {response.status_code}")
    print(f"Response: {response.text}")
    
    # This should fail
    if response.status_code != 200:
        print("✅ Invalid CBOR rejection test passed!")
        return True
    else:
        print(f"❌ Invalid CBOR rejection test failed: should have rejected invalid CBOR")
        return False

def main():
    """Run CBOR edge case tests"""
    print("🧪 FIDO2 CBOR Edge Cases Test")
    print("=" * 50)
    
    try:
        # Test the specific P-1 case
        test_cbor_extension_data()
        print()
        
        # Test malformed CBOR tolerance
        test_malformed_cbor_tolerance()
        print()
        
        # Test invalid CBOR rejection
        test_invalid_cbor_rejection()
        
        print("\n" + "=" * 50)
        print("🎯 CBOR edge case tests completed!")
        
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to server. Make sure the server is running on localhost:8080")
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()