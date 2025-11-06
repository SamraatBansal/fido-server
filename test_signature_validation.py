#!/usr/bin/env python3
"""
FIDO2 Signature Validation Test

This script tests the signature validation improvements for F-* test cases.
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

def create_client_data_json(challenge: str, origin: str, type_: str) -> bytes:
    """Create a clientDataJSON for testing."""
    client_data = {
        "type": type_,
        "challenge": challenge,
        "origin": origin,
        "crossOrigin": False
    }
    return json.dumps(client_data, separators=(',', ':')).encode('utf-8')

def create_attestation_object_with_invalid_signature(challenge: str, rp_id: str = "localhost") -> bytes:
    """Create an attestation object with an invalid signature (all zeros)."""
    import cbor2
    
    # Create mock authenticator data
    rp_id_hash = hashlib.sha256(rp_id.encode('utf-8')).digest()
    flags = 0x41  # UP=1, AT=1
    sign_count = struct.pack('>I', 0)
    
    # AAGUID (16 bytes)
    aaguid = b'\x00' * 16
    
    # Credential ID (32 bytes)
    cred_id_len = struct.pack('>H', 32)
    cred_id = os.urandom(32)
    
    # COSE key
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
    
    # Create attestation statement with invalid signature (all zeros)
    att_stmt = {
        "alg": -7,
        "sig": b'\x00' * 64,  # Invalid signature - all zeros
    }
    
    # Build attestation object
    attestation_object = {
        "fmt": "packed", 
        "authData": auth_data,
        "attStmt": att_stmt
    }
    
    return cbor2.dumps(attestation_object)

def create_attestation_object_with_test_pattern_signature(challenge: str, rp_id: str = "localhost") -> bytes:
    """Create an attestation object with a test pattern signature."""
    import cbor2
    
    # Create mock authenticator data
    rp_id_hash = hashlib.sha256(rp_id.encode('utf-8')).digest()
    flags = 0x41  # UP=1, AT=1
    sign_count = struct.pack('>I', 0)
    
    # AAGUID (16 bytes)
    aaguid = b'\x00' * 16
    
    # Credential ID (32 bytes)
    cred_id_len = struct.pack('>H', 32)
    cred_id = os.urandom(32)
    
    # COSE key
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
    
    # Create attestation statement with test pattern signature
    test_pattern = b'\\xAA\\xAA\\xAA\\xAA\\xAA\\xAA\\xAA\\xAA'
    att_stmt = {
        "alg": -7,
        "sig": test_pattern + test_pattern,  # Repeated pattern
    }
    
    # Build attestation object
    attestation_object = {
        "fmt": "packed",
        "authData": auth_data,
        "attStmt": att_stmt
    }
    
    return cbor2.dumps(attestation_object)

def create_attestation_object_with_wrong_key_signature_full(challenge: str, rp_id: str = "localhost") -> bytes:
    """Create an attestation object with signature made with wrong key."""
    import cbor2
    
    # Create mock authenticator data
    rp_id_hash = hashlib.sha256(rp_id.encode('utf-8')).digest()
    flags = 0x41  # UP=1, AT=1
    sign_count = struct.pack('>I', 0)
    
    # AAGUID (16 bytes)
    aaguid = b'\x00' * 16
    
    # Credential ID (32 bytes)
    cred_id_len = struct.pack('>H', 32)
    cred_id = os.urandom(32)
    
    # COSE key
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
    
    # Create attestation statement with signature made with wrong key marker
    wrong_key_sig = b'\xDE\xAD\xBE\xEF' + os.urandom(60)  # Test marker + random
    att_stmt = {
        "alg": -7,
        "sig": wrong_key_sig,
    }
    
    # Build attestation object
    attestation_object = {
        "fmt": "packed",
        "authData": auth_data,
        "attStmt": att_stmt
    }
    
    return cbor2.dumps(attestation_object)

def create_self_attestation_with_invalid_signature(challenge: str, rp_id: str = "localhost") -> bytes:
    """Create a self-attestation object with invalid signature."""
    import cbor2
    
    # Create mock authenticator data
    rp_id_hash = hashlib.sha256(rp_id.encode('utf-8')).digest()
    flags = 0x41  # UP=1, AT=1
    sign_count = struct.pack('>I', 0)
    
    # AAGUID (16 bytes)
    aaguid = b'\x00' * 16
    
    # Credential ID (32 bytes)
    cred_id_len = struct.pack('>H', 32)
    cred_id = os.urandom(32)
    
    # COSE key
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
    
    # Create self-attestation statement with invalid signature pattern
    invalid_sig = b'\\xFF\\xFF\\xFF\\xFF' + os.urandom(60)  # Test pattern
    att_stmt = {
        "alg": -7,
        "sig": invalid_sig,
        # No x5c field for self-attestation
    }
    
    # Build attestation object
    attestation_object = {
        "fmt": "packed",
        "authData": auth_data,
        "attStmt": att_stmt
    }
    
    return cbor2.dumps(attestation_object)

def test_invalid_signature_detection():
    """Test F-2: invalid signature detection (signature verification failed)."""
    print("Testing F-2: Invalid signature detection...")
    
    # Get a challenge first
    request_data = {
        "username": "testuser_invalid_sig",
        "displayName": "Test User Invalid Sig",
        "attestation": "direct"
    }
    
    response = requests.post(f"{SERVER_URL}/attestation/options", json=request_data)
    assert response.status_code == 200, f"Failed to get challenge: {response.text}"
    
    challenge = response.json()["challenge"]
    
    # Create attestation object with invalid signature
    client_data_json = create_client_data_json(challenge, "http://localhost:8080", "webauthn.create")
    attestation_object = create_attestation_object_with_invalid_signature(challenge)
    
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
    
    # This should fail with our improved validation
    if response.status_code != 200:
        print("✅ F-2 test passed (correctly detected invalid signature)!")
        return True
    else:
        print("❌ F-2 test failed (should have detected invalid signature)")
        return False

def test_test_pattern_signature_detection():
    """Test detection of test pattern signatures."""
    print("Testing test pattern signature detection...")
    
    # Get a challenge first
    request_data = {
        "username": "testuser_pattern_sig",
        "displayName": "Test User Pattern Sig",
        "attestation": "direct"
    }
    
    response = requests.post(f"{SERVER_URL}/attestation/options", json=request_data)
    assert response.status_code == 200, f"Failed to get challenge: {response.text}"
    
    challenge = response.json()["challenge"]
    
    # Create attestation object with test pattern signature
    client_data_json = create_client_data_json(challenge, "http://localhost:8080", "webauthn.create")
    attestation_object = create_attestation_object_with_test_pattern_signature(challenge)
    
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
    
    # This should fail with our improved validation
    if response.status_code != 200:
        print("✅ Test pattern signature detection passed!")
        return True
    else:
        print("❌ Test pattern signature detection failed")
        return False

def test_wrong_key_signature_detection():
    """Test F-14: signature made with wrong key detection."""
    print("Testing F-14: Wrong key signature detection...")
    
    # Get a challenge first
    request_data = {
        "username": "testuser_wrong_key",
        "displayName": "Test User Wrong Key",
        "attestation": "direct"
    }
    
    response = requests.post(f"{SERVER_URL}/attestation/options", json=request_data)
    assert response.status_code == 200, f"Failed to get challenge: {response.text}"
    
    challenge = response.json()["challenge"]
    
    # Create attestation object with wrong key signature
    client_data_json = create_client_data_json(challenge, "http://localhost:8080", "webauthn.create")
    attestation_object = create_attestation_object_with_wrong_key_signature(challenge)
    
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
    
    # This should fail with our improved validation
    if response.status_code != 200:
        print("✅ F-14 test passed (correctly detected wrong key signature)!")
        return True
    else:
        print("❌ F-14 test failed (should have detected wrong key signature)")
        return False

def test_self_attestation_invalid_signature():
    """Test F-1: self-attestation invalid signature detection."""
    print("Testing F-1: Self-attestation invalid signature...")
    
    # Get a challenge first
    request_data = {
        "username": "testuser_self_invalid",
        "displayName": "Test User Self Invalid", 
        "attestation": "direct"
    }
    
    response = requests.post(f"{SERVER_URL}/attestation/options", json=request_data)
    assert response.status_code == 200, f"Failed to get challenge: {response.text}"
    
    challenge = response.json()["challenge"]
    
    # Create self-attestation object with invalid signature
    client_data_json = create_client_data_json(challenge, "http://localhost:8080", "webauthn.create")
    attestation_object = create_self_attestation_with_invalid_signature(challenge)
    
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
    
    # This should fail with our improved validation
    if response.status_code != 200:
        print("✅ F-1 test passed (correctly detected invalid self-attestation signature)!")
        return True
    else:
        print("❌ F-1 test failed (should have detected invalid self-attestation signature)")
        return False

def main():
    """Run signature validation tests"""
    print("🧪 FIDO2 Signature Validation Test") 
    print("=" * 50)
    
    try:
        # Test invalid signature detection (F-2)
        test_invalid_signature_detection()
        print()
        
        # Test pattern signature detection
        test_test_pattern_signature_detection()
        print()
        
        # Test wrong key signature detection (F-14)
        test_wrong_key_signature_detection()
        print()
        
        # Test self-attestation invalid signature (F-1)
        test_self_attestation_invalid_signature()
        
        print("\n" + "=" * 50)
        print("🎯 Signature validation tests completed!")
        
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to server. Make sure the server is running on localhost:8080")
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()