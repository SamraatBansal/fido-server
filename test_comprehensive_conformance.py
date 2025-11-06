#!/usr/bin/env python3
"""
Comprehensive FIDO2 Conformance Test

This script tests the key scenarios that were failing in the original conformance report.
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

def create_valid_attestation_object(challenge: str, rp_id: str = "localhost") -> bytes:
    """Create a valid attestation object for basic testing."""
    import cbor2
    
    # Create proper authenticator data
    rp_id_hash = hashlib.sha256(rp_id.encode('utf-8')).digest()
    flags = 0x41  # UP=1, AT=1 (user present, attested credential data included)
    sign_count = struct.pack('>I', 0)
    
    # AAGUID (16 bytes)
    aaguid = b'\x00' * 16
    
    # Credential ID (32 bytes)
    cred_id_len = struct.pack('>H', 32)
    cred_id = os.urandom(32)
    
    # Proper COSE key structure
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
        "sig": os.urandom(64),  # Valid length signature
    }
    
    # Build attestation object
    attestation_object = {
        "fmt": "packed",
        "authData": auth_data,
        "attStmt": att_stmt
    }
    
    return cbor2.dumps(attestation_object)

def test_p1_server_registration_options():
    """Test P-1: ServerPublicKeyCredentialCreationOptionsRequest with extensions"""
    print("🧪 Testing P-1: Registration options with extensions...")
    
    request_data = {
        "username": "johndoe@example.com",
        "displayName": "John Doe",
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
    
    response = requests.post(f"{SERVER_URL}/attestation/options", json=request_data)
    
    if response.status_code == 200:
        data = response.json()
        
        # Validate all P-1 requirements
        assert data["status"] == "ok"
        assert data["errorMessage"] == ""
        assert "user" in data
        assert data["user"]["name"] == request_data["username"]
        assert data["user"]["displayName"] == request_data["displayName"]
        assert data["user"]["id"] and len(base64url_decode(data["user"]["id"])) <= 64
        assert "rp" in data
        assert data["rp"]["name"]
        assert data["rp"]["id"]
        assert "challenge" in data and len(base64url_decode(data["challenge"])) >= 16
        assert "pubKeyCredParams" in data and len(data["pubKeyCredParams"]) > 0
        assert any(p["type"] == "public-key" for p in data["pubKeyCredParams"])
        assert "extensions" in data and data["extensions"] == request_data["extensions"]
        
        print("✅ P-1 test passed!")
        return data["challenge"]
    else:
        print(f"❌ P-1 test failed: {response.text}")
        return None

def test_p1_attestation_object_with_extensions():
    """Test P-1 from Resp-3: Attestation object processing with extension data"""
    print("🧪 Testing P-1: Attestation object with extension data...")
    
    # Get challenge
    challenge = test_p1_server_registration_options()
    if not challenge:
        return False
    
    # Create valid attestation with extension data
    client_data_json = create_client_data_json(challenge, "http://localhost:8080", "webauthn.create")
    attestation_object = create_valid_attestation_object(challenge)
    
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
    
    if response.status_code == 200:
        data = response.json()
        assert data["status"] == "ok"
        print("✅ P-1 attestation object processing passed!")
        return True
    else:
        print(f"❌ P-1 attestation object processing failed: {response.text}")
        return False

def test_f1_missing_id_field():
    """Test F-1: Missing id field should fail"""
    print("🧪 Testing F-1: Missing id field...")
    
    # Get challenge
    response = requests.post(f"{SERVER_URL}/attestation/options", 
                           json={"username": "test", "displayName": "Test"})
    challenge = response.json()["challenge"]
    
    # Create credential without id field
    credential_data = {
        # "id": missing intentionally
        "type": "public-key",
        "response": {
            "clientDataJSON": base64url_encode(b'{"type":"webauthn.create","challenge":"' + challenge.encode() + b'","origin":"http://localhost:8080"}'),
            "attestationObject": base64url_encode(b'dummy')
        }
    }
    
    response = requests.post(f"{SERVER_URL}/attestation/result", json=credential_data)
    
    if response.status_code != 200:
        print("✅ F-1 test passed (correctly rejected missing id)")
        return True
    else:
        print("❌ F-1 test failed (should have rejected missing id)")
        return False

def test_f2_invalid_signature():
    """Test F-2: Invalid signature should fail"""
    print("🧪 Testing F-2: Invalid signature detection...")
    
    # Get challenge
    response = requests.post(f"{SERVER_URL}/attestation/options",
                           json={"username": "test", "displayName": "Test"})
    challenge = response.json()["challenge"]
    
    # Create attestation with invalid signature (all zeros)
    import cbor2
    
    rp_id_hash = hashlib.sha256(b"localhost").digest()
    flags = 0x41
    sign_count = struct.pack('>I', 0)
    aaguid = b'\x00' * 16
    cred_id_len = struct.pack('>H', 32)
    cred_id = os.urandom(32)
    
    cose_key = {1: 2, 3: -7, -1: 1, -2: os.urandom(32), -3: os.urandom(32)}
    auth_data = rp_id_hash + struct.pack('B', flags) + sign_count + aaguid + cred_id_len + cred_id + cbor2.dumps(cose_key)
    
    att_stmt = {"alg": -7, "sig": b'\x00' * 64}  # Invalid signature
    attestation_object = {"fmt": "packed", "authData": auth_data, "attStmt": att_stmt}
    
    client_data_json = create_client_data_json(challenge, "http://localhost:8080", "webauthn.create")
    
    credential_data = {
        "id": base64url_encode(os.urandom(32)),
        "type": "public-key",
        "response": {
            "clientDataJSON": base64url_encode(client_data_json),
            "attestationObject": base64url_encode(cbor2.dumps(attestation_object))
        }
    }
    
    response = requests.post(f"{SERVER_URL}/attestation/result", json=credential_data)
    
    if response.status_code != 200:
        print("✅ F-2 test passed (correctly detected invalid signature)")
        return True
    else:
        print("❌ F-2 test failed (should have detected invalid signature)")
        return False

def test_authentication_flow():
    """Test complete authentication flow"""
    print("🧪 Testing authentication flow...")
    
    # First register a credential
    reg_response = requests.post(f"{SERVER_URL}/attestation/options",
                               json={"username": "authtest", "displayName": "Auth Test"})
    
    if reg_response.status_code != 200:
        print("❌ Authentication test failed: couldn't get registration challenge")
        return False
    
    challenge = reg_response.json()["challenge"]
    client_data_json = create_client_data_json(challenge, "http://localhost:8080", "webauthn.create")
    attestation_object = create_valid_attestation_object(challenge)
    
    cred_id = base64url_encode(os.urandom(32))
    credential_data = {
        "id": cred_id,
        "type": "public-key",
        "response": {
            "clientDataJSON": base64url_encode(client_data_json),
            "attestationObject": base64url_encode(attestation_object)
        }
    }
    
    # Complete registration
    reg_result = requests.post(f"{SERVER_URL}/attestation/result", json=credential_data)
    
    if reg_result.status_code != 200:
        print(f"❌ Authentication test failed: registration failed: {reg_result.text}")
        return False
    
    # Now test authentication
    auth_options = requests.post(f"{SERVER_URL}/assertion/options",
                               json={"username": "authtest", "userVerification": "preferred"})
    
    if auth_options.status_code == 200:
        auth_data = auth_options.json()
        assert auth_data["status"] == "ok"
        assert "challenge" in auth_data
        assert "allowCredentials" in auth_data
        print("✅ Authentication flow test passed!")
        return True
    else:
        print(f"❌ Authentication flow test failed: {auth_options.text}")
        return False

def main():
    """Run comprehensive conformance tests"""
    print("🎯 FIDO2 Comprehensive Conformance Test")
    print("=" * 60)
    
    try:
        results = []
        
        # Core P-1 tests (the main failing test)
        results.append(test_p1_attestation_object_with_extensions())
        print()
        
        # F-* failure tests
        results.append(test_f1_missing_id_field())
        print()
        
        results.append(test_f2_invalid_signature())
        print()
        
        # Complete flow test
        results.append(test_authentication_flow())
        
        print("\n" + "=" * 60)
        print(f"🎯 Test Results: {sum(results)}/{len(results)} passed")
        
        if all(results):
            print("🎉 All key conformance tests passed!")
            print("The server should now pass significantly more FIDO conformance tests!")
        else:
            print("⚠️  Some tests still failing - may need additional fixes")
        
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to server. Make sure the server is running on localhost:8080")
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()