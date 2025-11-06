#!/usr/bin/env python3

import requests
import json
import base64
import cbor2

def create_valid_attestation_object():
    """Create a valid packed attestation object without x5c to trigger the specific error"""
    
    # Create a minimal but valid authenticator data
    # rpIdHash (32 bytes) + flags (1 byte) + signCount (4 bytes) + attested credential data
    rp_id_hash = b'\x00' * 32  # 32 zero bytes for rpIdHash
    flags = b'\x41'  # UP=1, AT=1 (attested credential data included)
    sign_count = b'\x00\x00\x00\x00'  # 4 zero bytes for signCount
    aaguid = b'\x00' * 16  # 16 zero bytes for AAGUID
    cred_id_len = b'\x00\x10'  # 16 bytes credential ID length
    cred_id = b'test-credential-' + b'\x00' * 1  # 16 bytes credential ID
    
    # Minimal COSE key (CBOR-encoded public key)
    cose_key = {
        1: 2,  # kty: EC2
        3: -7,  # alg: ES256
        -1: 1,  # crv: P-256
        -2: b'\x00' * 32,  # x coordinate
        -3: b'\x00' * 32   # y coordinate
    }
    cose_key_bytes = cbor2.dumps(cose_key)
    
    auth_data = rp_id_hash + flags + sign_count + aaguid + cred_id_len + cred_id + cose_key_bytes
    
    # Create attestation statement without x5c (this should trigger the x5c error)
    att_stmt = {
        "alg": -7,  # ES256
        "sig": b'\x00' * 64  # 64 zero bytes for signature
        # Note: NO x5c field - this should trigger "Missing required field: attestationObject.attStmt.x5c"
    }
    
    # Create attestation object
    attestation_object = {
        "fmt": "packed",
        "attStmt": att_stmt,
        "authData": auth_data
    }
    
    return cbor2.dumps(attestation_object)

def test_x5c_missing_error():
    """Test the specific x5c missing error that's failing in conformance tests"""
    print("=== Testing Missing x5c Error ===")
    
    # First get registration options with direct attestation
    options_url = "http://localhost:8080/attestation/options"
    request_data = {
        "username": "testuser@example.com",
        "displayName": "Test User",
        "attestation": "direct"  # This should require x5c for full attestation
    }
    
    options_response = requests.post(options_url, json=request_data)
    if options_response.status_code != 200:
        print(f"Failed to get options: {options_response.text}")
        return
        
    options_data = options_response.json()
    challenge = options_data["challenge"]
    
    # Create valid client data JSON with the challenge
    client_data = {
        "type": "webauthn.create",
        "challenge": challenge,
        "origin": "http://localhost:8080",
        "crossOrigin": False
    }
    client_data_json = json.dumps(client_data, separators=(',', ':'))
    client_data_b64 = base64.urlsafe_b64encode(client_data_json.encode()).decode().rstrip('=')
    
    # Create valid attestation object without x5c
    attestation_object_bytes = create_valid_attestation_object()
    attestation_object_b64 = base64.urlsafe_b64encode(attestation_object_bytes).decode().rstrip('=')
    
    # Create credential response
    credential = {
        "id": "dGVzdC1jcmVkZW50aWFsLTE2Ynl0ZXM",  # base64url of "test-credential-16bytes"
        "type": "public-key",
        "response": {
            "clientDataJSON": client_data_b64,
            "attestationObject": attestation_object_b64
        },
        "getClientExtensionResults": {}
    }
    
    # Send to finish registration
    finish_url = "http://localhost:8080/attestation/result"
    response = requests.post(finish_url, json=credential)
    
    print(f"Status: {response.status_code}")
    print(f"Response: {response.text}")
    
    if response.status_code != 200:
        response_data = response.json()
        error_msg = response_data.get("errorMessage", "")
        
        if "Missing required field: attestationObject.attStmt.x5c" in error_msg:
            print("✓ SUCCESS: Correctly detected missing x5c field for direct attestation")
            print("This matches the failing FIDO conformance tests P-5, P-8, P-9, P-12")
        else:
            print(f"✗ Unexpected error: {error_msg}")
    else:
        print("✗ Request succeeded when it should have failed for missing x5c")

def test_self_attestation_case():
    """Test self-attestation case (should work without x5c)"""
    print("\n=== Testing Self-Attestation (should work) ===")
    
    # Get registration options with "none" attestation
    options_url = "http://localhost:8080/attestation/options"
    request_data = {
        "username": "testuser2@example.com",
        "displayName": "Test User 2",
        "attestation": "none"  # This should allow self-attestation without x5c
    }
    
    options_response = requests.post(options_url, json=request_data)
    if options_response.status_code != 200:
        print(f"Failed to get options: {options_response.text}")
        return
        
    options_data = options_response.json()
    challenge = options_data["challenge"]
    
    # Create client data JSON
    client_data = {
        "type": "webauthn.create",
        "challenge": challenge,
        "origin": "http://localhost:8080",
        "crossOrigin": False
    }
    client_data_json = json.dumps(client_data, separators=(',', ':'))
    client_data_b64 = base64.urlsafe_b64encode(client_data_json.encode()).decode().rstrip('=')
    
    # Create "none" format attestation object
    rp_id_hash = b'\x00' * 32
    flags = b'\x41'  # UP=1, AT=1
    sign_count = b'\x00\x00\x00\x00'
    aaguid = b'\x00' * 16
    cred_id_len = b'\x00\x10'
    cred_id = b'test-credential2' + b'\x00' * 0  # 16 bytes
    
    cose_key = {
        1: 2,  # kty: EC2
        3: -7,  # alg: ES256
        -1: 1,  # crv: P-256
        -2: b'\x11' * 32,  # x coordinate (different from test above)
        -3: b'\x22' * 32   # y coordinate
    }
    cose_key_bytes = cbor2.dumps(cose_key)
    
    auth_data = rp_id_hash + flags + sign_count + aaguid + cred_id_len + cred_id + cose_key_bytes
    
    # "none" attestation format
    attestation_object = {
        "fmt": "none",
        "attStmt": {},  # Empty for "none" format
        "authData": auth_data
    }
    
    attestation_object_bytes = cbor2.dumps(attestation_object)
    attestation_object_b64 = base64.urlsafe_b64encode(attestation_object_bytes).decode().rstrip('=')
    
    credential = {
        "id": "dGVzdC1jcmVkZW50aWFsMlRlc3Q",
        "type": "public-key",
        "response": {
            "clientDataJSON": client_data_b64,
            "attestationObject": attestation_object_b64
        },
        "getClientExtensionResults": {}
    }
    
    finish_url = "http://localhost:8080/attestation/result"
    response = requests.post(finish_url, json=credential)
    
    print(f"Status: {response.status_code}")
    print(f"Response: {response.text}")
    
    if response.status_code == 200:
        print("✓ Self-attestation worked correctly")
    else:
        print(f"✗ Self-attestation failed: {response.text}")

if __name__ == "__main__":
    print("Testing Specific x5c Validation Issues")
    print("=" * 50)
    
    try:
        test_x5c_missing_error()
        test_self_attestation_case()
        
        print("\n" + "=" * 50)
        print("Test Complete")
        
    except Exception as e:
        print(f"Test failed with exception: {e}")
        import traceback
        traceback.print_exc()