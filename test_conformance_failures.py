#!/usr/bin/env python3

import requests
import json
import base64
import cbor2

def test_f2_unverifiable_signature():
    """Test F-2: signature that can not be verified should FAIL but currently succeeds"""
    print("=== F-2 Test: Unverifiable Signature (should FAIL) ===")
    
    # Get registration options
    options_url = "http://localhost:8080/attestation/options"
    request_data = {
        "username": "f2test@example.com",
        "displayName": "F2 Test User",
        "attestation": "direct"
    }
    
    options_response = requests.post(options_url, json=request_data)
    if options_response.status_code != 200:
        print(f"Failed to get options: {options_response.text}")
        return
        
    options_data = options_response.json()
    challenge = options_data["challenge"]
    
    # Create client data
    client_data = {
        "type": "webauthn.create",
        "challenge": challenge,
        "origin": "http://localhost:8080"
    }
    client_data_json = json.dumps(client_data, separators=(',', ':'))
    client_data_b64 = base64.urlsafe_b64encode(client_data_json.encode()).decode().rstrip('=')
    
    # Create attestation object with INTENTIONALLY UNVERIFIABLE signature
    # This should trigger F-2 failure (signature verification should fail)
    
    rp_id_hash = bytes([0x49, 0x96, 0x0d, 0xe5, 0x88, 0x0e, 0x8c, 0x68, 0x74, 0x34, 0x17, 0x0f, 0x64, 0x76, 0x60, 0x5b,
                       0x8f, 0xe4, 0xae, 0xb9, 0xa2, 0x86, 0x32, 0xc7, 0x99, 0x5c, 0xf3, 0xba, 0x83, 0x1d, 0x97, 0x63])
    flags = bytes([0x41])  # UP=1, AT=1  
    sign_count = bytes([0x00, 0x00, 0x00, 0x00])
    aaguid = bytes([0x00] * 16)
    cred_id_length = bytes([0x00, 0x10])
    cred_id = b"f2-test-cred1234"
    
    cose_key = {
        1: 2,    # kty: EC2
        3: -7,   # alg: ES256
        -1: 1,   # crv: P-256
        -2: bytes([0x50] * 32),  # x coordinate
        -3: bytes([0x60] * 32)   # y coordinate
    }
    
    cose_key_cbor = cbor2.dumps(cose_key)
    auth_data = rp_id_hash + flags + sign_count + aaguid + cred_id_length + cred_id + cose_key_cbor
    
    # F-2 test: Create signature that appears valid but can't be verified
    # This signature has a realistic structure but wrong content
    fake_signature = bytes([
        0x30, 0x45,  # DER sequence, length 69
        0x02, 0x21,  # integer, length 33
        0x00,        # padding for positive number
    ] + [0x12, 0x34, 0x56, 0x78] * 8 +  # Repeating pattern - should be detected
    [
        0x02, 0x20   # integer, length 32  
    ] + [0x9A, 0xBC, 0xDE, 0xF0] * 8)  # Another repeating pattern
    
    # Create x5c with fake certificate that should fail verification
    fake_cert = bytes([0x30, 0x82, 0x01, 0xFF] + [0x44] * 500)  # Fake DER certificate
    
    att_stmt = {
        "alg": -7,
        "sig": fake_signature,
        "x5c": [fake_cert]  # Include x5c to avoid the previous error
    }
    
    attestation_object = {
        "fmt": "packed",
        "attStmt": att_stmt,
        "authData": auth_data
    }
    
    attestation_object_bytes = cbor2.dumps(attestation_object)
    attestation_object_b64 = base64.urlsafe_b64encode(attestation_object_bytes).decode().rstrip('=')
    
    credential = {
        "id": "ZjItdGVzdC1jcmVkMTIzNA",
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
        print("✗ F-2 ISSUE: Server accepted unverifiable signature (should have failed)")
        print("This matches the FIDO conformance failure: 'Promise succeeded when expected to fail!'")
    else:
        response_data = response.json()
        error_msg = response_data.get("errorMessage", "")
        if "Can not validate response signature" in error_msg:
            print("✓ F-2 FIXED: Server correctly rejected unverifiable signature")
        else:
            print(f"? F-2: Different error: {error_msg}")

def test_f8_algorithm_mismatch():
    """Test F-8: algorithm mismatch should FAIL but currently succeeds"""
    print("\\n=== F-8 Test: Algorithm Mismatch (should FAIL) ===")
    
    options_url = "http://localhost:8080/attestation/options"
    request_data = {
        "username": "f8test@example.com",
        "displayName": "F8 Test User", 
        "attestation": "direct"
    }
    
    options_response = requests.post(options_url, json=request_data)
    if options_response.status_code != 200:
        print(f"Failed to get options: {options_response.text}")
        return
        
    options_data = options_response.json()
    challenge = options_data["challenge"]
    
    client_data = {
        "type": "webauthn.create",
        "challenge": challenge,
        "origin": "http://localhost:8080"
    }
    client_data_json = json.dumps(client_data, separators=(',', ':'))
    client_data_b64 = base64.urlsafe_b64encode(client_data_json.encode()).decode().rstrip('=')
    
    # Create attestation with algorithm that doesn't match certificate
    rp_id_hash = bytes([0x49, 0x96, 0x0d, 0xe5, 0x88, 0x0e, 0x8c, 0x68, 0x74, 0x34, 0x17, 0x0f, 0x64, 0x76, 0x60, 0x5b,
                       0x8f, 0xe4, 0xae, 0xb9, 0xa2, 0x86, 0x32, 0xc7, 0x99, 0x5c, 0xf3, 0xba, 0x83, 0x1d, 0x97, 0x63])
    flags = bytes([0x41])
    sign_count = bytes([0x00, 0x00, 0x00, 0x00])
    aaguid = bytes([0x00] * 16)
    cred_id_length = bytes([0x00, 0x10])
    cred_id = b"f8-test-cred1234"
    
    cose_key = {
        1: 2,
        3: -7,   # ES256 in the credential
        -1: 1,
        -2: bytes([0x70] * 32),
        -3: bytes([0x80] * 32)
    }
    
    cose_key_cbor = cbor2.dumps(cose_key)
    auth_data = rp_id_hash + flags + sign_count + aaguid + cred_id_length + cred_id + cose_key_cbor
    
    # F-8: Algorithm mismatch - claim RS256 in attStmt but certificate/key is ES256
    mismatched_signature = bytes([0x30, 0x45, 0x02, 0x21, 0x00] + [0x88] * 32 + [0x02, 0x20] + [0x99] * 32)
    fake_cert = bytes([0x30, 0x82, 0x01, 0xFF] + [0x55] * 500)
    
    att_stmt = {
        "alg": -257,  # RS256 - but this doesn't match the ES256 key above
        "sig": mismatched_signature,
        "x5c": [fake_cert]
    }
    
    attestation_object = {
        "fmt": "packed", 
        "attStmt": att_stmt,
        "authData": auth_data
    }
    
    attestation_object_bytes = cbor2.dumps(attestation_object)
    attestation_object_b64 = base64.urlsafe_b64encode(attestation_object_bytes).decode().rstrip('=')
    
    credential = {
        "id": "ZjgtdGVzdC1jcmVkMTIzNA",
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
        print("✗ F-8 ISSUE: Server accepted algorithm mismatch (should have failed)")
        print("This matches the FIDO conformance failure: 'Promise succeeded when expected to fail!'")
    else:
        response_data = response.json()
        error_msg = response_data.get("errorMessage", "")
        if "algorithm" in error_msg.lower() or "metadata" in error_msg.lower():
            print("✓ F-8 FIXED: Server correctly rejected algorithm mismatch")
        else:
            print(f"? F-8: Different error: {error_msg}")

if __name__ == "__main__":
    print("Testing FIDO Conformance Failures F-2, F-8, F-13")
    print("These are currently succeeding when they should fail")
    print("=" * 60)
    
    try:
        test_f2_unverifiable_signature() 
        test_f8_algorithm_mismatch()
        
        print("\\n" + "=" * 60)
        print("Test Complete")
        print("\\nNext steps:")
        print("- If tests show '✗ ISSUE', the validation needs to be stricter")
        print("- If tests show '✓ FIXED', those conformance failures should be resolved")
        
    except Exception as e:
        print(f"Test failed with exception: {e}")
        import traceback
        traceback.print_exc()