#!/usr/bin/env python3

import requests
import json
import base64
import cbor2

def create_simple_packed_attestation():
    """Create a simple packed attestation that should trigger x5c validation"""
    
    # Minimal authenticator data that should parse correctly
    rp_id_hash = bytes([0x49, 0x96, 0x0d, 0xe5, 0x88, 0x0e, 0x8c, 0x68, 0x74, 0x34, 0x17, 0x0f, 0x64, 0x76, 0x60, 0x5b,
                       0x8f, 0xe4, 0xae, 0xb9, 0xa2, 0x86, 0x32, 0xc7, 0x99, 0x5c, 0xf3, 0xba, 0x83, 0x1d, 0x97, 0x63])
    flags = bytes([0x41])  # UP=1, AT=1
    sign_count = bytes([0x00, 0x00, 0x00, 0x00])
    aaguid = bytes([0x00] * 16)
    cred_id_length = bytes([0x00, 0x10])  # 16 bytes
    cred_id = b"test-credential1"  # exactly 16 bytes
    
    # Valid COSE key structure
    cose_key = {
        1: 2,    # kty (Key Type): EC2
        3: -7,   # alg (Algorithm): ES256
        -1: 1,   # crv (Curve): P-256
        -2: bytes([0x01] * 32),  # x coordinate
        -3: bytes([0x02] * 32)   # y coordinate  
    }
    
    cose_key_cbor = cbor2.dumps(cose_key)
    
    auth_data = rp_id_hash + flags + sign_count + aaguid + cred_id_length + cred_id + cose_key_cbor
    
    # Packed attestation statement WITHOUT x5c (this should fail for direct attestation)
    att_stmt = {
        "alg": -7,
        "sig": bytes([0x30, 0x45, 0x02, 0x21] + [0x00] * 32 + [0x02, 0x20] + [0x01] * 32)  # Valid DER signature format
    }
    
    attestation_object = {
        "fmt": "packed",
        "attStmt": att_stmt,
        "authData": auth_data
    }
    
    return cbor2.dumps(attestation_object)

def test_direct_attestation_x5c_requirement():
    """Test that direct attestation requires x5c for packed format"""
    print("=== Testing Direct Attestation x5c Requirement ===")
    
    # Request registration options with direct attestation
    options_url = "http://localhost:8080/attestation/options"
    request_data = {
        "username": "directtest@example.com",
        "displayName": "Direct Test User",
        "attestation": "direct"
    }
    
    print(f"Requesting options with attestation: {request_data['attestation']}")
    options_response = requests.post(options_url, json=request_data)
    
    if options_response.status_code != 200:
        print(f"Failed to get options: {options_response.text}")
        return
        
    options_data = options_response.json()
    challenge = options_data["challenge"]
    print(f"Got challenge: {challenge}")
    print(f"Attestation in response: {options_data.get('attestation')}")
    
    # Create valid client data
    client_data = {
        "type": "webauthn.create",
        "challenge": challenge,
        "origin": "http://localhost:8080"
    }
    client_data_json = json.dumps(client_data, separators=(',', ':'))
    client_data_b64 = base64.urlsafe_b64encode(client_data_json.encode()).decode().rstrip('=')
    
    # Create packed attestation WITHOUT x5c
    attestation_object_bytes = create_simple_packed_attestation()
    attestation_object_b64 = base64.urlsafe_b64encode(attestation_object_bytes).decode().rstrip('=')
    
    # Debug: Print the attestation object structure
    parsed_att_obj = cbor2.loads(attestation_object_bytes)
    print(f"Attestation object format: {parsed_att_obj['fmt']}")
    print(f"AttStmt keys: {list(parsed_att_obj['attStmt'].keys())}")
    print(f"Has x5c: {'x5c' in parsed_att_obj['attStmt']}")
    
    credential = {
        "id": "dGVzdC1jcmVkZW50aWFsMQ",  # "test-credential1" base64url
        "type": "public-key",
        "response": {
            "clientDataJSON": client_data_b64,
            "attestationObject": attestation_object_b64
        },
        "getClientExtensionResults": {}
    }
    
    print("\\nSending credential to finish registration...")
    finish_url = "http://localhost:8080/attestation/result"
    response = requests.post(finish_url, json=credential)
    
    print(f"Status: {response.status_code}")
    print(f"Response: {response.text}")
    
    if response.status_code != 200:
        response_data = response.json()
        error_msg = response_data.get("errorMessage", "")
        
        if "Missing required field: attestationObject.attStmt.x5c" in error_msg:
            print("\\n✓ SUCCESS: Server correctly rejected packed attestation without x5c for direct attestation")
            print("This should fix FIDO conformance tests P-5, P-8, P-9, P-12")
        elif "x5c" in error_msg.lower():
            print(f"\\n? x5c-related error (different message): {error_msg}")
        else:
            print(f"\\n✗ Different error (x5c validation may not be working): {error_msg}")
    else:
        print("\\n✗ PROBLEM: Server accepted packed attestation without x5c for direct attestation")
        print("This indicates the x5c validation is not working correctly")

def test_indirect_attestation_should_work():
    """Test that indirect attestation works without x5c"""
    print("\\n=== Testing Indirect Attestation (should work without x5c) ===")
    
    options_url = "http://localhost:8080/attestation/options"
    request_data = {
        "username": "indirecttest@example.com", 
        "displayName": "Indirect Test User",
        "attestation": "indirect"  # Should allow packed without x5c
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
    
    attestation_object_bytes = create_simple_packed_attestation()
    attestation_object_b64 = base64.urlsafe_b64encode(attestation_object_bytes).decode().rstrip('=')
    
    credential = {
        "id": "aW5kaXJlY3QtdGVzdC1jcmVk",
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
        print("✓ Indirect attestation worked without x5c (correct)")
    else:
        print(f"? Indirect attestation failed: {response.text}")

if __name__ == "__main__":
    print("Debug x5c Validation Issue")
    print("=" * 50)
    
    try:
        test_direct_attestation_x5c_requirement()
        test_indirect_attestation_should_work()
        
        print("\\n" + "=" * 50)
        print("Debug Complete")
        
    except Exception as e:
        print(f"Test failed with exception: {e}")
        import traceback
        traceback.print_exc()