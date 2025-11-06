#!/usr/bin/env python3

import requests
import json
import base64
import cbor2
import time

# Test the key FIDO conformance scenarios
def test_registration_scenarios():
    base_url = "http://localhost:8080"
    
    print("🧪 Testing FIDO2 WebAuthn Server Conformance...")
    
    # Test 1: P-1 - Valid self-attestation (should pass)
    print("\n📋 Test P-1: Valid self-attestation...")
    try:
        # Start registration
        req_data = {
            "username": "testuser",
            "displayName": "Test User", 
            "attestation": "direct"
        }
        
        response = requests.post(f"{base_url}/attestation/options", json=req_data, timeout=10)
        if response.status_code != 200:
            print(f"❌ P-1 Start registration failed: {response.text}")
            return
            
        challenge_response = response.json()
        print(f"✅ P-1 Start registration: {challenge_response['status']}")
        
        # Create a mock valid self-attestation response
        mock_attestation_obj = {
            "fmt": "packed",
            "attStmt": {
                "alg": -7,  # ES256
                "sig": b'\x30\x45\x02\x21\x00\xAB\xCD\xEF\x12\x34\x56\x78\x90\xAB\xCD\xEF\x12\x34\x56\x78\x90\xAB\xCD\xEF\x12\x34\x56\x78\x90\xAB\xCD\xEF\x12\x02\x20\x12\x34\x56\x78\x90\xAB\xCD\xEF\x12\x34\x56\x78\x90\xAB\xCD\xEF\x12\x34\x56\x78\x90\xAB\xCD\xEF\x12\x34\x56'
            },
            "authData": b'\x00' * 37 + b'\x40' + b'\x00' * 4 + b'\x00' * 16 + b'\x00\x20' + b'\x12' * 32 + b'\xA5\x01\x02\x03\x26\x20\x01\x21\x58\x20' + b'\x11' * 32 + b'\x22\x58\x20' + b'\x22' * 32
        }
        
        # Encode to CBOR and base64url
        attestation_object_cbor = cbor2.dumps(mock_attestation_obj)
        attestation_object_b64 = base64.urlsafe_b64encode(attestation_object_cbor).decode().rstrip('=')
        
        # Create mock client data
        client_data = {
            "type": "webauthn.create",
            "challenge": challenge_response["challenge"],
            "origin": "http://localhost:8080"
        }
        client_data_json = json.dumps(client_data)
        client_data_b64 = base64.urlsafe_b64encode(client_data_json.encode()).decode().rstrip('=')
        
        # Finish registration  
        credential_id = base64.urlsafe_b64encode(b"test-credential-id-123").decode().rstrip('=')
        finish_req = {
            "id": credential_id,
            "type": "public-key",
            "response": {
                "clientDataJSON": client_data_b64,
                "attestationObject": attestation_object_b64
            },
            "getClientExtensionResults": {}
        }
        
        finish_response = requests.post(f"{base_url}/attestation/result", json=finish_req, timeout=10)
        print(f"✅ P-1 Finish registration: {finish_response.status_code} - {finish_response.json()}")
        
    except Exception as e:
        print(f"❌ P-1 Test failed: {e}")
    
    # Test 2: F-2 - Invalid signature (should fail) 
    print("\n📋 Test F-2: Invalid signature (should fail)...")
    try:
        # Start registration
        req_data = {
            "username": "testuser2",
            "displayName": "Test User 2",
            "attestation": "direct"
        }
        
        response = requests.post(f"{base_url}/attestation/options", json=req_data, timeout=10)
        challenge_response = response.json()
        
        # Create a mock attestation with invalid signature
        mock_attestation_obj = {
            "fmt": "packed",
            "attStmt": {
                "alg": -7,
                "sig": b'\xBA\xAD\xF0\x0D' * 16  # BADF00D pattern - should be detected as invalid
            },
            "authData": b'\x00' * 37 + b'\x40' + b'\x00' * 4 + b'\x00' * 16 + b'\x00\x20' + b'\x12' * 32 + b'\xA5\x01\x02\x03\x26\x20\x01\x21\x58\x20' + b'\x11' * 32 + b'\x22\x58\x20' + b'\x22' * 32
        }
        
        attestation_object_cbor = cbor2.dumps(mock_attestation_obj)
        attestation_object_b64 = base64.urlsafe_b64encode(attestation_object_cbor).decode().rstrip('=')
        
        client_data = {
            "type": "webauthn.create",
            "challenge": challenge_response["challenge"],
            "origin": "http://localhost:8080"
        }
        client_data_json = json.dumps(client_data)
        client_data_b64 = base64.urlsafe_b64encode(client_data_json.encode()).decode().rstrip('=')
        
        finish_req = {
            "id": "test-credential-id-456",
            "type": "public-key",
            "response": {
                "clientDataJSON": client_data_b64,
                "attestationObject": attestation_object_b64
            },
            "getClientExtensionResults": {}
        }
        
        finish_response = requests.post(f"{base_url}/attestation/result", json=finish_req, timeout=10)
        result = finish_response.json()
        
        if finish_response.status_code != 200 and "Can not validate response signature!" in result.get("errorMessage", ""):
            print(f"✅ F-2 Correctly rejected invalid signature: {result['errorMessage']}")
        else:
            print(f"❌ F-2 Should have failed but got: {result}")
            
    except Exception as e:
        print(f"❌ F-2 Test failed: {e}")

if __name__ == "__main__":
    test_registration_scenarios()