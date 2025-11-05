#!/usr/bin/env python3

import requests
import json
import subprocess
import time
import signal
import os
import base64

def run_fido_validation_tests():
    print("Starting FIDO validation conformance tests...")
    
    # Start the server in the background
    print("Starting server...")
    env = os.environ.copy()
    env['PORT'] = '9999'
    env['RUST_LOG'] = 'info'
    
    server = subprocess.Popen(
        ['./target/debug/fido2-minimal'],
        cwd='/tmp/cmhm3v1xr00xm3x03rcbqjvf2',
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    # Give the server time to start
    time.sleep(2)
    
    try:
        # Test the specific failing scenarios from FIDO conformance
        test_missing_fields()
        test_invalid_encodings()
        test_client_data_validation()
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        
    finally:
        # Kill the server
        try:
            server.terminate()
            server.wait(timeout=5)
        except:
            server.kill()

def test_missing_fields():
    print("\n=== Testing missing field validation ===")
    
    # First test a basic valid structure to make sure server is working
    test_basic_validation()
    
    # Test F-1: Missing "id" field (serde should reject this during deserialization)
    # Let's test with an empty id instead
    payload_empty_id = {
        "id": "",  # Empty id should fail our validation
        "response": {
            "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoidGVzdCIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6OTk5OSJ9",
            "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAA"
        },
        "type": "public-key",
        "getClientExtensionResults": {}
    }
    
    test_error_response("/attestation/result", payload_empty_id, "Empty id field should fail")
    
    # Test F-4: Missing "type" field
    payload_missing_type = {
        "id": "test123",
        "response": {
            "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0",
            "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAA"
        },
        "getClientExtensionResults": {}
    }
    
    test_error_response("/attestation/result", payload_missing_type, "Missing type field should fail")

def test_invalid_encodings():
    print("\n=== Testing invalid encoding validation ===")
    
    # Test F-3: Invalid base64url encoding for id
    payload_invalid_id = {
        "id": "invalid_base64_with_padding==",  # Should be base64url (no padding)
        "response": {
            "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0",
            "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAA"
        },
        "type": "public-key",
        "getClientExtensionResults": {}
    }
    
    test_error_response("/attestation/result", payload_invalid_id, "Invalid credential ID encoding should fail")
    
    # Test F-6: type not set to "public-key"
    payload_wrong_type = {
        "id": "dGVzdDEyMw",
        "response": {
            "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0",
            "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAA"
        },
        "type": "avocado-toast",
        "getClientExtensionResults": {}
    }
    
    test_error_response("/attestation/result", payload_wrong_type, "Wrong type field should fail")

def test_client_data_validation():
    print("\n=== Testing clientDataJSON validation ===")
    
    # Test F-11: Empty clientDataJSON
    payload_empty_client_data = {
        "id": "dGVzdDEyMw",
        "response": {
            "clientDataJSON": "",
            "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAA"
        },
        "type": "public-key",
        "getClientExtensionResults": {}
    }
    
    test_error_response("/attestation/result", payload_empty_client_data, "Empty clientDataJSON should fail")
    
    # Test F-14: Empty attestationObject
    payload_empty_attestation = {
        "id": "dGVzdDEyMw",
        "response": {
            "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0",
            "attestationObject": ""
        },
        "type": "public-key",
        "getClientExtensionResults": {}
    }
    
    test_error_response("/attestation/result", payload_empty_attestation, "Empty attestationObject should fail")

def test_error_response(endpoint, payload, description):
    try:
        response = requests.post(
            f"http://localhost:9999{endpoint}",
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        
        if response.status_code >= 400:
            data = response.json()
            if data.get("status") == "failed" and data.get("errorMessage"):
                print(f"✅ {description} - Got expected error: {data['errorMessage']}")
            else:
                print(f"❌ {description} - Got error but wrong format: {data}")
        else:
            print(f"❌ {description} - Should have failed but got {response.status_code}: {response.text}")
            
    except Exception as e:
        print(f"❌ {description} - Request failed: {e}")

if __name__ == "__main__":
    run_fido_validation_tests()