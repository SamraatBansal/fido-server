#!/usr/bin/env python3

import requests
import json
import sys

def test_registration_start():
    """Test the key failing cases from FIDO conformance tests"""
    url = "http://localhost:8080/attestation/options"
    
    # Basic test to get the registration options format
    print("=== Testing Registration Start ===")
    request_data = {
        "username": "testuser@example.com",
        "displayName": "Test User",
        "authenticatorSelection": {
            "requireResidentKey": False,
            "authenticatorAttachment": "cross-platform",
            "userVerification": "preferred"
        },
        "attestation": "direct"
    }
    
    response = requests.post(url, json=request_data)
    print(f"Status: {response.status_code}")
    
    if response.status_code == 200:
        data = response.json()
        print("Response structure:")
        print(json.dumps(data, indent=2))
        
        # Key checks for FIDO conformance
        print("\n=== FIDO Conformance Checks ===")
        
        # Check status and errorMessage
        if "status" in data and data["status"] == "ok":
            print("✓ status field correct")
        else:
            print("✗ status field missing or incorrect")
            
        if "errorMessage" in data and data["errorMessage"] == "":
            print("✓ errorMessage field correct")
        else:
            print("✗ errorMessage field missing or incorrect")
            
        # Check user fields
        if "user" in data:
            user = data["user"]
            if "id" in user and user["id"]:
                print("✓ user.id present")
            else:
                print("✗ user.id missing")
                
            if "name" in user and user["name"] == request_data["username"]:
                print("✓ user.name correct")
            else:
                print("✗ user.name missing or incorrect")
                
            if "displayName" in user and user["displayName"] == request_data["displayName"]:
                print("✓ user.displayName correct")
            else:
                print("✗ user.displayName missing or incorrect")
        else:
            print("✗ user field missing")
            
        # Check RP fields
        if "rp" in data:
            rp = data["rp"]
            if "name" in rp and rp["name"]:
                print("✓ rp.name present")
            else:
                print("✗ rp.name missing")
                
            if "id" in rp and rp["id"]:
                print("✓ rp.id present")
            else:
                print("✗ rp.id missing")
        else:
            print("✗ rp field missing")
            
        # Check challenge
        if "challenge" in data and data["challenge"]:
            challenge = data["challenge"]
            if len(challenge) >= 22:  # base64url encoded 16+ bytes
                print("✓ challenge length adequate")
            else:
                print("✗ challenge too short")
        else:
            print("✗ challenge missing")
            
        # Check pubKeyCredParams
        if "pubKeyCredParams" in data and isinstance(data["pubKeyCredParams"], list):
            params = data["pubKeyCredParams"]
            if len(params) > 0:
                print(f"✓ pubKeyCredParams present ({len(params)} algorithms)")
                # Check for required algorithms
                algs = [p.get("alg") for p in params if "alg" in p]
                required_algs = [-7, -257, -8]  # ES256, RS256, Ed25519
                for alg in required_algs:
                    if alg in algs:
                        print(f"✓ Algorithm {alg} supported")
                    else:
                        print(f"✗ Algorithm {alg} missing")
            else:
                print("✗ pubKeyCredParams empty")
        else:
            print("✗ pubKeyCredParams missing or invalid")
            
        # Check extensions (should be empty if not requested)
        if "extensions" not in data:
            print("✓ extensions field correctly omitted")
        elif data["extensions"] == {}:
            print("✓ extensions field present but empty")
        else:
            print("? extensions field has content")
            
        return data
    else:
        print(f"Error: {response.text}")
        return None

def test_registration_finish_basic():
    """Test basic registration finish to identify x5c issues"""
    print("\n=== Testing Registration Finish (Basic) ===")
    
    # First get registration options
    options_response = test_registration_start()
    if not options_response:
        print("Failed to get registration options")
        return
        
    # Test with a minimal attestation response (should fail with specific errors)
    finish_url = "http://localhost:8080/attestation/result"
    
    # This is a minimal test credential that should trigger specific validation errors
    test_credential = {
        "id": "dGVzdC1jcmVkZW50aWFsLWlk",  # "test-credential-id" base64url
        "type": "public-key",
        "response": {
            "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiZEdWemRDMWphR0ZzYkdWdVoyVSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCJ9",
            "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAALraVWanqkAfvZZLlhZXGDEAFHRlc3QtY3JlZGVudGlhbC1pZKUBAgMmIAEhWCDy8qKuEkwP07KjrKHSK3sMlJr1CYOuEcXQ9pB9cXe9jiJYIHOKyOGVPHrPBVkmS-MNP16ZF9jmnNgNf7YMpNgLCNxL"
        },
        "getClientExtensionResults": {}
    }
    
    response = requests.post(finish_url, json=test_credential)
    print(f"Status: {response.status_code}")
    print(f"Response: {response.text}")
    
    if response.status_code != 200:
        response_data = response.json()
        error_msg = response_data.get("errorMessage", "")
        
        # Check for specific FIDO conformance error patterns
        if "Missing required field: attestationObject.attStmt.x5c" in error_msg:
            print("✗ Key Issue: x5c validation problem detected")
        elif "Can not validate response signature" in error_msg:
            print("✗ Key Issue: Signature validation problem detected")
        elif "Missing required field" in error_msg:
            print(f"✗ Key Issue: Missing field problem: {error_msg}")
        else:
            print(f"? Other validation error: {error_msg}")

def test_packed_attestation_issue():
    """Test specific packed attestation scenarios that are failing"""
    print("\n=== Testing Packed Attestation Issues ===")
    
    # Get registration options first
    options_response = test_registration_start()
    if not options_response:
        return
        
    finish_url = "http://localhost:8080/attestation/result"
    
    # Test case that should trigger the "Missing required field: attestationObject.attStmt.x5c" error
    # This simulates the P-5, P-8, P-9, P-12 test failures
    packed_credential = {
        "id": "dGVzdC1wYWNrZWQtY3JlZA",
        "type": "public-key", 
        "response": {
            "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiZEdWemRDMWphR0ZzYkdWdVoyVSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCJ9",
            # Packed attestation without x5c - should fail per FIDO conformance
            "attestationObject": "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZ04mY3NpZ1hHMEUCIQDKlJP6dkJJU7pLaGJLNGE2C8yjL4N4pq8bjGMrq5K2UQIgWlIhMjY4NjgyODBhYWJjZGVmZ2hpams_k1N-V2XYmhNZaGF1dGhEYXRhWKRJlg3liA6MaHQ0Fw9kdmBbj-SuuaKGMseZXPO6gx2XYwAAAAAA"
        },
        "getClientExtensionResults": {}
    }
    
    response = requests.post(finish_url, json=packed_credential)
    print(f"Packed attestation test - Status: {response.status_code}")
    print(f"Response: {response.text}")
    
    if response.status_code != 200:
        response_data = response.json()
        error_msg = response_data.get("errorMessage", "")
        if "x5c" in error_msg:
            print("✓ Correctly detecting x5c requirement for packed attestation")
        else:
            print(f"? Unexpected error for packed attestation: {error_msg}")

if __name__ == "__main__":
    print("FIDO2 Conformance Key Issues Test")
    print("=" * 50)
    
    try:
        test_registration_start()
        test_registration_finish_basic()
        test_packed_attestation_issue()
        
        print("\n" + "=" * 50)
        print("Test Complete")
        
    except Exception as e:
        print(f"Test failed with exception: {e}")
        sys.exit(1)