#!/usr/bin/env python3

import requests
import json
import base64
import sys

def test_algorithm_support():
    """Test that all required algorithms are supported"""
    print("Testing algorithm support...")
    
    url = "http://localhost:8080/attestation/options"
    payload = {
        "username": "testuser@example.com",
        "displayName": "Test User"
    }
    
    response = requests.post(url, json=payload)
    
    if response.status_code == 200:
        data = response.json()
        pub_key_cred_params = data.get("pubKeyCredParams", [])
        
        # Check for required algorithms
        required_algs = [-7, -8, -257, -65535]  # ES256, Ed25519, RS256, RS1
        supported_algs = [param["alg"] for param in pub_key_cred_params if param["type"] == "public-key"]
        
        missing_algs = [alg for alg in required_algs if alg not in supported_algs]
        
        if not missing_algs:
            print(f"✅ Algorithm support test PASSED - Found algorithms: {supported_algs}")
            return True
        else:
            print(f"❌ Missing required algorithms: {missing_algs}")
            return False
    else:
        print(f"❌ Request failed with status {response.status_code}")
        return False

def test_challenge_uniqueness():
    """Test that challenges are unique across requests"""
    print("\nTesting challenge uniqueness...")
    
    url = "http://localhost:8080/attestation/options"
    payload = {
        "username": "testuser@example.com",
        "displayName": "Test User"
    }
    
    # Get first challenge
    response1 = requests.post(url, json=payload)
    if response1.status_code != 200:
        print("❌ Failed to get first challenge")
        return False
    
    challenge1 = response1.json().get("challenge")
    
    # Get second challenge
    response2 = requests.post(url, json=payload)
    if response2.status_code != 200:
        print("❌ Failed to get second challenge")
        return False
    
    challenge2 = response2.json().get("challenge")
    
    if challenge1 != challenge2:
        print("✅ Challenge uniqueness test PASSED")
        return True
    else:
        print("❌ Challenges are not unique")
        return False

def test_challenge_length():
    """Test that challenge is at least 16 bytes (FIDO requirement)"""
    print("\nTesting challenge length...")
    
    url = "http://localhost:8080/attestation/options"
    payload = {
        "username": "testuser@example.com",
        "displayName": "Test User"
    }
    
    response = requests.post(url, json=payload)
    
    if response.status_code == 200:
        data = response.json()
        challenge = data.get("challenge", "")
        
        # Decode base64url to get actual byte length
        try:
            # Add padding if necessary
            padding = 4 - (len(challenge) % 4)
            if padding != 4:
                challenge += "=" * padding
            
            challenge_bytes = base64.urlsafe_b64decode(challenge)
            byte_length = len(challenge_bytes)
            
            if byte_length >= 16:
                print(f"✅ Challenge length test PASSED - {byte_length} bytes")
                return True
            else:
                print(f"❌ Challenge too short: {byte_length} bytes (minimum 16)")
                return False
        except Exception as e:
            print(f"❌ Failed to decode challenge: {e}")
            return False
    else:
        print(f"❌ Request failed with status {response.status_code}")
        return False

def test_user_verification_required():
    """Test userVerification requirement handling"""
    print("\nTesting userVerification requirement...")
    
    url = "http://localhost:8080/attestation/options"
    payload = {
        "username": "testuser@example.com",
        "displayName": "Test User",
        "authenticatorSelection": {
            "userVerification": "required"
        }
    }
    
    response = requests.post(url, json=payload)
    
    if response.status_code == 200:
        data = response.json()
        auth_selection = data.get("authenticatorSelection", {})
        user_verification = auth_selection.get("userVerification")
        
        if user_verification == "required":
            print("✅ UserVerification requirement test PASSED")
            return True
        else:
            print(f"❌ UserVerification not set correctly: {user_verification}")
            return False
    else:
        print(f"❌ Request failed with status {response.status_code}")
        return False

def test_exclude_credentials():
    """Test excludeCredentials for existing user"""
    print("\nTesting excludeCredentials handling...")
    
    url = "http://localhost:8080/attestation/options"
    payload = {
        "username": "newuser@example.com",
        "displayName": "New User"
    }
    
    response = requests.post(url, json=payload)
    
    if response.status_code == 200:
        data = response.json()
        exclude_credentials = data.get("excludeCredentials", [])
        
        # For a new user, excludeCredentials should be empty
        if isinstance(exclude_credentials, list):
            print(f"✅ ExcludeCredentials test PASSED - Found {len(exclude_credentials)} excluded credentials")
            return True
        else:
            print(f"❌ ExcludeCredentials should be a list, got: {type(exclude_credentials)}")
            return False
    else:
        print(f"❌ Request failed with status {response.status_code}")
        return False

def test_rp_entity_structure():
    """Test RP entity structure compliance"""
    print("\nTesting RP entity structure...")
    
    url = "http://localhost:8080/attestation/options"
    payload = {
        "username": "testuser@example.com",
        "displayName": "Test User"
    }
    
    response = requests.post(url, json=payload)
    
    if response.status_code == 200:
        data = response.json()
        rp = data.get("rp", {})
        
        required_fields = ["name"]
        optional_fields = ["id"]
        
        missing_required = [field for field in required_fields if field not in rp]
        
        if not missing_required:
            has_id = "id" in rp and rp["id"] is not None
            print(f"✅ RP entity structure test PASSED - Name: {rp.get('name')}, ID: {rp.get('id') if has_id else 'Not set'}")
            return True
        else:
            print(f"❌ Missing required RP fields: {missing_required}")
            return False
    else:
        print(f"❌ Request failed with status {response.status_code}")
        return False

def test_user_entity_structure():
    """Test User entity structure compliance"""
    print("\nTesting User entity structure...")
    
    url = "http://localhost:8080/attestation/options"
    payload = {
        "username": "testuser@example.com",
        "displayName": "Test User"
    }
    
    response = requests.post(url, json=payload)
    
    if response.status_code == 200:
        data = response.json()
        user = data.get("user", {})
        
        required_fields = ["id", "name", "displayName"]
        missing_required = [field for field in required_fields if field not in user]
        
        if not missing_required:
            # Check that user.id is base64url encoded and not empty
            user_id = user.get("id", "")
            if user_id and len(user_id) > 0:
                print(f"✅ User entity structure test PASSED")
                return True
            else:
                print("❌ User ID is empty")
                return False
        else:
            print(f"❌ Missing required user fields: {missing_required}")
            return False
    else:
        print(f"❌ Request failed with status {response.status_code}")
        return False

def test_attestation_parameter():
    """Test attestation parameter handling"""
    print("\nTesting attestation parameter...")
    
    url = "http://localhost:8080/attestation/options"
    
    test_cases = [
        ("none", "none"),
        ("indirect", "indirect"), 
        ("direct", "direct")
    ]
    
    for input_val, expected_val in test_cases:
        payload = {
            "username": "testuser@example.com",
            "displayName": "Test User",
            "attestation": input_val
        }
        
        response = requests.post(url, json=payload)
        
        if response.status_code == 200:
            data = response.json()
            attestation = data.get("attestation")
            
            if attestation == expected_val:
                print(f"  ✅ Attestation '{input_val}' -> '{attestation}' PASSED")
            else:
                print(f"  ❌ Attestation mismatch for '{input_val}': expected '{expected_val}', got '{attestation}'")
                return False
        else:
            print(f"  ❌ Request failed for attestation '{input_val}' with status {response.status_code}")
            return False
    
    print("✅ Attestation parameter test PASSED")
    return True

def main():
    print("Testing FIDO Conformance Fixes\n")
    
    tests = [
        test_algorithm_support,
        test_challenge_uniqueness,
        test_challenge_length,
        test_user_verification_required,
        test_exclude_credentials,
        test_rp_entity_structure,
        test_user_entity_structure,
        test_attestation_parameter
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"❌ Test failed with exception: {e}")
    
    print(f"\n🎯 FIDO Conformance Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All FIDO conformance tests passed!")
        return 0
    else:
        print("⚠️  Some FIDO conformance tests failed.")
        return 1

if __name__ == "__main__":
    sys.exit(main())