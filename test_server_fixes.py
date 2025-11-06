#!/usr/bin/env python3

import requests
import json
import sys

def test_extensions_exact_match():
    """Test that extensions are returned exactly as requested (FIDO conformance P-1)"""
    print("Testing extensions exact match...")
    
    url = "http://localhost:8080/attestation/options"
    payload = {
        "username": "testuser@example.com",
        "displayName": "Test User",
        "extensions": {
            "example.extension.bool": True
        }
    }
    
    response = requests.post(url, json=payload)
    
    if response.status_code == 200:
        data = response.json()
        if "extensions" in data:
            expected = {"example.extension.bool": True}
            actual = data["extensions"]
            if actual == expected:
                print("✅ Extensions exact match test PASSED")
                return True
            else:
                print(f"❌ Extensions mismatch. Expected: {expected}, Got: {actual}")
                return False
        else:
            print("❌ No extensions field in response")
            return False
    else:
        print(f"❌ Request failed with status {response.status_code}")
        return False

def test_missing_field_validation():
    """Test that missing required fields are properly validated"""
    print("\nTesting missing field validation...")
    
    url = "http://localhost:8080/attestation/options"
    payload = {
        "displayName": "Test User"
        # Missing username field
    }
    
    response = requests.post(url, json=payload)
    
    if response.status_code == 400:
        data = response.json()
        if data.get("status") == "failed" and "username" in data.get("errorMessage", ""):
            print("✅ Missing field validation test PASSED")
            return True
        else:
            print(f"❌ Wrong error message: {data}")
            return False
    else:
        print(f"❌ Expected 400 status, got {response.status_code}")
        return False

def test_invalid_type_validation():
    """Test that invalid credential type is properly validated"""
    print("\nTesting invalid type validation...")
    
    # First get a challenge
    url = "http://localhost:8080/attestation/options"
    payload = {
        "username": "testuser@example.com",
        "displayName": "Test User"
    }
    
    options_response = requests.post(url, json=payload)
    if options_response.status_code != 200:
        print("❌ Failed to get registration options")
        return False
    
    # Now try to finish registration with invalid type
    finish_url = "http://localhost:8080/attestation/result"
    invalid_credential = {
        "id": "test-credential-id",
        "type": "invalid-type",  # Should be "public-key"
        "response": {
            "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoidGVzdCIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCJ9",
            "attestationObject": "test"
        }
    }
    
    response = requests.post(finish_url, json=invalid_credential)
    
    if response.status_code == 400:
        data = response.json()
        if data.get("status") == "failed":
            print("✅ Invalid type validation test PASSED")
            return True
        else:
            print(f"❌ Wrong error response: {data}")
            return False
    else:
        print(f"❌ Expected 400 status, got {response.status_code}")
        return False

def test_base64url_validation():
    """Test that invalid base64url encoding is properly validated"""
    print("\nTesting base64url validation...")
    
    # First get a challenge
    url = "http://localhost:8080/attestation/options"
    payload = {
        "username": "testuser@example.com",
        "displayName": "Test User"
    }
    
    options_response = requests.post(url, json=payload)
    if options_response.status_code != 200:
        print("❌ Failed to get registration options")
        return False
    
    # Now try to finish registration with invalid base64url
    finish_url = "http://localhost:8080/attestation/result"
    invalid_credential = {
        "id": "invalid+base64/with+padding==",  # Invalid base64url (contains +, /, =)
        "type": "public-key",
        "response": {
            "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoidGVzdCIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCJ9",
            "attestationObject": "test"
        }
    }
    
    response = requests.post(finish_url, json=invalid_credential)
    
    if response.status_code == 400:
        data = response.json()
        if data.get("status") == "failed":
            print("✅ Base64url validation test PASSED")
            return True
        else:
            print(f"❌ Wrong error response: {data}")
            return False
    else:
        print(f"❌ Expected 400 status, got {response.status_code}: {response.text}")
        return False

def main():
    print("Testing FIDO2 WebAuthn Server Fixes\n")
    
    tests = [
        test_extensions_exact_match,
        test_missing_field_validation,
        test_invalid_type_validation,
        test_base64url_validation
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"❌ Test failed with exception: {e}")
    
    print(f"\n🎯 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Server fixes are working correctly.")
        return 0
    else:
        print("⚠️  Some tests failed. Please check the implementation.")
        return 1

if __name__ == "__main__":
    sys.exit(main())