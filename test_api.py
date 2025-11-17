#!/usr/bin/env python3
"""
Test script for FIDO2/WebAuthn Relying Party Server API endpoints
Validates that the server responds correctly to FIDO conformance test requests.
"""

import json
import requests
import base64
import os
from urllib.parse import urljoin

# Server configuration
SERVER_BASE_URL = "http://localhost:8080"

def test_health_endpoint():
    """Test the health check endpoint"""
    print("🩺 Testing health check endpoint...")
    try:
        response = requests.get(urljoin(SERVER_BASE_URL, "/health"))
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        print(f"✅ Health check passed: {data}")
        return True
    except Exception as e:
        print(f"❌ Health check failed: {e}")
        return False

def test_attestation_options():
    """Test POST /attestation/options - Registration challenge generation"""
    print("🔐 Testing attestation options (registration challenge)...")
    
    payload = {
        "username": "johndoe@example.com",
        "displayName": "John Doe",
        "authenticatorSelection": {
            "requireResidentKey": False,
            "authenticatorAttachment": "cross-platform",
            "userVerification": "preferred"
        },
        "attestation": "direct"
    }
    
    try:
        response = requests.post(
            urljoin(SERVER_BASE_URL, "/attestation/options"),
            json=payload,
            headers={"Content-Type": "application/json"}
        )
        
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.text[:200]}...")
        
        if response.status_code == 200:
            data = response.json()
            
            # Validate response structure
            required_fields = ["status", "rp", "user", "challenge", "pubKeyCredParams", "timeout"]
            for field in required_fields:
                assert field in data, f"Missing required field: {field}"
            
            assert data["status"] == "ok"
            assert len(data["challenge"]) > 0, "Challenge should not be empty"
            assert data["rp"]["name"] is not None
            assert data["user"]["id"] is not None
            assert data["user"]["name"] == payload["username"]
            assert data["user"]["displayName"] == payload["displayName"]
            
            print(f"✅ Attestation options test passed")
            print(f"  Challenge: {data['challenge'][:16]}...")
            print(f"  User ID: {data['user']['id'][:16]}...")
            print(f"  RP Name: {data['rp']['name']}")
            
            return data["challenge"]
            
    except Exception as e:
        print(f"❌ Attestation options test failed: {e}")
        return None

def test_assertion_options():
    """Test POST /assertion/options - Authentication challenge generation"""
    print("🔑 Testing assertion options (authentication challenge)...")
    
    payload = {
        "username": "johndoe@example.com",
        "userVerification": "required"
    }
    
    try:
        response = requests.post(
            urljoin(SERVER_BASE_URL, "/assertion/options"),
            json=payload,
            headers={"Content-Type": "application/json"}
        )
        
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.text[:200]}...")
        
        # For authentication, the user might not exist yet, so we expect 404
        if response.status_code == 404:
            data = response.json()
            assert data["status"] == "failed"
            print("✅ Assertion options correctly returned 404 for non-existent user")
            return True
        elif response.status_code == 200:
            data = response.json()
            required_fields = ["status", "challenge", "timeout", "rpId", "allowCredentials"]
            for field in required_fields:
                assert field in data, f"Missing required field: {field}"
            
            assert data["status"] == "ok"
            print("✅ Assertion options test passed")
            return True
            
    except Exception as e:
        print(f"❌ Assertion options test failed: {e}")
        return False

def test_invalid_endpoints():
    """Test various invalid requests to ensure proper error handling"""
    print("🚫 Testing invalid endpoints and payloads...")
    
    test_cases = [
        {
            "name": "Empty username in attestation options",
            "url": "/attestation/options",
            "payload": {"username": "", "displayName": "Test"},
            "expected_status": 400
        },
        {
            "name": "Missing displayName in attestation options", 
            "url": "/attestation/options",
            "payload": {"username": "test@example.com"},
            "expected_status": 400
        },
        {
            "name": "Empty username in assertion options",
            "url": "/assertion/options", 
            "payload": {"username": ""},
            "expected_status": 400
        },
        {
            "name": "Invalid endpoint",
            "url": "/invalid/endpoint",
            "payload": {},
            "expected_status": 404
        }
    ]
    
    passed = 0
    for test_case in test_cases:
        try:
            if test_case["url"] == "/invalid/endpoint":
                response = requests.post(urljoin(SERVER_BASE_URL, test_case["url"]))
            else:
                response = requests.post(
                    urljoin(SERVER_BASE_URL, test_case["url"]),
                    json=test_case["payload"],
                    headers={"Content-Type": "application/json"}
                )
            
            if response.status_code == test_case["expected_status"]:
                print(f"✅ {test_case['name']}: Expected {test_case['expected_status']}, got {response.status_code}")
                passed += 1
            else:
                print(f"❌ {test_case['name']}: Expected {test_case['expected_status']}, got {response.status_code}")
                
        except Exception as e:
            print(f"❌ {test_case['name']}: Exception - {e}")
    
    print(f"Invalid endpoint tests: {passed}/{len(test_cases)} passed")
    return passed == len(test_cases)

def main():
    """Run all API tests"""
    print("🚀 Starting FIDO2/WebAuthn Server API Tests")
    print("=" * 50)
    
    tests_passed = 0
    total_tests = 4
    
    # Test 1: Health check
    if test_health_endpoint():
        tests_passed += 1
    print()
    
    # Test 2: Attestation options 
    challenge = test_attestation_options()
    if challenge:
        tests_passed += 1
    print()
    
    # Test 3: Assertion options
    if test_assertion_options():
        tests_passed += 1
    print()
    
    # Test 4: Invalid requests
    if test_invalid_endpoints():
        tests_passed += 1
    print()
    
    print("=" * 50)
    print(f"🏁 Tests completed: {tests_passed}/{total_tests} passed")
    
    if tests_passed == total_tests:
        print("🎉 All tests passed! Server is working correctly.")
        return 0
    else:
        print("❌ Some tests failed. Check server logs for details.")
        return 1

if __name__ == "__main__":
    exit(main())