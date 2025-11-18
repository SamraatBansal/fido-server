#!/usr/bin/env python3
"""
Simple endpoint test script for FIDO2 server conformance
"""

import requests
import json
import sys

def test_attestation_options():
    """Test the registration begin endpoint"""
    url = "http://localhost:8080/attestation/options"
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
        response = requests.post(url, json=payload, headers={'Content-Type': 'application/json'})
        print(f"Registration Begin - Status: {response.status_code}")
        print(f"Response: {response.text}")
        
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "ok" and "challenge" in data:
                print("✅ Registration begin endpoint working correctly")
                return data
            else:
                print("❌ Registration begin endpoint response invalid")
                return None
        else:
            print("❌ Registration begin endpoint failed")
            return None
            
    except Exception as e:
        print(f"❌ Registration begin endpoint error: {e}")
        return None

def test_assertion_options():
    """Test the authentication begin endpoint"""
    url = "http://localhost:8080/assertion/options"
    payload = {
        "username": "johndoe@example.com",
        "userVerification": "required"
    }
    
    try:
        response = requests.post(url, json=payload, headers={'Content-Type': 'application/json'})
        print(f"Authentication Begin - Status: {response.status_code}")
        print(f"Response: {response.text}")
        
        # This might fail if no user exists, which is expected
        if response.status_code == 404:
            data = response.json()
            if "User does not exists!" in data.get("errorMessage", ""):
                print("✅ Authentication begin endpoint correctly reports no user")
                return True
        elif response.status_code == 200:
            print("✅ Authentication begin endpoint working")
            return True
        else:
            print("❌ Authentication begin endpoint unexpected response")
            return False
            
    except Exception as e:
        print(f"❌ Authentication begin endpoint error: {e}")
        return False

def test_health_endpoint():
    """Test the health check endpoint"""
    url = "http://localhost:8080/health"
    
    try:
        response = requests.get(url)
        print(f"Health Check - Status: {response.status_code}")
        print(f"Response: {response.text}")
        
        if response.status_code == 200:
            print("✅ Health check endpoint working")
            return True
        else:
            print("❌ Health check endpoint failed")
            return False
            
    except Exception as e:
        print(f"❌ Health check endpoint error: {e}")
        return False

def main():
    print("🧪 Testing FIDO2 Server Endpoints")
    print("=" * 50)
    
    # Test health check first
    health_ok = test_health_endpoint()
    print()
    
    # Test registration begin
    reg_data = test_attestation_options()
    print()
    
    # Test authentication begin
    auth_ok = test_assertion_options()
    print()
    
    print("=" * 50)
    if health_ok and reg_data and auth_ok:
        print("✅ All basic endpoint tests passed!")
        
        # Print sample response structure
        print("\n📋 Sample Registration Response Structure:")
        if reg_data:
            print(json.dumps({k: v for k, v in reg_data.items() if k not in ['challenge']}, indent=2))
        
        return 0
    else:
        print("❌ Some endpoint tests failed!")
        return 1

if __name__ == "__main__":
    sys.exit(main())