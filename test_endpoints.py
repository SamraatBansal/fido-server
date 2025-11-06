#!/usr/bin/env python3
"""
Test script for FIDO2/WebAuthn API endpoints
This verifies the server responds correctly to conformance test requests
"""

import requests
import json
import base64
import time

# Test configuration
BASE_URL = "http://localhost:8080"
HEADERS = {"Content-Type": "application/json"}

def test_health_check():
    """Test the health check endpoint"""
    try:
        response = requests.get(f"{BASE_URL}/health")
        print(f"Health check: {response.status_code}")
        if response.status_code == 200:
            print(f"Response: {response.json()}")
            return True
    except Exception as e:
        print(f"Health check failed: {e}")
    return False

def test_registration_start():
    """Test registration start endpoint"""
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
        response = requests.post(f"{BASE_URL}/attestation/options", 
                               headers=HEADERS, 
                               json=payload)
        print(f"Registration start: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"Status: {data.get('status')}")
            if "challenge" in data:
                print(f"Challenge received: {data['challenge'][:20]}...")
                return data
    except Exception as e:
        print(f"Registration start failed: {e}")
    return None

def test_registration_finish(challenge_data):
    """Test registration finish endpoint with mock data"""
    if not challenge_data:
        return False
        
    # Create mock credential data (normally from authenticator)
    payload = {
        "id": "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
        "response": {
            "clientDataJSON": base64.urlsafe_b64encode(json.dumps({
                "challenge": challenge_data["challenge"],
                "clientExtensions": {},
                "hashAlgorithm": "SHA-256",
                "origin": "http://localhost:8080",
                "type": "webauthn.create"
            }).encode()).decode().rstrip('='),
            "attestationObject": "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgVzzvX3Nyp_g9j9f2B-tPWy6puW01aZHI8RXjwqfDjtQCIQDLsdniGPO9iKr7tdgVV-FnBYhvzlZLG3u28rVt10YXfGN4NWOBWQJOMIICSjCCATKgAwIBAgIEVxb3wDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowLDEqMCgGA1UEAwwhWXViaWNvIFUyRiBFRSBTZXJpYWwgMjUwNTY5MjI2MTc2MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZNkcVNbZV43TsGB4TEY21UijmDqvNSfO6y3G4ytnnjP86ehjFK28-FdSGy9MSZ-Ur3BVZb4iGVsptk5NrQ3QYqM7MDkwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjUwEwYLKwYBBAGC5RwCAQEEBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAHibGMqbpNt2IOL4i4z96VEmbSoid9Xj--m2jJqg6RpqSOp1TO8L3lmEA22uf4uj_eZLUXYEw6EbLm11TUo3Ge-odpMPoODzBj9aTKC8oDFPfwWj6l1O3ZHTSma1XVyPqG4A579f3YAjfrPbgj404xJns0mqx5wkpxKlnoBKqo1rqSUmonencd4xanO_PHEfxU0iZif615Xk9E4bcANPCfz-OLfeKXiT-1msixwzz8XGvl2OTMJ_Sh9G9vhE-HjAcovcHfumcdoQh_WM445Za6Pyn9BZQV3FCqMviRR809sIATfU5lu86wu_5UGIGI7MFDEYeVGSqzpzh6mlcn8QSIZoYXV0aERhdGFYxEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAEAsV2gIUlPIHzZnNIlQdz5zvbKtpFz_WY-8ZfxOgTyy7f3Ffbolyp3fUtSQo5LfoUgBaBaXqK0wqqYO-u6FrrLApQECAyYgASFYIPr9-YH8DuBsOnaI3KJa0a39hyxh9LDtHErNvfQSyxQsIlgg4rAuQQ5uy4VXGFbkiAt0uwgJJodp-DymkoBcrGsLtkI"
        },
        "getClientExtensionResults": {},
        "type": "public-key"
    }
    
    try:
        response = requests.post(f"{BASE_URL}/attestation/result", 
                               headers=HEADERS, 
                               json=payload)
        print(f"Registration finish: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"Registration result: {data}")
            return True
    except Exception as e:
        print(f"Registration finish failed: {e}")
    return False

def test_authentication_start():
    """Test authentication start endpoint"""
    payload = {
        "username": "johndoe@example.com",
        "userVerification": "required"
    }
    
    try:
        response = requests.post(f"{BASE_URL}/assertion/options", 
                               headers=HEADERS, 
                               json=payload)
        print(f"Authentication start: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"Status: {data.get('status')}")
            return data
        else:
            print(f"Error response: {response.text}")
    except Exception as e:
        print(f"Authentication start failed: {e}")
    return None

def main():
    print("=== FIDO2/WebAuthn Server Test ===\n")
    
    # Test health check
    if not test_health_check():
        print("❌ Server not responding")
        return
    print("✅ Health check passed\n")
    
    # Test registration flow
    print("Testing registration flow...")
    challenge_data = test_registration_start()
    if challenge_data:
        print("✅ Registration start passed")
        if test_registration_finish(challenge_data):
            print("✅ Registration finish passed")
        else:
            print("❌ Registration finish failed")
    else:
        print("❌ Registration start failed")
    
    print("\nTesting authentication flow...")
    auth_data = test_authentication_start()
    if auth_data:
        print("✅ Authentication start passed")
    else:
        print("❌ Authentication start failed")
    
    print("\n=== Test Complete ===")

if __name__ == "__main__":
    main()