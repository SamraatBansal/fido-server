#!/usr/bin/env python3
import requests
import json

def test_attestation_options():
    """Test /attestation/options endpoint with Newman format"""
    url = "http://localhost:8080/attestation/options"
    headers = {"Content-Type": "application/json"}
    
    # Newman request format
    data = {
        "username": "johndoe@example.com",
        "displayName": "John Doe",
        "authenticatorSelection": {
            "requireResidentKey": False,
            "authenticatorAttachment": "cross-platform",
            "userVerification": "preferred"
        },
        "attestation": "direct"
    }
    
    print("Testing /attestation/options...")
    response = requests.post(url, json=data, headers=headers)
    
    print(f"Status: {response.status_code}")
    
    if response.status_code != 200:
        print(f"❌ Expected 200, got {response.status_code}")
        return False
    
    try:
        result = response.json()
        
        # Check required fields from Newman specification
        required_fields = ["status", "errorMessage", "rp", "user", "challenge", "pubKeyCredParams"]
        for field in required_fields:
            if field not in result:
                print(f"❌ Missing required field: {field}")
                return False
        
        # Check specific values
        if result["status"] != "ok":
            print(f"❌ Status should be 'ok', got '{result['status']}'")
            return False
            
        if result["errorMessage"] != "":
            print(f"❌ Error message should be empty, got '{result['errorMessage']}'")
            return False
            
        # Check RP entity
        if "name" not in result["rp"]:
            print(f"❌ Missing rp.name field")
            return False
            
        # Check user entity
        user = result["user"]
        if not all(key in user for key in ["id", "name", "displayName"]):
            print(f"❌ Missing required user fields")
            return False
            
        # Check challenge
        if not result["challenge"]:
            print("❌ Missing challenge field")
            return False
            
        # Check pubKeyCredParams
        if not result["pubKeyCredParams"]:
            print("❌ Missing pubKeyCredParams field")
            return False
            
        print("✅ /attestation/options test passed")
        return True
        
    except json.JSONDecodeError as e:
        print(f"❌ Invalid JSON response: {e}")
        return False

def test_attestation_result():
    """Test /attestation/result endpoint"""
    url = "http://localhost:8080/attestation/result"
    headers = {"Content-Type": "application/json"}
    
    # Newman credential format
    data = {
        "id": "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
        "response": {
            "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJOeHlab3B3VktiRmw3RW5uTWFlXzVGbmlyN1FKN1FXcDFVRlVLakZIbGZrIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9",
            "attestationObject": "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgVzzvX3Nyp_g9j9f2B-tPWy6puW01aZHI8RXjwqfDjtQCIQDLsdniGPO9iKr7tdgVV-FnBYhvzlZLG3u28rVt10YXfGN4NWOBWQJOMIICSjCCATKgAwIBAgIEVxb3wDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowLDEqMCgGA1UEAwwhWXViaWNvIFUyRiBFRSBTZXJpYWwgMjUwNTY5MjI2MTc2MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZNkcVNbZV43TsGB4TEY21UijmDqvNSfO6y3G4ytnnjP86ehjFK28-FdSGy9MSZ-Ur3BVZb4iGVsptk5NrQ3QYqM7MDkwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjUwEwYLKwYBBAGC5RwCAQEEBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAHibGMqbpNt2IOL4i4z96VEmbSoid9Xj--m2jJqg6RpqSOp1TO8L3lmEA22uf4uj_eZLUXYEw6EbLm11TUo3Ge-odpMPoODzBj9aTKC8oDFPfwWj6l1O3ZHTSma1XVyPqG4A579f3YAjfrPbgj404xJns0mqx5wkpxKlnoBKqo1rqSUmonencd4xanO_PHEfxU0iZif615Xk9E4bcANPCfz-OLfeKXiT-1msixwzz8XGvl2OTMJ_Sh9G9vhE-HjAcovcHfumcdoQh_WM445Za6Pyn9BZQV3FCqMviRR809sIATfU5lu86wu_5UGIGI7MFDEYeVGSqzpzh6mlcn8QSIZoYXV0aERhdGFYxEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAEAsV2gIUlPIHzZnNIlQdz5zvbKtpFz_WY-8ZfxOgTyy7f3Ffbolyp3fUtSQo5LfoUgBaBaXqK0wqqYO-u6FrrLApQECAyYgASFYIPr9-YH8DuBsOnaI3KJa0a39hyxh9LDtHErNvfQSyxQsIlgg4rAuQQ5uy4VXGFbkiAt0uwgJJodp-DymkoBcrGsLtkI"
        },
        "getClientExtensionResults": {},
        "type": "public-key"
    }
    
    print("Testing /attestation/result...")
    response = requests.post(url, json=data, headers=headers)
    
    print(f"Status: {response.status_code}")
    
    if response.status_code != 200:
        print(f"❌ Expected 200, got {response.status_code}")
        return False
    
    try:
        result = response.json()
        
        # Check required fields
        if result["status"] != "ok":
            print(f"❌ Status should be 'ok', got '{result['status']}'")
            return False
            
        if result["errorMessage"] != "":
            print(f"❌ Error message should be empty, got '{result['errorMessage']}'")
            return False
            
        print("✅ /attestation/result test passed")
        return True
        
    except json.JSONDecodeError as e:
        print(f"❌ Invalid JSON response: {e}")
        return False

def test_assertion_options():
    """Test /assertion/options endpoint"""
    url = "http://localhost:8080/assertion/options"
    headers = {"Content-Type": "application/json"}
    
    data = {
        "username": "johndoe@example.com",
        "userVerification": "required"
    }
    
    print("Testing /assertion/options...")
    response = requests.post(url, json=data, headers=headers)
    
    print(f"Status: {response.status_code}")
    
    if response.status_code != 200:
        print(f"❌ Expected 200, got {response.status_code}")
        return False
    
    try:
        result = response.json()
        
        # Check required fields
        required_fields = ["status", "errorMessage", "challenge", "rpId", "allowCredentials", "userVerification"]
        for field in required_fields:
            if field not in result:
                print(f"❌ Missing required field: {field}")
                return False
        
        if result["status"] != "ok":
            print(f"❌ Status should be 'ok', got '{result['status']}'")
            return False
            
        if result["errorMessage"] != "":
            print(f"❌ Error message should be empty, got '{result['errorMessage']}'")
            return False
            
        if result["rpId"] != "localhost":
            print(f"❌ rpId should be 'localhost', got '{result['rpId']}'")
            return False
            
        print("✅ /assertion/options test passed")
        return True
        
    except json.JSONDecodeError as e:
        print(f"❌ Invalid JSON response: {e}")
        return False

def test_assertion_result():
    """Test /assertion/result endpoint"""
    url = "http://localhost:8080/assertion/result"
    headers = {"Content-Type": "application/json"}
    
    data = {
        "id": "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
        "response": {
            "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA",
            "signature": "MEYCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL",
            "userHandle": "",
            "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJ4ZGowQ0JmWDY5MnFzQVRweTBrTmM4NTMzSmR2ZExVcHFZUDh3RFRYX1pFIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9"
        },
        "getClientExtensionResults": {},
        "type": "public-key"
    }
    
    print("Testing /assertion/result...")
    response = requests.post(url, json=data, headers=headers)
    
    print(f"Status: {response.status_code}")
    
    if response.status_code != 200:
        print(f"❌ Expected 200, got {response.status_code}")
        return False
    
    try:
        result = response.json()
        
        if result["status"] != "ok":
            print(f"❌ Status should be 'ok', got '{result['status']}'")
            return False
            
        if result["errorMessage"] != "":
            print(f"❌ Error message should be empty, got '{result['errorMessage']}'")
            return False
            
        print("✅ /assertion/result test passed")
        return True
        
    except json.JSONDecodeError as e:
        print(f"❌ Invalid JSON response: {e}")
        return False

def main():
    """Run all Newman compliance tests"""
    print("Running Newman Compliance Tests")
    print("=" * 50)
    
    tests = [
        test_attestation_options,
        test_attestation_result,
        test_assertion_options,
        test_assertion_result
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
    
    print(f"\nResults: {passed}/{total} tests passed")
    
    if passed == total:
        print("✅ ALL NEWMAN COMPLIANCE TESTS PASSED!")
        return 0
    else:
        print(f"❌ {total - passed} tests failed")
        return 1

if __name__ == "__main__":
    exit(main())