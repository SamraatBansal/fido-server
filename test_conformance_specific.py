#!/usr/bin/env python3
"""
Test specific FIDO2 conformance scenarios to debug failing tests
"""
import json
import requests
import sys

BASE_URL = "http://localhost:8080"

def test_registration_options_basic():
    """Test Server-ServerPublicKeyCredentialCreationOptions-Req-1 P-1"""
    print("Testing P-1: Basic registration options...")
    
    request_data = {
        "username": "testuser",
        "displayName": "Test User",
        "extensions": {"example.extension": True}
    }
    
    response = requests.post(f"{BASE_URL}/attestation/options", json=request_data)
    
    if response.status_code != 200:
        print(f"❌ HTTP Status: {response.status_code}")
        return False
    
    try:
        data = response.json()
    except:
        print("❌ Invalid JSON response")
        return False
    
    # Check all required fields per FIDO conformance test P-1
    checks = [
        ("status", str, "ok"),
        ("errorMessage", str, ""),
        ("user.name", str, "testuser"),
        ("user.displayName", str, "Test User"),
        ("user.id", str, None),  # Should be non-empty base64url
        ("rp.name", str, None),  # Should be non-empty
        ("rp.id", str, None),   # Should be non-empty
        ("challenge", str, None),  # Should be base64url, >= 16 bytes
        ("pubKeyCredParams", list, None),  # Should contain supported algorithms
        ("extensions.example.extension", bool, None),  # Should be present and boolean
    ]
    
    all_passed = True
    for check in checks:
        field_path, expected_type, expected_value = check
        
        # Navigate nested fields
        current_data = data
        field_parts = field_path.split(".")
        try:
            for part in field_parts:
                if current_data is None:
                    raise KeyError(f"Parent is None for {field_path}")
                current_data = current_data[part]
        except (KeyError, TypeError) as e:
            print(f"❌ Missing field: {field_path} - {e}")
            print(f"   Available data structure: {json.dumps(data, indent=2)[:500]}...")
            all_passed = False
            continue
        
        # Check type
        if expected_type and not isinstance(current_data, expected_type):
            print(f"❌ Wrong type for {field_path}: expected {expected_type.__name__}, got {type(current_data).__name__}")
            all_passed = False
            continue
        
        # Check value
        if expected_value is not None and current_data != expected_value:
            print(f"❌ Wrong value for {field_path}: expected {expected_value}, got {current_data}")
            all_passed = False
            continue
        
        # Special validations
        if field_path == "user.id":
            if not current_data or len(current_data) < 16:  # Base64url should be longer
                print(f"❌ user.id too short or empty: {current_data}")
                all_passed = False
                continue
        
        if field_path == "challenge":
            if not current_data or len(current_data) < 22:  # Base64url for 16+ bytes
                print(f"❌ challenge too short: {current_data}")
                all_passed = False
                continue
        
        if field_path == "pubKeyCredParams":
            if not current_data or len(current_data) == 0:
                print(f"❌ pubKeyCredParams empty")
                all_passed = False
                continue
            # Should contain ES256 (-7)
            has_es256 = any(param.get("alg") == -7 for param in current_data)
            if not has_es256:
                print(f"❌ pubKeyCredParams missing ES256 (-7)")
                all_passed = False
                continue
        
        print(f"✅ {field_path}: OK")
    
    if all_passed:
        print("✅ P-1 Basic registration options: PASSED")
    else:
        print("❌ P-1 Basic registration options: FAILED")
    
    return all_passed

def test_challenge_uniqueness():
    """Test P-3: Challenge uniqueness"""
    print("\nTesting P-3: Challenge uniqueness...")
    
    request_data = {
        "username": "testuser",
        "displayName": "Test User"
    }
    
    # Get two challenges
    response1 = requests.post(f"{BASE_URL}/attestation/options", json=request_data)
    response2 = requests.post(f"{BASE_URL}/attestation/options", json=request_data)
    
    if response1.status_code != 200 or response2.status_code != 200:
        print(f"❌ HTTP Status errors: {response1.status_code}, {response2.status_code}")
        return False
    
    try:
        data1 = response1.json()
        data2 = response2.json()
    except:
        print("❌ Invalid JSON responses")
        return False
    
    challenge1 = data1.get("challenge")
    challenge2 = data2.get("challenge")
    
    if challenge1 == challenge2:
        print(f"❌ Challenges are identical: {challenge1}")
        return False
    
    print("✅ P-3 Challenge uniqueness: PASSED")
    return True

def test_attestation_required():
    """Test P-2: Attestation set to none"""
    print("\nTesting P-2: Attestation 'none'...")
    
    request_data = {
        "username": "testuser", 
        "displayName": "Test User",
        "attestation": "none"
    }
    
    response = requests.post(f"{BASE_URL}/attestation/options", json=request_data)
    
    if response.status_code != 200:
        print(f"❌ HTTP Status: {response.status_code}")
        return False
    
    try:
        data = response.json()
    except:
        print("❌ Invalid JSON response")
        return False
    
    if data.get("attestation") != "none":
        print(f"❌ Attestation not set to 'none': {data.get('attestation')}")
        return False
    
    print("✅ P-2 Attestation 'none': PASSED")
    return True

def test_user_verification():
    """Test P-4: User verification required"""
    print("\nTesting P-4: User verification required...")
    
    request_data = {
        "username": "testuser",
        "displayName": "Test User", 
        "authenticatorSelection": {
            "userVerification": "required"
        }
    }
    
    response = requests.post(f"{BASE_URL}/attestation/options", json=request_data)
    
    if response.status_code != 200:
        print(f"❌ HTTP Status: {response.status_code}")
        return False
    
    try:
        data = response.json()
    except:
        print("❌ Invalid JSON response")
        return False
    
    auth_selection = data.get("authenticatorSelection")
    if not auth_selection or auth_selection.get("userVerification") != "required":
        print(f"❌ userVerification not set to 'required': {auth_selection}")
        return False
    
    print("✅ P-4 User verification required: PASSED")
    return True

if __name__ == "__main__":
    print("🔬 FIDO2 Conformance Test Debugging")
    print("=" * 50)
    
    tests = [
        test_registration_options_basic,
        test_challenge_uniqueness,
        test_attestation_required,
        test_user_verification,
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"❌ Test failed with exception: {e}")
    
    print("\n" + "=" * 50)
    print(f"📊 Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All basic conformance tests passed!")
        sys.exit(0)
    else:
        print("⚠️  Some tests failed - check output above")
        sys.exit(1)