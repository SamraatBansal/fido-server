#!/usr/bin/env python3

import requests
import json
import subprocess
import time
import signal
import os
import base64

def run_comprehensive_test():
    print("Starting comprehensive FIDO2 conformance test...")
    
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
        # Test 1: Basic attestation/options endpoint
        test_attestation_options()
        
        # Test 2: Test with various required fields
        test_attestation_options_fields()
        
        # Test 3: Test assertion endpoints
        test_assertion_endpoints()
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        
    finally:
        # Kill the server
        try:
            server.terminate()
            server.wait(timeout=5)
        except:
            server.kill()

def test_attestation_options():
    print("\n=== Testing /attestation/options ===")
    
    # Basic test from conformance
    test_payload = {
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
            "http://localhost:9999/attestation/options",
            json=test_payload,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        
        print(f"Status: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print("✅ Basic attestation/options works")
            
            # Check required fields
            required_fields = ["status", "errorMessage", "rp", "user", "challenge", "pubKeyCredParams", "extensions"]
            missing_fields = []
            for field in required_fields:
                if field not in data:
                    missing_fields.append(field)
            
            if missing_fields:
                print(f"❌ Missing required fields: {missing_fields}")
            else:
                print("✅ All required fields present")
                
            # Check field types and values
            check_field_validation(data)
        else:
            print(f"❌ attestation/options failed: {response.text}")
            
    except Exception as e:
        print(f"❌ Request failed: {e}")

def check_field_validation(data):
    print("\n--- Field validation ---")
    
    # Check status
    if data.get("status") == "ok":
        print("✅ status field correct")
    else:
        print(f"❌ status field incorrect: {data.get('status')}")
    
    # Check errorMessage
    if data.get("errorMessage") == "":
        print("✅ errorMessage field correct")
    else:
        print(f"❌ errorMessage field incorrect: {data.get('errorMessage')}")
    
    # Check user object
    user = data.get("user", {})
    if all(field in user for field in ["id", "name", "displayName"]):
        print("✅ user object has required fields")
        
        # Check user.id is base64url and not empty
        try:
            user_id = user["id"]
            if user_id and len(user_id) > 0:
                # Try to decode to verify it's valid base64url
                decoded = base64.urlsafe_b64decode(user_id + '==')  # Add padding
                if len(decoded) <= 64:  # Should be <= 64 bytes per spec
                    print("✅ user.id is valid base64url and proper length")
                else:
                    print(f"❌ user.id too long: {len(decoded)} bytes")
            else:
                print("❌ user.id is empty")
        except Exception as e:
            print(f"❌ user.id is not valid base64url: {e}")
    else:
        print(f"❌ user object missing fields: {user}")
    
    # Check rp object
    rp = data.get("rp", {})
    if "name" in rp and "id" in rp:
        print("✅ rp object has required fields")
    else:
        print(f"❌ rp object missing fields: {rp}")
    
    # Check challenge
    challenge = data.get("challenge", "")
    if challenge:
        try:
            decoded = base64.urlsafe_b64decode(challenge + '==')
            if len(decoded) >= 16:  # Should be at least 16 bytes
                print("✅ challenge is valid base64url and proper length")
            else:
                print(f"❌ challenge too short: {len(decoded)} bytes")
        except Exception as e:
            print(f"❌ challenge is not valid base64url: {e}")
    else:
        print("❌ challenge is empty")
    
    # Check pubKeyCredParams
    pub_key_params = data.get("pubKeyCredParams", [])
    if pub_key_params:
        valid_params = True
        for param in pub_key_params:
            if not (isinstance(param, dict) and "type" in param and "alg" in param):
                valid_params = False
                break
        if valid_params:
            print("✅ pubKeyCredParams is valid")
        else:
            print("❌ pubKeyCredParams has invalid format")
    else:
        print("❌ pubKeyCredParams is empty")
    
    # Check extensions
    extensions = data.get("extensions", {})
    if "example.extension" in extensions:
        print("✅ extensions field includes example.extension")
    else:
        print("❌ extensions field missing example.extension")

def test_attestation_options_fields():
    print("\n=== Testing field variations ===")
    
    # Test with minimal fields
    minimal_payload = {
        "username": "test@example.com",
        "displayName": "Test User"
    }
    
    try:
        response = requests.post(
            "http://localhost:9999/attestation/options",
            json=minimal_payload,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        
        if response.status_code == 200:
            print("✅ Minimal payload works")
        else:
            print(f"❌ Minimal payload failed: {response.text}")
    except Exception as e:
        print(f"❌ Minimal payload request failed: {e}")

def test_assertion_endpoints():
    print("\n=== Testing /assertion/options ===")
    
    # First create a user with attestation
    print("Creating user with attestation/options...")
    attestation_payload = {
        "username": "authtest@example.com",
        "displayName": "Auth Test User"
    }
    
    try:
        response = requests.post(
            "http://localhost:9999/attestation/options",
            json=attestation_payload,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        
        if response.status_code == 200:
            print("✅ Created user for auth test")
            
            # Now test assertion/options
            assertion_payload = {
                "username": "authtest@example.com",
                "userVerification": "required"
            }
            
            response = requests.post(
                "http://localhost:9999/assertion/options",
                json=assertion_payload,
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            
            if response.status_code == 200:
                print("✅ assertion/options works")
                data = response.json()
                
                # Check required fields for assertion
                required_fields = ["status", "errorMessage", "challenge"]
                missing = [f for f in required_fields if f not in data]
                if missing:
                    print(f"❌ assertion/options missing fields: {missing}")
                else:
                    print("✅ assertion/options has required fields")
            else:
                print(f"❌ assertion/options failed: {response.text}")
        else:
            print(f"❌ Could not create user: {response.text}")
            
    except Exception as e:
        print(f"❌ Assertion test failed: {e}")

if __name__ == "__main__":
    run_comprehensive_test()