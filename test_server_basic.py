#!/usr/bin/env python3
"""
Basic test for FIDO2 WebAuthn server to verify API responses and error handling
"""

import json
import requests
import subprocess
import time
import sys
from base64 import urlsafe_b64encode, urlsafe_b64decode
import os

def test_server():
    # Start the server
    print("Starting FIDO2 WebAuthn server...")
    server_process = subprocess.Popen(
        ["cargo", "run", "--release"],
        cwd="/tmp/cmhnccf3s02p8c1w5gx993rmr",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=dict(os.environ, RUST_LOG="info")
    )
    
    # Give server time to start
    time.sleep(3)
    
    try:
        # Test 1: Basic registration start
        print("\n1. Testing registration start...")
        reg_start_data = {
            "username": "testuser@example.com",
            "displayName": "Test User"
        }
        
        response = requests.post(
            "http://localhost:8080/attestation/options",
            json=reg_start_data,
            headers={"Content-Type": "application/json"}
        )
        
        print(f"Status Code: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print("✓ Registration start successful")
            print(f"  - Status: {data.get('status')}")
            print(f"  - Has challenge: {'challenge' in data}")
            print(f"  - Has user: {'user' in data}")
            print(f"  - Has rp: {'rp' in data}")
            print(f"  - Has pubKeyCredParams: {'pubKeyCredParams' in data}")
            
            # Verify required fields
            assert data.get('status') == 'ok'
            assert 'challenge' in data
            assert 'user' in data
            assert 'rp' in data
            assert 'pubKeyCredParams' in data
            assert data.get('errorMessage') == ""
        else:
            print(f"✗ Registration start failed: {response.text}")
            return False
            
        # Test 2: Missing required field
        print("\n2. Testing missing required field...")
        invalid_data = {
            "username": "testuser@example.com"
            # Missing displayName
        }
        
        response = requests.post(
            "http://localhost:8080/attestation/options",
            json=invalid_data,
            headers={"Content-Type": "application/json"}
        )
        
        print(f"Status Code: {response.status_code}")
        if response.status_code == 400:
            data = response.json()
            print("✓ Missing field validation works")
            print(f"  - Status: {data.get('status')}")
            print(f"  - Error: {data.get('errorMessage')}")
            assert data.get('status') == 'failed'
        else:
            print(f"✗ Missing field validation failed: {response.text}")
            return False
            
        # Test 3: Authentication start (should fail - no user exists)
        print("\n3. Testing authentication start (should fail)...")
        auth_start_data = {
            "username": "nonexistent@example.com"
        }
        
        response = requests.post(
            "http://localhost:8080/assertion/options",
            json=auth_start_data,
            headers={"Content-Type": "application/json"}
        )
        
        print(f"Status Code: {response.status_code}")
        if response.status_code in [400, 404]:
            data = response.json()
            print("✓ Authentication start correctly fails for nonexistent user")
            print(f"  - Status: {data.get('status')}")
            print(f"  - Error: {data.get('errorMessage')}")
            assert data.get('status') == 'failed'
        else:
            print(f"✗ Authentication validation failed: {response.text}")
            return False
            
        # Test 4: Invalid JSON
        print("\n4. Testing invalid JSON...")
        response = requests.post(
            "http://localhost:8080/attestation/options",
            data="invalid json",
            headers={"Content-Type": "application/json"}
        )
        
        print(f"Status Code: {response.status_code}")
        if response.status_code == 400:
            data = response.json()
            print("✓ Invalid JSON handling works")
            print(f"  - Status: {data.get('status')}")
            print(f"  - Error: {data.get('errorMessage')}")
        else:
            print(f"✗ Invalid JSON handling failed: {response.text}")
            return False
            
        # Test 5: Health check
        print("\n5. Testing health check...")
        response = requests.get("http://localhost:8080/health")
        
        print(f"Status Code: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print("✓ Health check works")
            print(f"  - Status: {data.get('status')}")
            assert data.get('status') == 'ok'
        else:
            print(f"✗ Health check failed: {response.text}")
            return False
            
        print("\n✓ All basic tests passed!")
        return True
        
    except requests.exceptions.ConnectionError:
        print("✗ Could not connect to server")
        return False
    except Exception as e:
        print(f"✗ Test failed with error: {e}")
        return False
    finally:
        # Clean up
        print("\nStopping server...")
        server_process.terminate()
        try:
            server_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server_process.kill()

if __name__ == "__main__":
    success = test_server()
    sys.exit(0 if success else 1)