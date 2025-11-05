#!/usr/bin/env python3

import requests
import json
import subprocess
import time
import signal
import os
import base64

def run_final_conformance_test():
    print("=== FINAL FIDO2 CONFORMANCE TEST ===")
    
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
    
    results = {
        "total_tests": 0,
        "passed_tests": 0,
        "failed_tests": 0
    }
    
    try:
        print("\n1. Testing ServerPublicKeyCredentialCreationOptions-Req-1")
        test_creation_options_basic(results)
        
        print("\n2. Testing field validation requirements")
        test_field_validation(results)
        
        print("\n3. Testing error handling")
        test_error_handling(results)
        
        print("\n4. Testing assertion endpoints")
        test_assertion_basic(results)
        
        print(f"\n=== SUMMARY ===")
        print(f"Total tests: {results['total_tests']}")
        print(f"Passed: {results['passed_tests']}")
        print(f"Failed: {results['failed_tests']}")
        print(f"Success rate: {results['passed_tests']/results['total_tests']*100:.1f}%")
        
    except Exception as e:
        print(f"❌ Test suite failed: {e}")
        
    finally:
        # Kill the server
        try:
            server.terminate()
            server.wait(timeout=5)
        except:
            server.kill()

def test_creation_options_basic(results):
    """Test P-1: Get ServerPublicKeyCredentialCreationOptionsResponse and check fields"""
    
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
        
        results["total_tests"] += 1
        
        if response.status_code == 200:
            data = response.json()
            
            # Check all required fields from the conformance test
            required_checks = [
                ("status", lambda d: d.get("status") == "ok"),
                ("errorMessage", lambda d: d.get("errorMessage") == ""),
                ("user.name", lambda d: d.get("user", {}).get("name") is not None),
                ("user.displayName", lambda d: d.get("user", {}).get("displayName") is not None),
                ("user.id", lambda d: d.get("user", {}).get("id") is not None and len(d.get("user", {}).get("id", "")) > 0),
                ("rp.name", lambda d: d.get("rp", {}).get("name") is not None),
                ("rp.id", lambda d: d.get("rp", {}).get("id") is not None),
                ("challenge", lambda d: d.get("challenge") is not None and len(d.get("challenge", "")) >= 22),  # min 16 bytes base64url
                ("pubKeyCredParams", lambda d: isinstance(d.get("pubKeyCredParams"), list) and len(d.get("pubKeyCredParams", [])) > 0),
                ("extensions", lambda d: "example.extension" in d.get("extensions", {})),
            ]
            
            all_passed = True
            for field_name, check_func in required_checks:
                if check_func(data):
                    print(f"  ✅ {field_name} - OK")
                else:
                    print(f"  ❌ {field_name} - FAIL")
                    all_passed = False
            
            if all_passed:
                results["passed_tests"] += 1
                print("✅ PASS: ServerPublicKeyCredentialCreationOptions-Req-1")
            else:
                results["failed_tests"] += 1
                print("❌ FAIL: ServerPublicKeyCredentialCreationOptions-Req-1")
        else:
            results["failed_tests"] += 1
            print(f"❌ FAIL: Got {response.status_code} - {response.text}")
            
    except Exception as e:
        results["total_tests"] += 1
        results["failed_tests"] += 1
        print(f"❌ FAIL: Exception - {e}")

def test_field_validation(results):
    """Test specific field validation requirements"""
    
    print("Testing user.id base64url validation...")
    
    test_payload = {
        "username": "testuser@example.com",
        "displayName": "Test User"
    }
    
    try:
        response = requests.post(
            "http://localhost:9999/attestation/options",
            json=test_payload,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        
        results["total_tests"] += 1
        
        if response.status_code == 200:
            data = response.json()
            user_id = data.get("user", {}).get("id", "")
            
            # Validate user.id is proper base64url and <= 64 bytes
            try:
                decoded = base64.urlsafe_b64decode(user_id + '==')
                if len(decoded) <= 64:
                    results["passed_tests"] += 1
                    print("✅ PASS: user.id is valid base64url and <= 64 bytes")
                else:
                    results["failed_tests"] += 1
                    print(f"❌ FAIL: user.id too long: {len(decoded)} bytes")
            except Exception as e:
                results["failed_tests"] += 1
                print(f"❌ FAIL: user.id not valid base64url: {e}")
        else:
            results["failed_tests"] += 1
            print(f"❌ FAIL: Request failed: {response.status_code}")
            
    except Exception as e:
        results["total_tests"] += 1
        results["failed_tests"] += 1
        print(f"❌ FAIL: Exception - {e}")

def test_error_handling(results):
    """Test error handling for various invalid inputs"""
    
    error_tests = [
        {
            "name": "Missing id field",
            "payload": {
                "response": {
                    "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoidGVzdCIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6OTk5OSJ9",
                    "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAA"
                },
                "type": "public-key",
                "getClientExtensionResults": {}
            }
        },
        {
            "name": "Empty id field",
            "payload": {
                "id": "",
                "response": {
                    "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoidGVzdCIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6OTk5OSJ9",
                    "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAA"
                },
                "type": "public-key",
                "getClientExtensionResults": {}
            }
        },
        {
            "name": "Wrong type field",
            "payload": {
                "id": "dGVzdDEyMw",
                "response": {
                    "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoidGVzdCIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6OTk5OSJ9",
                    "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAA"
                },
                "type": "avocado-toast",
                "getClientExtensionResults": {}
            }
        },
        {
            "name": "Empty clientDataJSON",
            "payload": {
                "id": "dGVzdDEyMw",
                "response": {
                    "clientDataJSON": "",
                    "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAA"
                },
                "type": "public-key",
                "getClientExtensionResults": {}
            }
        }
    ]
    
    for test_case in error_tests:
        try:
            response = requests.post(
                "http://localhost:9999/attestation/result",
                json=test_case["payload"],
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            
            results["total_tests"] += 1
            
            if response.status_code >= 400:
                try:
                    data = response.json()
                    if data.get("status") == "failed" and data.get("errorMessage"):
                        results["passed_tests"] += 1
                        print(f"✅ PASS: {test_case['name']} - Got expected error")
                    else:
                        results["failed_tests"] += 1
                        print(f"❌ FAIL: {test_case['name']} - Wrong error format")
                except:
                    results["failed_tests"] += 1
                    print(f"❌ FAIL: {test_case['name']} - Invalid JSON response")
            else:
                results["failed_tests"] += 1
                print(f"❌ FAIL: {test_case['name']} - Should have failed but got {response.status_code}")
                
        except Exception as e:
            results["total_tests"] += 1
            results["failed_tests"] += 1
            print(f"❌ FAIL: {test_case['name']} - Exception: {e}")

def test_assertion_basic(results):
    """Test assertion endpoint basic functionality"""
    
    # Test with a user that doesn't exist
    test_payload = {
        "username": "nonexistent@example.com",
        "userVerification": "required"
    }
    
    try:
        response = requests.post(
            "http://localhost:9999/assertion/options",
            json=test_payload,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        
        results["total_tests"] += 1
        
        # Should fail with user not found
        if response.status_code >= 400:
            data = response.json()
            if data.get("status") == "failed":
                results["passed_tests"] += 1
                print("✅ PASS: assertion/options correctly rejects non-existent user")
            else:
                results["failed_tests"] += 1
                print("❌ FAIL: assertion/options wrong error format")
        else:
            results["failed_tests"] += 1
            print("❌ FAIL: assertion/options should have failed for non-existent user")
            
    except Exception as e:
        results["total_tests"] += 1
        results["failed_tests"] += 1
        print(f"❌ FAIL: assertion/options exception: {e}")

if __name__ == "__main__":
    run_final_conformance_test()