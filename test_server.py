#!/usr/bin/env python3

import requests
import json
import time
import subprocess
import signal
import sys
import os

def test_fido_endpoints():
    # Basic test payload for attestation options
    attestation_request = {
        "username": "test@example.com",
        "displayName": "Test User",
        "authenticatorSelection": {
            "requireResidentKey": False,
            "authenticatorAttachment": "cross-platform",
            "userVerification": "preferred"
        },
        "attestation": "direct"
    }
    
    print("Testing /attestation/options endpoint...")
    
    try:
        response = requests.post(
            "http://localhost:8080/attestation/options",
            json=attestation_request,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        print(f"Status Code: {response.status_code}")
        print(f"Response Headers: {response.headers}")
        print(f"Response Body: {response.text}")
        
        if response.status_code == 200:
            print("✅ /attestation/options working!")
            data = response.json()
            print(f"Challenge: {data.get('challenge', 'N/A')}")
        else:
            print("❌ /attestation/options failed")
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Request failed: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

    # Test health check
    try:
        print("\nTesting /health endpoint...")
        response = requests.get("http://localhost:8080/health", timeout=5)
        print(f"Health Status: {response.status_code}")
        print(f"Health Response: {response.text}")
    except Exception as e:
        print(f"Health check failed: {e}")

if __name__ == "__main__":
    test_fido_endpoints()