#!/usr/bin/env python3

import requests
import json
import subprocess
import time
import signal
import os

def run_simple_test():
    print("Starting FIDO2 server test...")
    
    # Start the server in the background
    print("Starting server...")
    env = os.environ.copy()
    env['PORT'] = '9999'
    env['RUST_LOG'] = 'debug'
    
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
        # Check if server is responding
        print("Testing health endpoint...")
        response = requests.get("http://localhost:9999/health", timeout=5)
        print(f"Health check: {response.status_code} - {response.text}")
        
        if response.status_code == 200:
            print("✅ Server is running!")
            
            # Test attestation/options endpoint
            test_payload = {
                "username": "test@example.com",
                "displayName": "Test User"
            }
            
            print("Testing /attestation/options...")
            response = requests.post(
                "http://localhost:9999/attestation/options",
                json=test_payload,
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            
            print(f"Attestation options: {response.status_code}")
            print(f"Response: {response.text}")
            
        else:
            print("❌ Server health check failed")
            
    except Exception as e:
        print(f"❌ Test failed: {e}")
        
    finally:
        # Kill the server
        try:
            server.terminate()
            server.wait(timeout=5)
        except:
            server.kill()
            
        # Print server output for debugging
        stdout, stderr = server.communicate()
        print("\n--- Server stdout ---")
        print(stdout)
        print("\n--- Server stderr ---")
        print(stderr)

if __name__ == "__main__":
    run_simple_test()