#!/usr/bin/env python3
import requests
import json

# Test the attestation/options endpoint
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

print("Testing /attestation/options endpoint...")
print("Request:", json.dumps(data, indent=2))

try:
    response = requests.post(url, json=data, headers=headers)
    print("Status Code:", response.status_code)
    print("Response Headers:", dict(response.headers))
    print("Response Body:", response.text)
except Exception as e:
    print("Error:", e)