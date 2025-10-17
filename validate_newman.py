#!/usr/bin/env python3
import subprocess
import json
import time

def run_newman_test():
    """Run Newman validation and check if all tests pass"""
    try:
        # Run Newman validation
        result = subprocess.run(
            ["newman", "run", "FIDO_Conformance_Test.postman_collection.json"],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        print("Newman Test Results:")
        print("=" * 50)
        print(result.stdout)
        
        # Check if all tests passed
        if "Tests Passed: 652" in result.stdout and "Tests Failed: 0" in result.stdout:
            print("\n✅ ALL NEWMAN TESTS PASSED!")
            return True
        else:
            print("\n❌ Some Newman tests are still failing")
            return False
            
    except subprocess.TimeoutExpired:
        print("❌ Newman test timed out")
        return False
    except Exception as e:
        print(f"❌ Error running Newman: {e}")
        return False

if __name__ == "__main__":
    success = run_newman_test()
    exit(0 if success else 1)