//! Test build verification script

use std::process::Command;

fn main() {
    println!("Running test build verification...");
    
    // Check if we can compile the tests
    let output = Command::new("rustc")
        .args(&["--edition", "2021", "--crate-type", "lib", "src/lib.rs", "--extern", "tokio", "--extern", "uuid", "--extern", "base64", "--extern", "rand", "--extern", "thiserror"])
        .output()
        .expect("Failed to run rustc");

    if output.status.success() {
        println!("✓ Library compiles successfully");
    } else {
        println!("✗ Library compilation failed:");
        println!("{}", String::from_utf8_lossy(&output.stderr));
    }

    // Test individual test files
    let test_files = vec![
        "tests/unit/services/fido_test.rs",
        "tests/integration/api_test.rs",
        "tests/integration/registration_tests.rs",
        "tests/integration/authentication_tests.rs",
        "tests/security/replay_protection_test.rs",
    ];

    for test_file in test_files {
        println!("Checking {}...", test_file);
        
        // Basic syntax check
        let output = Command::new("rustc")
            .args(&["--edition", "2021", "--crate-type", "bin", test_file, "--extern", "fido_server=target/debug/deps/libfido_server.rlib"])
            .output();

        match output {
            Ok(output) => {
                if output.status.success() {
                    println!("  ✓ {} syntax is valid", test_file);
                } else {
                    println!("  ✗ {} has syntax errors:", test_file);
                    println!("{}", String::from_utf8_lossy(&output.stderr));
                }
            }
            Err(e) => {
                println!("  ? {} could not be checked: {}", test_file, e);
            }
        }
    }

    println!("Test build verification completed.");
}