#!/bin/bash

# FIDO2/WebAuthn Test Runner
# This script runs all tests and provides comprehensive reporting

set -e

echo "🚀 Starting FIDO2/WebAuthn Test Suite"
echo "======================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if we're in the right directory
if [ ! -f "Cargo.toml" ]; then
    print_error "Cargo.toml not found. Please run this script from the project root."
    exit 1
fi

print_status "Running from project root: $(pwd)"

# Create test results directory
mkdir -p test_results
TEST_RESULTS_DIR="test_results"

# Function to run a test category
run_test_category() {
    local category=$1
    local description=$2
    local test_path=$3
    
    print_status "Running $description..."
    
    local start_time=$(date +%s)
    local log_file="$TEST_RESULTS_DIR/${category}_test.log"
    
    if cargo test $test_path 2>&1 | tee "$log_file"; then
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        print_success "$description completed successfully in ${duration}s"
        echo "✅ $description: PASSED (${duration}s)" >> "$TEST_RESULTS_DIR/test_summary.txt"
        return 0
    else
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        print_error "$description failed after ${duration}s"
        echo "❌ $description: FAILED (${duration}s)" >> "$TEST_RESULTS_DIR/test_summary.txt"
        return 1
    fi
}

# Initialize test summary
echo "FIDO2/WebAuthn Test Results - $(date)" > "$TEST_RESULTS_DIR/test_summary.txt"
echo "========================================" >> "$TEST_RESULTS_DIR/test_summary.txt"

# Run test categories
print_status "Starting test execution..."

# 1. Unit Tests
if ! run_test_category "unit" "Unit Tests" "--test unit"; then
    UNIT_FAILED=1
else
    UNIT_FAILED=0
fi

# 2. Integration Tests
if ! run_test_category "integration" "Integration Tests" "--test integration"; then
    INTEGRATION_FAILED=1
else
    INTEGRATION_FAILED=0
fi

# 3. Security Tests
if ! run_test_category "security" "Security Tests" "--test security"; then
    SECURITY_FAILED=1
else
    SECURITY_FAILED=0
fi

# 4. Performance Tests (if criterion is available)
if command -v cargo bench &> /dev/null; then
    print_status "Running Performance Benchmarks..."
    if cargo bench 2>&1 | tee "$TEST_RESULTS_DIR/performance_bench.log"; then
        print_success "Performance benchmarks completed"
        echo "📊 Performance Benchmarks: COMPLETED" >> "$TEST_RESULTS_DIR/test_summary.txt"
    else
        print_warning "Performance benchmarks failed (may be expected in some environments)"
        echo "⚠️  Performance Benchmarks: FAILED" >> "$TEST_RESULTS_DIR/test_summary.txt"
    fi
else
    print_warning "Cargo bench not available, skipping performance benchmarks"
    echo "⚠️  Performance Benchmarks: SKIPPED" >> "$TEST_RESULTS_DIR/test_summary.txt"
fi

# 5. Compliance Tests
if ! run_test_category "compliance" "Compliance Tests" "--test compliance"; then
    COMPLIANCE_FAILED=1
else
    COMPLIANCE_FAILED=0
fi

# 6. Library Tests (core library tests)
if ! run_test_category "library" "Library Tests" "--lib"; then
    LIBRARY_FAILED=1
else
    LIBRARY_FAILED=0
fi

# Generate test coverage report (if tools are available)
if command -v cargo-tarpaulin &> /dev/null; then
    print_status "Generating test coverage report..."
    if cargo tarpaulin --out Html --output-dir "$TEST_RESULTS_DIR" 2>&1 | tee "$TEST_RESULTS_DIR/coverage.log"; then
        print_success "Coverage report generated"
        echo "📈 Coverage Report: GENERATED" >> "$TEST_RESULTS_DIR/test_summary.txt"
    else
        print_warning "Coverage report generation failed"
        echo "⚠️  Coverage Report: FAILED" >> "$TEST_RESULTS_DIR/test_summary.txt"
    fi
else
    print_warning "Cargo tarpaulin not available, skipping coverage report"
    echo "⚠️  Coverage Report: SKIPPED" >> "$TEST_RESULTS_DIR/test_summary.txt"
fi

# Final summary
echo ""
echo "======================================"
echo "🏁 Test Suite Execution Complete"
echo "======================================"

# Count total failures
TOTAL_FAILED=$((UNIT_FAILED + INTEGRATION_FAILED + SECURITY_FAILED + COMPLIANCE_FAILED + LIBRARY_FAILED))

if [ $TOTAL_FAILED -eq 0 ]; then
    print_success "All test categories passed! 🎉"
    echo ""
    echo "📊 Test Summary:"
    cat "$TEST_RESULTS_DIR/test_summary.txt"
    echo ""
    echo "📁 Detailed logs available in: $TEST_RESULTS_DIR/"
    exit 0
else
    print_error "$TOTAL_FAILED test category(ies) failed!"
    echo ""
    echo "📊 Test Summary:"
    cat "$TEST_RESULTS_DIR/test_summary.txt"
    echo ""
    echo "📁 Check detailed logs in: $TEST_RESULTS_DIR/"
    echo ""
    echo "💡 To run individual test categories:"
    echo "   cargo test --test unit          # Unit tests only"
    echo "   cargo test --test integration   # Integration tests only"
    echo "   cargo test --test security      # Security tests only"
    echo "   cargo test --test compliance    # Compliance tests only"
    exit 1
fi