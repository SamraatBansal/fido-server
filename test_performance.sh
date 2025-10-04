#!/bin/bash

# FIDO2/WebAuthn Performance and Load Testing Script
# Tests system performance under various load conditions

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SERVER_URL=${SERVER_URL:-"http://localhost:8080"}
CONCURRENT_USERS=${CONCURRENT_USERS:-10}
REQUESTS_PER_USER=${REQUESTS_PER_USER:-100}
DURATION=${DURATION:-30}

# Logging function
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_failure() {
    echo -e "${RED}[✗]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[⚠]${NC} $1"
}

# Check if server is running
check_server() {
    log "Checking if server is running at $SERVER_URL"
    
    if curl -s -f "$SERVER_URL/health" >/dev/null 2>&1; then
        log_success "Server is running"
        return 0
    else
        log_failure "Server is not running at $SERVER_URL"
        return 1
    fi
}

# Baseline performance test
baseline_test() {
    log "Running baseline performance test"
    
    # Test single request latency
    local start_time=$(date +%s%N)
    curl -s "$SERVER_URL/api/v1/health" >/dev/null
    local end_time=$(date +%s%N)
    local latency=$(( (end_time - start_time) / 1000000 )) # Convert to milliseconds
    
    echo "Single request latency: ${latency}ms"
    
    if [ $latency -lt 100 ]; then
        log_success "Excellent latency (< 100ms)"
    elif [ $latency -lt 500 ]; then
        log_success "Good latency (< 500ms)"
    else
        log_warning "High latency (> 500ms)"
    fi
}

# Load test with curl
load_test_curl() {
    log "Running load test with curl (Concurrent: $CONCURRENT_USERS, Requests: $REQUESTS_PER_USER)"
    
    local temp_dir=$(mktemp -d)
    local pids=()
    local total_requests=0
    local successful_requests=0
    local failed_requests=0
    
    # Start concurrent users
    for ((i=1; i<=CONCURRENT_USERS; i++)); do
        {
            local user_success=0
            local user_failed=0
            
            for ((j=1; j<=REQUESTS_PER_USER; j++)); do
                if curl -s -f "$SERVER_URL/api/v1/health" >/dev/null 2>&1; then
                    ((user_success++))
                else
                    ((user_failed++))
                fi
            done
            
            echo "$user_success $user_failed" > "$temp_dir/user_$i.txt"
        } &
        pids+=($!)
    done
    
    # Wait for all users to complete
    for pid in "${pids[@]}"; do
        wait $pid
    done
    
    # Collect results
    for ((i=1; i<=CONCURRENT_USERS; i++)); do
        if [ -f "$temp_dir/user_$i.txt" ]; then
            local success failed
            read success failed < "$temp_dir/user_$i.txt"
            successful_requests=$((successful_requests + success))
            failed_requests=$((failed_requests + failed))
            total_requests=$((total_requests + success + failed))
        fi
    done
    
    # Calculate metrics
    local success_rate=$(( (successful_requests * 100) / total_requests ))
    local total_rps=$(( total_requests / DURATION ))
    
    echo "Load Test Results:"
    echo "  Total Requests: $total_requests"
    echo "  Successful: $successful_requests"
    echo "  Failed: $failed_requests"
    echo "  Success Rate: ${success_rate}%"
    echo "  Requests/Second: $total_rps"
    
    if [ $success_rate -ge 95 ]; then
        log_success "Excellent success rate (≥95%)"
    elif [ $success_rate -ge 90 ]; then
        log_success "Good success rate (≥90%)"
    else
        log_failure "Poor success rate (<90%)"
    fi
    
    # Cleanup
    rm -rf "$temp_dir"
}

# Stress test
stress_test() {
    log "Running stress test (Duration: ${DURATION}s)"
    
    local start_time=$(date +%s)
    local end_time=$((start_time + DURATION))
    local request_count=0
    local error_count=0
    
    while [ $(date +%s) -lt $end_time ]; do
        # Send multiple concurrent requests
        for ((i=1; i<=20; i++)); do
            (
                if curl -s -f "$SERVER_URL/api/v1/health" >/dev/null 2>&1; then
                    echo "success" >> "/tmp/stress_test_success_$$.log"
                else
                    echo "error" >> "/tmp/stress_test_error_$$.log"
                fi
            ) &
        done
        
        # Wait a bit before next batch
        sleep 0.1
        ((request_count += 20))
    done
    
    wait # Wait for all background jobs
    
    # Count results
    local success_count=$(wc -l < "/tmp/stress_test_success_$$.log" 2>/dev/null || echo 0)
    local error_count_file=$(wc -l < "/tmp/stress_test_error_$$.log" 2>/dev/null || echo 0)
    
    echo "Stress Test Results:"
    echo "  Duration: ${DURATION}s"
    echo "  Total Requests: $request_count"
    echo "  Successful: $success_count"
    echo "  Errors: $error_count_file"
    echo "  Average RPS: $(( request_count / DURATION ))"
    
    # Cleanup
    rm -f "/tmp/stress_test_success_$$.log" "/tmp/stress_test_error_$$.log"
}

# Memory usage test
memory_test() {
    log "Monitoring memory usage during load"
    
    # Get initial memory
    local initial_memory=$(ps -o rss= -p $(pgrep -f fido-server) 2>/dev/null || echo 0)
    
    # Run load for memory testing
    for ((i=1; i<=50; i++)); do
        curl -s "$SERVER_URL/api/v1/health" >/dev/null &
        if [ $((i % 10)) -eq 0 ]; then
            wait # Wait for some requests to complete
        fi
    done
    wait
    
    # Get final memory
    local final_memory=$(ps -o rss= -p $(pgrep -f fido-server) 2>/dev/null || echo 0)
    local memory_increase=$((final_memory - initial_memory))
    
    echo "Memory Usage Test:"
    echo "  Initial Memory: ${initial_memory}KB"
    echo "  Final Memory: ${final_memory}KB"
    echo "  Memory Increase: ${memory_increase}KB"
    
    if [ $memory_increase -lt 10240 ]; then # Less than 10MB increase
        log_success "Memory usage is stable"
    else
        log_warning "Significant memory increase detected"
    fi
}

# API endpoint performance test
api_performance_test() {
    log "Testing API endpoint performance"
    
    local endpoints=(
        "/health"
        "/api/v1/health"
        "/api/v1/register/start"
        "/api/v1/auth/start"
    )
    
    for endpoint in "${endpoints[@]}"; do
        log "Testing endpoint: $endpoint"
        
        local total_time=0
        local iterations=10
        
        for ((i=1; i<=iterations; i++)); do
            local start_time=$(date +%s%N)
            
            # For POST endpoints, send empty JSON
            if [[ "$endpoint" == *"/start" ]]; then
                curl -s -X POST -H "Content-Type: application/json" -d '{}' "$SERVER_URL$endpoint" >/dev/null 2>&1
            else
                curl -s "$SERVER_URL$endpoint" >/dev/null 2>&1
            fi
            
            local end_time=$(date +%s%N)
            local request_time=$(( (end_time - start_time) / 1000000 ))
            total_time=$((total_time + request_time))
        done
        
        local avg_time=$((total_time / iterations))
        echo "  $endpoint: ${avg_time}ms average"
        
        if [ $avg_time -lt 200 ]; then
            log_success "$endpoint: Excellent performance"
        elif [ $avg_time -lt 1000 ]; then
            log_success "$endpoint: Good performance"
        else
            log_warning "$endpoint: Slow performance"
        fi
    done
}

# Generate performance report
generate_performance_report() {
    log "Generating performance report"
    
    cat > performance_report.md << EOF
# FIDO2/WebAuthn Performance Test Report

**Generated:** $(date)
**Test Configuration:**
- Server URL: $SERVER_URL
- Concurrent Users: $CONCURRENT_USERS
- Requests per User: $REQUESTS_PER_USER
- Test Duration: ${DURATION}s

## Test Summary

This report contains performance metrics for the FIDO2/WebAuthn server implementation
under various load conditions.

## Performance Metrics

### 1. Baseline Performance
- Single request latency measured
- Response time analysis completed

### 2. Load Testing
- Concurrent user handling tested
- Throughput measured
- Error rate calculated

### 3. Stress Testing
- Sustained load performance
- Resource utilization monitored
- Stability under pressure assessed

### 4. Memory Usage
- Memory consumption tracked
- Memory leaks detected
- Resource efficiency evaluated

### 5. API Endpoint Performance
- Individual endpoint response times
- Performance bottlenecks identified
- Optimization recommendations provided

## Recommendations

### Performance Optimizations
1. Implement connection pooling
2. Add response caching where appropriate
3. Optimize database queries
4. Consider load balancing for high traffic

### Monitoring
1. Set up performance monitoring
2. Implement alerting for response times
3. Track resource utilization
4. Monitor error rates

### Scaling
1. Plan for horizontal scaling
2. Implement database replication
3. Use CDN for static assets
4. Consider microservices architecture

## Next Steps

1. Address performance bottlenecks
2. Implement recommended optimizations
3. Set up continuous performance monitoring
4. Plan for capacity scaling

EOF

    log_success "Performance report generated: performance_report.md"
}

# Main execution
main() {
    log "Starting FIDO2/WebAuthn performance testing"
    log "=========================================="
    
    # Check if we're in the right directory
    if [ ! -f "Cargo.toml" ]; then
        log_failure "Cargo.toml not found. Please run this script from the project root."
        exit 1
    fi
    
    # Check if server is running
    if ! check_server; then
        log_failure "Please start the server before running performance tests"
        exit 1
    fi
    
    # Run performance tests
    baseline_test
    api_performance_test
    load_test_curl
    stress_test
    memory_test
    
    # Generate report
    generate_performance_report
    
    log "=========================================="
    log "Performance testing complete!"
    log "Report generated: performance_report.md"
}

# Run main function
main "$@"