#!/bin/bash

# Comprehensive Test Runner for HFT WebSocket Library
# Runs all test suites with proper reporting

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test results
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0

# Build directory
BUILD_DIR="${BUILD_DIR:-build}"
cd "$(dirname "$0")/.."

echo "HFT WebSocket Library - Test Suite Runner"
echo "=========================================="
echo ""

# Check if build directory exists
if [ ! -d "$BUILD_DIR" ]; then
    echo -e "${YELLOW}Build directory not found. Building...${NC}"
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"
    cmake .. -DCMAKE_BUILD_TYPE=Release
    make -j$(sysctl -n hw.ncpu)
    cd ..
fi

# Function to run a test
run_test() {
    local test_name="$1"
    local test_binary="$BUILD_DIR/$2"
    
    if [ ! -f "$test_binary" ]; then
        echo -e "${RED}✗${NC} $test_name: Binary not found ($test_binary)"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        TESTS_TOTAL=$((TESTS_TOTAL + 1))
        return 1
    fi
    
    echo -e "${YELLOW}Running: $test_name${NC}"
    echo "----------------------------------------"
    
    if "$test_binary"; then
        echo -e "${GREEN}✓${NC} $test_name: PASSED"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        TESTS_TOTAL=$((TESTS_TOTAL + 1))
        return 0
    else
        echo -e "${RED}✗${NC} $test_name: FAILED"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        TESTS_TOTAL=$((TESTS_TOTAL + 1))
        return 1
    fi
}

# Function to run test with AddressSanitizer
run_test_asan() {
    local test_name="$1"
    local test_binary="$BUILD_DIR/$2"
    
    if [ ! -f "$test_binary" ]; then
        echo -e "${RED}✗${NC} $test_name (ASan): Binary not found"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        TESTS_TOTAL=$((TESTS_TOTAL + 1))
        return 1
    fi
    
    echo -e "${YELLOW}Running (AddressSanitizer): $test_name${NC}"
    echo "----------------------------------------"
    
    # Check if ASan build exists
    if nm "$test_binary" | grep -q "__asan"; then
        if "$test_binary"; then
            echo -e "${GREEN}✓${NC} $test_name (ASan): PASSED"
            TESTS_PASSED=$((TESTS_PASSED + 1))
            TESTS_TOTAL=$((TESTS_TOTAL + 1))
            return 0
        else
            echo -e "${RED}✗${NC} $test_name (ASan): FAILED"
            TESTS_FAILED=$((TESTS_FAILED + 1))
            TESTS_TOTAL=$((TESTS_TOTAL + 1))
            return 1
        fi
    else
        echo -e "${YELLOW}⚠${NC} $test_name: Not built with AddressSanitizer (skipping)"
        return 0
    fi
}

# Parse command line arguments
RUN_UNIT_TESTS=1
RUN_STRESS_TESTS=1
RUN_PERFORMANCE_TESTS=1
RUN_INTEGRATION_TESTS=0
RUN_ASAN_TESTS=0
QUICK_MODE=0

while [[ $# -gt 0 ]]; do
    case $1 in
        --unit-only)
            RUN_UNIT_TESTS=1
            RUN_STRESS_TESTS=0
            RUN_PERFORMANCE_TESTS=0
            RUN_INTEGRATION_TESTS=0
            ;;
        --stress-only)
            RUN_UNIT_TESTS=0
            RUN_STRESS_TESTS=1
            RUN_PERFORMANCE_TESTS=0
            RUN_INTEGRATION_TESTS=0
            ;;
        --performance-only)
            RUN_UNIT_TESTS=0
            RUN_STRESS_TESTS=0
            RUN_PERFORMANCE_TESTS=1
            RUN_INTEGRATION_TESTS=0
            ;;
        --integration-only)
            RUN_UNIT_TESTS=0
            RUN_STRESS_TESTS=0
            RUN_PERFORMANCE_TESTS=0
            RUN_INTEGRATION_TESTS=1
            ;;
        --asan)
            RUN_ASAN_TESTS=1
            ;;
        --quick)
            QUICK_MODE=1
            ;;
        --help)
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --unit-only        Run only unit tests"
            echo "  --stress-only      Run only stress tests"
            echo "  --performance-only Run only performance tests"
            echo "  --integration-only Run only integration tests"
            echo "  --asan             Run AddressSanitizer tests (if built)"
            echo "  --quick            Skip long-running tests"
            echo "  --help             Show this help"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
    shift
done

# Unit Tests
if [ $RUN_UNIT_TESTS -eq 1 ]; then
    echo ""
    echo "=== Unit Tests ==="
    echo ""
    
    run_test "Ring Buffer Tests" "test_ringbuffer"
    run_test "Parser Neon Tests" "test_parser_neon"
    run_test "kqueue Tests" "test_kqueue"
    run_test "Memory Management Tests" "test_memory"
    run_test "Error Handling Tests" "test_errors"
    run_test "Thread Safety Tests" "test_threading"
fi

# Stress Tests
if [ $RUN_STRESS_TESTS -eq 1 ]; then
    echo ""
    echo "=== Stress Tests ==="
    echo ""
    
    if [ $QUICK_MODE -eq 1 ]; then
        echo -e "${YELLOW}Skipping stress tests in quick mode${NC}"
    else
        run_test "Stress Tests" "test_stress"
    fi
fi

# Performance Tests
if [ $RUN_PERFORMANCE_TESTS -eq 1 ]; then
    echo ""
    echo "=== Performance Tests ==="
    echo ""
    
    run_test "Performance Tests" "test_performance"
fi

# Integration Tests
if [ $RUN_INTEGRATION_TESTS -eq 1 ]; then
    echo ""
    echo "=== Integration Tests ==="
    echo ""
    
    if [ $QUICK_MODE -eq 1 ]; then
        echo -e "${YELLOW}Skipping integration tests in quick mode${NC}"
    else
        run_test "Integration Binance" "test_integration_binance"
        run_test "WebSocket Reconnect" "test_websocket_reconnect"
        run_test "Integration Stress" "test_integration_stress"
    fi
fi

# AddressSanitizer Tests
if [ $RUN_ASAN_TESTS -eq 1 ]; then
    echo ""
    echo "=== AddressSanitizer Tests ==="
    echo ""
    
    # Rebuild with ASan if needed
    if [ ! -d "${BUILD_DIR}_asan" ]; then
        echo -e "${YELLOW}Building AddressSanitizer version...${NC}"
        mkdir -p "${BUILD_DIR}_asan"
        cd "${BUILD_DIR}_asan"
        cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS_DEBUG="-O0 -g -fsanitize=address"
        make -j$(sysctl -n hw.ncpu)
        cd ..
    fi
    
    run_test_asan "Memory Tests (ASan)" "${BUILD_DIR}_asan/test_memory"
    run_test_asan "Error Tests (ASan)" "${BUILD_DIR}_asan/test_errors"
fi

# Summary
echo ""
echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo -e "Total:  $TESTS_TOTAL"
echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
if [ $TESTS_FAILED -gt 0 ]; then
    echo -e "${RED}Failed: $TESTS_FAILED${NC}"
else
    echo -e "Failed: $TESTS_FAILED"
fi
echo ""

if [ $TESTS_FAILED -gt 0 ]; then
    exit 1
else
    exit 0
fi



