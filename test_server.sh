#!/bin/bash

# Test script to reproduce autograder issues
# This simulates the test sequence to find where the server crashes

cd "$(dirname "$0")"

echo "==================================="
echo "Server Testing Script"
echo "==================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if server is running
check_server() {
    curl -k -s -o /dev/null -w "%{http_code}" https://localhost:8443/ > /dev/null 2>&1
    return $?
}

# Run a test request
test_request() {
    local url=$1
    local name=$2
    local expected_status=${3:-200}
    
    echo -n "Testing $name... "
    
    response=$(curl -k -s -o /tmp/test_output -w "%{http_code}" "https://localhost:8443$url" 2>&1)
    status=$?
    
    if [ $status -ne 0 ]; then
        echo -e "${RED}✗ FAILED - Connection error${NC}"
        echo "  Server may have crashed!"
        return 1
    fi
    
    if [ "$response" = "$expected_status" ]; then
        echo -e "${GREEN}✓ PASSED (HTTP $response)${NC}"
        return 0
    else
        echo -e "${YELLOW}⚠ Got HTTP $response, expected $expected_status${NC}"
        return 2
    fi
}

# Check if server is running
if ! check_server; then
    echo -e "${RED}Server is not running!${NC}"
    echo "Start server with: ./server"
    exit 1
fi

echo "Server is responding"
echo ""

# Test sequence matching autograder order
echo "==================================="
echo "Phase 1: Basic Tests"
echo "==================================="

test_request "/test.txt" "Text file"
test_request "/index.html" "Default index"
test_request "/binaryfile" "Large binary file"
test_request "/test.jpg" "JPG file"
test_request "/name%20with%20spaces.txt" "File with space"
test_request "/file%25name.txt" "File with % symbol"
test_request "/video_server/output.m3u8" "Video manifest"

echo ""
echo "==================================="
echo "Phase 2: Proxy Tests"
echo "==================================="

# Check if backend is running
if ! curl -s http://localhost:5001/ > /dev/null 2>&1; then
    echo -e "${YELLOW}Backend server not running on port 5001${NC}"
    echo "Start with: cd video_server && python3 -m http.server 5001"
    echo ""
fi

test_request "/video_server/output0.ts" "Video Chunk 1"
test_request "/video_server/output1.ts" "Video Chunk 2"

echo ""
echo "==================================="
echo "Phase 3: Failing Tests"
echo "==================================="
echo "These are the tests that fail in autograder:"
echo ""

# This is where autograder fails
test_request "/small_binary.bin" "Small binary file"

if [ $? -eq 1 ]; then
    echo -e "${RED}Server crashed on small binary file test!${NC}"
    echo "This matches the autograder failure."
    exit 1
fi

test_request "/video_server/output2.ts" "Video Chunk 3"

if [ $? -eq 1 ]; then
    echo -e "${RED}Server crashed on Video Chunk 3!${NC}"
    echo "This matches the autograder failure."
    exit 1
fi

echo ""
echo "==================================="
echo "Phase 4: Edge Cases"
echo "==================================="

test_request "/nonexistent.txt" "File Not Found" 404

# Test Bad Gateway - backend should NOT be running for this test
echo ""
echo "Testing Bad Gateway (requires backend to be DOWN):"
echo -n "  Checking backend status... "
if curl -s http://localhost:5001/ > /dev/null 2>&1; then
    echo -e "${YELLOW}Backend is UP - cannot test Bad Gateway${NC}"
    echo "  Stop backend and run: curl -k https://localhost:8443/video_server/test.ts"
else
    echo "Backend is DOWN - testing..."
    test_request "/video_server/test.ts" "Bad Gateway" 502
fi

echo ""
echo "==================================="
echo "Test Summary"
echo "==================================="
echo "If server is still running, all tests passed!"

if check_server; then
    echo -e "${GREEN}✓ Server still responding${NC}"
else
    echo -e "${RED}✗ Server crashed during tests${NC}"
fi
