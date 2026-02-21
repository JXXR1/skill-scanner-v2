#!/bin/bash
# Skill Scanner v2 Certification Test
# Validates detection accuracy with known samples
# Author: JXXR1

SCANNER="../skill-scan-v2.sh"
TEST_DIR="$(dirname "$0")"
RESULTS="certification-results-$(date +%Y%m%d-%H%M%S).txt"

echo "=== Skill Scanner v2 Certification Test ===" | tee "$RESULTS"
echo "Date: $(date -u)" | tee -a "$RESULTS"
echo "" | tee -a "$RESULTS"

TOTAL=0
PASSED=0
FAILED=0

test_skill() {
    local name=$1
    local path=$2
    local expected=$3
    local threshold=$4
    
    echo "Testing: $name" | tee -a "$RESULTS"
    OUTPUT=$(bash "$SCANNER" "$path" 2>&1)
    EXIT_CODE=$?
    echo "  Exit Code: $EXIT_CODE" | tee -a "$RESULTS"
    
    RESULT="FAIL"
    if [ "$expected" = "MALICIOUS" ] && [ "$EXIT_CODE" -ge "$threshold" ]; then
        RESULT="PASS"
        ((PASSED++))
    elif [ "$expected" = "SUSPICIOUS" ] && [ "$EXIT_CODE" -gt 0 ] && [ "$EXIT_CODE" -lt 10 ]; then
        RESULT="PASS"
        ((PASSED++))
    elif [ "$expected" = "CLEAN" ] && [ "$EXIT_CODE" -eq 0 ]; then
        RESULT="PASS"
        ((PASSED++))
    else
        ((FAILED++))
    fi
    
    ((TOTAL++))
    echo "  Result: $RESULT" | tee -a "$RESULTS"
    echo "$OUTPUT" | grep -E "🚫|⚠️" | head -3 | tee -a "$RESULTS"
    echo "" | tee -a "$RESULTS"
}

echo "=== MALICIOUS SAMPLES ===" | tee -a "$RESULTS"
test_skill "Crypto Miner" "$TEST_DIR/malicious-miner" "MALICIOUS" 10
test_skill "Reverse Shell" "$TEST_DIR/malicious-shell" "MALICIOUS" 10
test_skill "Infostealer" "$TEST_DIR/malicious-stealer" "MALICIOUS" 10
test_skill "Typosquatting" "$TEST_DIR/suspicious-typosquat" "MALICIOUS" 10

echo "=== SUSPICIOUS SAMPLES ===" | tee -a "$RESULTS"
test_skill "Obfuscated Code" "$TEST_DIR/suspicious-obfuscated" "SUSPICIOUS" 1

echo "=== CLEAN SAMPLES ===" | tee -a "$RESULTS"
test_skill "Weather API" "$TEST_DIR/clean-weather" "CLEAN" 0
test_skill "Hello Skill" "$TEST_DIR/clean-hello" "CLEAN" 0

echo "==========================================" | tee -a "$RESULTS"
echo "Total: $TOTAL | Passed: $PASSED | Failed: $FAILED" | tee -a "$RESULTS"

if [ "$FAILED" -eq 0 ]; then
    echo "✅ CERTIFICATION: PASSED (100%)" | tee -a "$RESULTS"
    echo "" | tee -a "$RESULTS"
    echo "Skill Scanner v2 is CERTIFIED for production use" | tee -a "$RESULTS"
    echo "" | tee -a "$RESULTS"
    echo "Detection Coverage:" | tee -a "$RESULTS"
    echo "  - Crypto Miners: ✅" | tee -a "$RESULTS"
    echo "  - Reverse Shells: ✅" | tee -a "$RESULTS"
    echo "  - Infostealers: ✅" | tee -a "$RESULTS"
    echo "  - Typosquatting: ✅" | tee -a "$RESULTS"
    echo "  - Obfuscation: ✅" | tee -a "$RESULTS"
    echo "  - Clean Code: ✅ (No false positives)" | tee -a "$RESULTS"
    exit 0
else
    ACCURACY=$((PASSED * 100 / TOTAL))
    echo "⚠️  CERTIFICATION: PARTIAL ($ACCURACY%)" | tee -a "$RESULTS"
    exit 1
fi
