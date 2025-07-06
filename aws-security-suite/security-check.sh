#!/bin/bash

# AWS Security Suite - Security Validation Script
# Runs comprehensive security checks before deployment

set -e

echo "🔒 AWS Security Suite - Security Validation"
echo "=========================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    local status=$1
    local message=$2
    case $status in
        "SUCCESS")
            echo -e "${GREEN}✅ $message${NC}"
            ;;
        "ERROR")
            echo -e "${RED}❌ $message${NC}"
            ;;
        "WARNING")
            echo -e "${YELLOW}⚠️  $message${NC}"
            ;;
        "INFO")
            echo -e "ℹ️  $message"
            ;;
    esac
}

# Check if virtual environment is activated
check_venv() {
    if [[ "$VIRTUAL_ENV" != "" ]]; then
        print_status "SUCCESS" "Virtual environment detected: $VIRTUAL_ENV"
    else
        print_status "WARNING" "No virtual environment detected. Consider using one for isolation."
    fi
}

# Install security tools if not present
install_security_tools() {
    print_status "INFO" "Installing security scanning tools..."
    
    # Install security dependencies
    pip install --quiet bandit safety semgrep || {
        print_status "ERROR" "Failed to install security tools"
        exit 1
    }
    
    print_status "SUCCESS" "Security tools installed"
}

# Run Bandit security scanner
run_bandit() {
    print_status "INFO" "Running Bandit security scanner..."
    
    if bandit -r . -f txt -o bandit-report.txt --config .bandit 2>/dev/null; then
        print_status "SUCCESS" "Bandit scan completed - No critical issues found"
    else
        print_status "ERROR" "Bandit found security issues. Check bandit-report.txt"
        cat bandit-report.txt
        return 1
    fi
}

# Run Safety vulnerability scanner
run_safety() {
    print_status "INFO" "Running Safety vulnerability scanner..."
    
    if safety check --json --output safety-report.json 2>/dev/null; then
        print_status "SUCCESS" "Safety scan completed - No known vulnerabilities found"
    else
        print_status "ERROR" "Safety found vulnerabilities. Check safety-report.json"
        safety check --short-report
        return 1
    fi
}

# Run Semgrep static analysis
run_semgrep() {
    print_status "INFO" "Running Semgrep static analysis..."
    
    if semgrep --config=auto --json --output=semgrep-report.json . 2>/dev/null; then
        # Check if any findings were reported
        findings=$(jq '.results | length' semgrep-report.json 2>/dev/null || echo "0")
        if [[ "$findings" -eq "0" ]]; then
            print_status "SUCCESS" "Semgrep scan completed - No issues found"
        else
            print_status "WARNING" "Semgrep found $findings potential issues. Review semgrep-report.json"
        fi
    else
        print_status "WARNING" "Semgrep scan failed or not available"
    fi
}

# Check for hardcoded secrets
check_secrets() {
    print_status "INFO" "Checking for hardcoded secrets..."
    
    # Common secret patterns
    secret_patterns=(
        "AWS_ACCESS_KEY_ID.*=.*[A-Z0-9]{20}"
        "AWS_SECRET_ACCESS_KEY.*=.*[A-Za-z0-9/+=]{40}"
        "password.*=.*['\"][^'\"]*['\"]"
        "secret.*=.*['\"][^'\"]*['\"]"
        "token.*=.*['\"][^'\"]*['\"]"
        "api_key.*=.*['\"][^'\"]*['\"]"
    )
    
    found_secrets=false
    for pattern in "${secret_patterns[@]}"; do
        if grep -r -E "$pattern" --include="*.py" --exclude-dir=venv --exclude-dir=.git . 2>/dev/null; then
            found_secrets=true
        fi
    done
    
    if [[ "$found_secrets" == "true" ]]; then
        print_status "ERROR" "Potential hardcoded secrets found. Review the matches above."
        return 1
    else
        print_status "SUCCESS" "No hardcoded secrets detected"
    fi
}

# Check file permissions
check_permissions() {
    print_status "INFO" "Checking file permissions..."
    
    # Find files with overly permissive permissions
    if find . -type f -perm -o+w -not -path "./.git/*" -not -path "./venv/*" 2>/dev/null | grep -q .; then
        print_status "WARNING" "Found world-writable files:"
        find . -type f -perm -o+w -not -path "./.git/*" -not -path "./venv/*"
    else
        print_status "SUCCESS" "File permissions look secure"
    fi
}

# Validate dependencies
validate_dependencies() {
    print_status "INFO" "Validating dependencies..."
    
    # Check for development dependencies in production
    if pip list --format=freeze | grep -E "(pytest|test|mock|debug)" >/dev/null; then
        print_status "WARNING" "Development/test dependencies found. Consider using production requirements."
    fi
    
    # Check for outdated packages with known vulnerabilities
    if pip list --outdated --format=json 2>/dev/null | jq -r '.[].name' | head -5 | grep -q .; then
        print_status "WARNING" "Some packages are outdated. Consider updating."
        pip list --outdated --format=columns | head -10
    else
        print_status "SUCCESS" "Dependencies are up to date"
    fi
}

# Main execution
main() {
    echo
    check_venv
    echo
    
    install_security_tools
    echo
    
    # Run all security checks
    local exit_code=0
    
    check_secrets || exit_code=1
    echo
    
    check_permissions
    echo
    
    run_bandit || exit_code=1
    echo
    
    run_safety || exit_code=1
    echo
    
    run_semgrep
    echo
    
    validate_dependencies
    echo
    
    if [[ $exit_code -eq 0 ]]; then
        print_status "SUCCESS" "All security checks passed! ✨"
        echo
        echo "📋 Security Report Generated:"
        echo "  - bandit-report.txt"
        echo "  - safety-report.json"
        echo "  - semgrep-report.json"
    else
        print_status "ERROR" "Security checks failed. Please address the issues above."
        exit 1
    fi
}

# Run main function
main "$@"