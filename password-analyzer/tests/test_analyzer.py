#!/usr/bin/env python3
"""
Test suite for the Password Strength Analyzer.
This script runs tests against the password analyzer to verify functionality.
"""

import sys
import os
from pathlib import Path

# Add the parent directory to the path for imports
sys.path.append(str(Path(__file__).parent.parent))

from src.password_analyzer import (
    analyze_password,
    calculate_entropy,
    check_complexity,
    check_patterns,
    generate_password_suggestion,
    load_dictionaries
)

# Initialize dictionary data
load_dictionaries()

def test_password_analysis():
    """Test the password analysis functionality with various passwords."""
    print("\n=== Testing Password Analysis ===")
    
    test_cases = [
        {
            "password": "password",
            "expected": {
                "strength": "Very Weak",
                "score_range": (0, 30),
                "has_issue": "common password"
            }
        },
        {
            "password": "Password123",
            "expected": {
                "strength": "Weak",
                "score_range": (25, 50),
                "has_issue": "common"
            }
        },
        {
            "password": "J7nB#9pL",
            "expected": {
                "strength": "Moderate",
                "score_range": (50, 70),
                "recommendations": ["length"]
            }
        },
        {
            "password": "c0rr3ct-h0rs3-b4tt3ry-st4pl3",
            "expected": {
                "strength": "Strong",
                "score_range": (70, 90),
                "recommendations_max": 1
            }
        },
        {
            "password": "aK8#Lp2$7mZ!9vB5^tN",
            "expected": {
                "strength": "Very Strong",
                "score_range": (90, 100),
                "recommendations_max": 0
            }
        }
    ]
    
    for i, case in enumerate(test_cases, 1):
        password = case["password"]
        expected = case["expected"]
        
        print(f"\nTest {i}: '{password}'")
        
        # Run analysis
        report = analyze_password(password)
        
        # Check strength
        print(f"  Strength: {report['strength']} (expected {expected['strength']})")
        if report['strength'] != expected['strength']:
            print(f"  ❌ FAILED: Incorrect strength classification")
        else:
            print(f"  ✅ PASSED: Strength classification")
        
        # Check score range
        min_score, max_score = expected['score_range']
        score_in_range = min_score <= report['overall_score'] <= max_score
        print(f"  Score: {report['overall_score']} (expected range {min_score}-{max_score})")
        if not score_in_range:
            print(f"  ❌ FAILED: Score out of expected range")
        else:
            print(f"  ✅ PASSED: Score in expected range")
        
        # Check for expected issues
        if "has_issue" in expected:
            issue_found = any(expected["has_issue"] in issue.lower() for issue in report["issues"])
            print(f"  Expected issue '{expected['has_issue']}': {'Found' if issue_found else 'Not found'}")
            if not issue_found:
                print(f"  ❌ FAILED: Did not detect expected issue")
            else:
                print(f"  ✅ PASSED: Detected expected issue")
        
        # Check recommendations
        if "recommendations" in expected:
            rec_found = any(expected["recommendations"][0] in rec.lower() for rec in report["recommendations"])
            print(f"  Expected recommendation about '{expected['recommendations'][0]}': {'Found' if rec_found else 'Not found'}")
            if not rec_found:
                print(f"  ❌ FAILED: Did not provide expected recommendation")
            else:
                print(f"  ✅ PASSED: Provided expected recommendation")
        
        # Check max recommendations
        if "recommendations_max" in expected:
            rec_count = len(report["recommendations"])
            print(f"  Recommendation count: {rec_count} (max allowed {expected['recommendations_max']})")
            if rec_count > expected["recommendations_max"]:
                print(f"  ❌ FAILED: Too many recommendations for strong password")
            else:
                print(f"  ✅ PASSED: Appropriate recommendation count")


def test_entropy_calculation():
    """Test the entropy calculation functionality."""
    print("\n=== Testing Entropy Calculation ===")
    
    test_cases = [
        {"password": "a", "expected_min": 4.0, "expected_max": 5.0},
        {"password": "ab", "expected_min": 9.0, "expected_max": 10.0},
        {"password": "abc123", "expected_min": 35.0, "expected_max": 38.0},
        {"password": "Abc123!", "expected_min": 45.0, "expected_max": 52.0},
        {"password": "aB3!xY7^", "expected_min": 52.0, "expected_max": 60.0},
    ]
    
    for case in test_cases:
        password = case["password"]
        entropy = calculate_entropy(password)
        min_entropy = case["expected_min"]
        max_entropy = case["expected_max"]
        
        print(f"Password: '{password}', Entropy: {entropy:.2f} bits (expected range: {min_entropy}-{max_entropy})")
        
        if min_entropy <= entropy <= max_entropy:
            print(f"✅ PASSED: Entropy in expected range")
        else:
            print(f"❌ FAILED: Entropy outside expected range")


def test_complexity_check():
    """Test the complexity checking functionality."""
    print("\n=== Testing Complexity Checking ===")
    
    test_cases = [
        {"password": "aaaaaaaa", "expected_min": 30, "expected_max": 40},
        {"password": "Aaaaaaaa", "expected_min": 40, "expected_max": 50},
        {"password": "Aa1aaaaa", "expected_min": 50, "expected_max": 60},
        {"password": "Aa1!aaaa", "expected_min": 60, "expected_max": 70},
        {"password": "Aa1!2Bb@", "expected_min": 70, "expected_max": 100},
    ]
    
    for case in test_cases:
        password = case["password"]
        score = check_complexity(password)
        min_score = case["expected_min"]
        max_score = case["expected_max"]
        
        print(f"Password: '{password}', Complexity Score: {score} (expected range: {min_score}-{max_score})")
        
        if min_score <= score <= max_score:
            print(f"✅ PASSED: Complexity score in expected range")
        else:
            print(f"❌ FAILED: Complexity score outside expected range")


def test_pattern_detection():
    """Test the pattern detection functionality."""
    print("\n=== Testing Pattern Detection ===")
    
    test_cases = [
        {"password": "abcdef", "expected_patterns": ["sequence"]},
        {"password": "password", "expected_patterns": ["common password"]},
        {"password": "aaaabb", "expected_patterns": ["repeated"]},
        {"password": "football2023", "expected_patterns": ["dictionary", "year"]},
        {"password": "p4ssw0rd", "expected_patterns": ["dictionary"]},
    ]
    
    for case in test_cases:
        password = case["password"]
        issues = check_patterns(password)
        expected = case["expected_patterns"]
        
        print(f"\nPassword: '{password}'")
        print(f"Issues detected: {len(issues)}")
        for issue in issues:
            print(f"  - {issue}")
        
        all_found = True
        for pattern in expected:
            found = any(pattern.lower() in issue.lower() for issue in issues)
            print(f"Expected pattern '{pattern}': {'✅ Found' if found else '❌ Not found'}")
            if not found:
                all_found = False
        
        if all_found:
            print(f"✅ PASSED: All expected patterns detected")
        else:
            print(f"❌ FAILED: Some expected patterns not detected")


def test_password_generation():
    """Test the password generation functionality."""
    print("\n=== Testing Password Generation ===")
    
    # Generate and test 5 passwords
    for i in range(5):
        password = generate_password_suggestion()
        report = analyze_password(password)
        
        print(f"\nGenerated Password {i+1}: {password}")
        print(f"Length: {len(password)}")
        print(f"Score: {report['overall_score']:.2f}")
        print(f"Strength: {report['strength']}")
        
        # Check if generated password is strong enough
        if report['overall_score'] < 70:
            print(f"❌ FAILED: Generated password score too low: {report['overall_score']:.2f}")
        else:
            print(f"✅ PASSED: Generated password is strong")
        
        # Check for sufficient complexity
        if not (
            any(c.islower() for c in password) and
            any(c.isupper() for c in password) and
            any(c.isdigit() for c in password) and
            any(not c.isalnum() for c in password)
        ):
            print(f"❌ FAILED: Generated password missing required character classes")
        else:
            print(f"✅ PASSED: Generated password has all character classes")


def run_all_tests():
    """Run all tests."""
    test_password_analysis()
    test_entropy_calculation()
    test_complexity_check()
    test_pattern_detection()
    test_password_generation()


if __name__ == "__main__":
    print("===== Password Analyzer Test Suite =====")
    run_all_tests()
    print("\n===== All Tests Completed =====")