#!/usr/bin/env python3
"""
Password Strength Analyzer

This tool analyzes password strength according to NIST and OWASP guidelines.
It checks for common patterns, dictionary words, and provides an overall
strength score with specific recommendations for improvement.
"""

import re
import math
import argparse
import getpass
from pathlib import Path
from datetime import datetime
import json
import sys

# Constants for scoring
MIN_LENGTH = 8
RECOMMENDED_LENGTH = 12
MAX_SCORE = 100
ENTROPY_WEIGHT = 0.5
COMPLEXITY_WEIGHT = 0.3
PATTERN_WEIGHT = 0.2

# Common password lists (paths are relative to this script)
BASE_DIR = Path(__file__).parent.parent
COMMON_PASSWORDS_PATH = BASE_DIR / "data/common_passwords.txt"
WORD_LIST_PATH = BASE_DIR / "data/english_words.txt"

# Global variables for dictionary checks
common_passwords = set()
dictionary_words = set()


def load_dictionaries():
    """Load the common password and dictionary word lists."""
    global common_passwords, dictionary_words
    
    # Create data directory if it doesn't exist
    data_dir = BASE_DIR / "data"
    data_dir.mkdir(exist_ok=True)
    
    # Initialize with a small set of very common passwords if file doesn't exist
    if not COMMON_PASSWORDS_PATH.exists():
        default_common = ["password", "123456", "qwerty", "admin", "welcome", 
                         "password123", "abc123", "letmein", "monkey", "1234567890"]
        with open(COMMON_PASSWORDS_PATH, 'w') as f:
            f.write('\n'.join(default_common))
    
    # Read common passwords
    try:
        with open(COMMON_PASSWORDS_PATH, 'r') as f:
            common_passwords = {line.strip().lower() for line in f if line.strip()}
    except Exception as e:
        print(f"Warning: Could not load common passwords file: {e}")
    
    # Initialize with a small set of common words if file doesn't exist
    if not WORD_LIST_PATH.exists():
        default_words = ["password", "admin", "user", "login", "welcome", "secret",
                         "dragon", "baseball", "football", "letmein", "monkey", "sunshine"]
        with open(WORD_LIST_PATH, 'w') as f:
            f.write('\n'.join(default_words))
    
    # Read dictionary words
    try:
        with open(WORD_LIST_PATH, 'r') as f:
            dictionary_words = {line.strip().lower() for line in f if line.strip()}
    except Exception as e:
        print(f"Warning: Could not load word list file: {e}")


def calculate_entropy(password):
    """Calculate the entropy of a password in bits."""
    # Count character classes
    has_lowercase = bool(re.search(r'[a-z]', password))
    has_uppercase = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[^a-zA-Z0-9]', password))
    
    # Calculate pool size
    pool_size = 0
    if has_lowercase:
        pool_size += 26
    if has_uppercase:
        pool_size += 26
    if has_digit:
        pool_size += 10
    if has_special:
        pool_size += 33  # Approximation of special characters
    
    # If no characters are found, return 0
    if pool_size == 0:
        return 0
    
    # Calculate entropy (H = L * log2(R)) where L is length and R is pool size
    entropy = len(password) * math.log2(pool_size)
    return entropy


def check_complexity(password):
    """Check password complexity and return a score out of 100."""
    score = 0
    
    # Length checks (up to 40 points)
    if len(password) >= MIN_LENGTH:
        score += 20
        # Bonus for longer passwords
        if len(password) >= RECOMMENDED_LENGTH:
            bonus = min(20, (len(password) - MIN_LENGTH) * 2)
            score += bonus
    
    # Character variety (up to 40 points)
    if re.search(r'[a-z]', password):
        score += 10
    if re.search(r'[A-Z]', password):
        score += 10
    if re.search(r'\d', password):
        score += 10
    if re.search(r'[^a-zA-Z0-9]', password):
        score += 10
    
    # Bonus for good distribution of characters (up to 20 points)
    char_counts = {}
    for char in password:
        char_counts[char] = char_counts.get(char, 0) + 1
    
    unique_ratio = len(char_counts) / len(password) if password else 0
    distribution_score = int(unique_ratio * 20)
    score += distribution_score
    
    return score


def check_patterns(password):
    """Check for common patterns and return a list of issues found."""
    issues = []
    
    # Check for sequences
    sequences = [
        "abcdefghijklmnopqrstuvwxyz",
        "zyxwvutsrqponmlkjihgfedcba",
        "0123456789",
        "9876543210",
        "qwertyuiop",
        "poiuytrewq",
        "asdfghjkl",
        "lkjhgfdsa",
        "zxcvbnm",
        "mnbvcxz"
    ]
    
    for seq in sequences:
        for i in range(len(seq) - 2):
            if seq[i:i+3].lower() in password.lower():
                issues.append(f"Contains a common sequence '{seq[i:i+3]}'")
                break
    
    # Check for repeated characters
    if re.search(r'(.)\1{2,}', password):
        issues.append("Contains repeated characters (3 or more)")
    
    # Check for years and dates
    if re.search(r'19\d\d|20\d\d', password):
        issues.append("Contains a year (19xx or 20xx)")
    
    if re.search(r'(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])', password):
        issues.append("Contains a potential date (MMDD format)")
    
    # Check against common password list
    if password.lower() in common_passwords:
        issues.append("Is a known common password")
    
    # Check for dictionary words (at least 4 chars)
    lower_pass = password.lower()
    for word in dictionary_words:
        if len(word) >= 4 and word in lower_pass:
            issues.append(f"Contains dictionary word '{word}'")
            break
    
    # Check for common substitutions
    leet_map = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7'}
    stripped_pass = password.lower()
    for char, leet in leet_map.items():
        stripped_pass = stripped_pass.replace(leet, char)
    
    if stripped_pass != password.lower():
        # Check if the deleet version is in common words
        for word in dictionary_words:
            if len(word) >= 4 and word in stripped_pass:
                issues.append(f"Contains dictionary word with leet speak substitutions '{word}'")
                break
    
    return issues


def analyze_password(password):
    """Analyze a password and return a comprehensive report."""
    # Calculate the core metrics
    entropy = calculate_entropy(password)
    complexity_score = check_complexity(password)
    pattern_issues = check_patterns(password)
    
    # Calculate pattern score (100 - 20 per issue, minimum 0)
    pattern_deductions = min(5, len(pattern_issues)) * 20
    pattern_score = max(0, 100 - pattern_deductions)
    
    # Calculate final score using weighted average
    final_score = (
        # Scale entropy down instead of up so weak passwords don't
        # automatically receive a high score. This prevents short,
        # simple passwords from appearing "Strong".
        (min(100, entropy / 4) * ENTROPY_WEIGHT) +
        (complexity_score * COMPLEXITY_WEIGHT) +
        (pattern_score * PATTERN_WEIGHT)
    )
    
    # Determine strength category
    strength = "Very Weak"
    if final_score >= 90:
        strength = "Very Strong"
    elif final_score >= 70:
        strength = "Strong"
    elif final_score >= 50:
        strength = "Moderate"
    elif final_score >= 25:
        strength = "Weak"
    
    # Generate recommendations
    recommendations = []
    
    if len(password) < RECOMMENDED_LENGTH:
        recommendations.append(f"Increase length to at least {RECOMMENDED_LENGTH} characters")
    
    if not re.search(r'[a-z]', password):
        recommendations.append("Add lowercase letters")
    if not re.search(r'[A-Z]', password):
        recommendations.append("Add uppercase letters")
    if not re.search(r'\d', password):
        recommendations.append("Add numbers")
    if not re.search(r'[^a-zA-Z0-9]', password):
        recommendations.append("Add special characters")
    
    # Add recommendations based on pattern issues
    for issue in pattern_issues:
        if "common sequence" in issue:
            recommendations.append("Avoid keyboard patterns and sequences")
        elif "repeated characters" in issue:
            recommendations.append("Avoid repeating characters")
        elif "year" in issue or "date" in issue:
            recommendations.append("Avoid using dates and years")
        elif "common password" in issue:
            recommendations.append("Avoid commonly used passwords")
        elif "dictionary word" in issue:
            recommendations.append("Avoid using dictionary words")
    
    # Ensure no duplicate recommendations
    recommendations = list(set(recommendations))
    
    # Create final report
    report = {
        "password_length": len(password),
        "entropy_bits": round(entropy, 2),
        "complexity_score": complexity_score,
        "pattern_score": pattern_score,
        "overall_score": round(final_score, 2),
        "strength": strength,
        "issues": pattern_issues,
        "recommendations": recommendations,
        "timestamp": datetime.now().isoformat()
    }
    
    return report


def generate_password_suggestion():
    """Generate a strong password suggestion."""
    import random
    import string
    
    # Define character sets
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    symbols = "!@#$%^&*()-_=+[]{};:,.<>?"
    
    # Length between 12-16 characters
    length = random.randint(12, 16)
    
    # Ensure at least 2 characters from each set
    password = []
    password.extend(random.choice(lowercase) for _ in range(2))
    password.extend(random.choice(uppercase) for _ in range(2))
    password.extend(random.choice(digits) for _ in range(2))
    password.extend(random.choice(symbols) for _ in range(2))
    
    # Fill the rest randomly
    remaining = length - len(password)
    all_chars = lowercase + uppercase + digits + symbols
    password.extend(random.choice(all_chars) for _ in range(remaining))
    
    # Shuffle the password
    random.shuffle(password)
    
    return ''.join(password)


def print_color_text(text, color_code):
    """Print colored text if supported."""
    if sys.stdout.isatty():  # Check if terminal supports colors
        print(f"\033[{color_code}m{text}\033[0m")
    else:
        print(text)


def print_report(report):
    """Print the password analysis report in a human-readable format."""
    # Define color codes
    GREEN = "32"
    YELLOW = "33"
    RED = "31"
    BLUE = "36"
    
    # Choose color based on strength
    strength = report["strength"]
    if strength in ["Very Strong", "Strong"]:
        strength_color = GREEN
    elif strength == "Moderate":
        strength_color = YELLOW
    else:
        strength_color = RED
    
    print("\n" + "=" * 60)
    print_color_text(f"PASSWORD STRENGTH: {strength.upper()}", strength_color)
    print("=" * 60)
    
    print(f"\nOverall Score: {report['overall_score']}/100")
    print(f"Length: {report['password_length']} characters")
    print(f"Entropy: {report['entropy_bits']} bits")
    print(f"Complexity Score: {report['complexity_score']}/100")
    print(f"Pattern Safety Score: {report['pattern_score']}/100")
    
    if report["issues"]:
        print("\nISSUES DETECTED:")
        for issue in report["issues"]:
            print_color_text(f"• {issue}", RED)
    
    if report["recommendations"]:
        print("\nRECOMMENDATIONS:")
        for rec in report["recommendations"]:
            print_color_text(f"• {rec}", BLUE)
    
    if not report["recommendations"]:
        print_color_text("\nGREAT! No improvements needed.", GREEN)
    
    # Provide a password suggestion if score is less than 70
    if report['overall_score'] < 70:
        print("\nPassword suggestion:")
        print_color_text(generate_password_suggestion(), GREEN)
    
    print("\n" + "=" * 60)


def save_report(report, output_file=None):
    """Save the report to a JSON file."""
    if output_file is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"password_analysis_{timestamp}.json"
    
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"Report saved to {output_file}")


def main():
    """Main function to run the password analyzer."""
    parser = argparse.ArgumentParser(description="Analyze password strength")
    parser.add_argument("--password", "-p", help="Password to analyze (not recommended, use interactive mode)")
    parser.add_argument("--output", "-o", help="Output file for JSON report")
    parser.add_argument("--quiet", "-q", action="store_true", help="Only output JSON report")
    args = parser.parse_args()
    
    # Load dictionaries
    load_dictionaries()
    
    # Get password to analyze
    password = args.password
    if not password:
        password = getpass.getpass("Enter password to analyze: ")
    
    # Analyze password
    report = analyze_password(password)
    
    # Print report unless quiet mode is on
    if not args.quiet:
        print_report(report)
    
    # Save report if output is specified
    if args.output:
        save_report(report, args.output)
    
    return report


if __name__ == "__main__":
    main()