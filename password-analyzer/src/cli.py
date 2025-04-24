#!/usr/bin/env python3
"""
Password Strength Analyzer CLI

This is the command-line interface for the password strength analyzer.
It provides an interactive way to check passwords and view detailed reports.
"""

import sys
import os
import argparse
import getpass
from pathlib import Path
import json
import time

# Add the parent directory to the path
sys.path.append(str(Path(__file__).parent.parent))
from src.password_analyzer import analyze_password, print_report, generate_password_suggestion

# ANSI color codes
RESET = "\033[0m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
BLUE = "\033[36m"
BOLD = "\033[1m"


def clear_screen():
    """Clear the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')


def print_banner():
    """Print the application banner."""
    banner = f"""
{BOLD}╔═══════════════════════════════════════════════════════╗
║                                                       ║
║  {BLUE}PASSWORD STRENGTH ANALYZER{RESET}{BOLD}                        ║
║  {YELLOW}Evaluate passwords against NIST/OWASP guidelines{RESET}{BOLD}    ║
║                                                       ║
╚═══════════════════════════════════════════════════════╝{RESET}
"""
    print(banner)


def print_menu():
    """Print the main menu options."""
    print(f"\n{BOLD}Select an option:{RESET}")
    print(f"  {BLUE}1.{RESET} Analyze a password")
    print(f"  {BLUE}2.{RESET} Generate a strong password")
    print(f"  {BLUE}3.{RESET} Compare multiple passwords")
    print(f"  {BLUE}4.{RESET} Save last analysis to file")
    print(f"  {BLUE}5.{RESET} About/Help")
    print(f"  {BLUE}6.{RESET} Exit")


def analyze_password_flow():
    """Handle the password analysis flow."""
    # Get the password
    password = getpass.getpass(f"\n{BOLD}Enter password to analyze:{RESET} ")
    
    if not password:
        print(f"{YELLOW}No password entered. Returning to main menu.{RESET}")
        return None
    
    print(f"\n{BLUE}Analyzing password...{RESET}")
    time.sleep(0.5)  # Small delay for UX
    
    # Analyze the password
    report = analyze_password(password)
    
    # Print the report
    print_report(report)
    
    input(f"\n{BOLD}Press Enter to continue...{RESET}")
    return report


def generate_password_flow():
    """Handle password generation flow."""
    print(f"\n{BLUE}Generating a strong password...{RESET}")
    time.sleep(0.5)  # Small delay for UX
    
    password = generate_password_suggestion()
    
    print(f"\n{GREEN}Generated password:{RESET}")
    print(f"{BOLD}{password}{RESET}")
    
    # Ask if user wants to analyze this password
    choice = input(f"\n{BOLD}Would you like to analyze this password? (y/n):{RESET} ").lower()
    
    if choice.startswith('y'):
        print(f"\n{BLUE}Analyzing generated password...{RESET}")
        time.sleep(0.5)
        report = analyze_password(password)
        print_report(report)
        return report
    
    input(f"\n{BOLD}Press Enter to continue...{RESET}")
    return None


def compare_passwords_flow():
    """Handle comparing multiple passwords."""
    print(f"\n{BOLD}Compare Multiple Passwords{RESET}")
    print("Enter each password when prompted. Press Enter with an empty password to finish.")
    
    passwords = []
    reports = []
    
    i = 1
    while True:
        password = getpass.getpass(f"\n{BOLD}Enter password #{i} (or empty to finish):{RESET} ")
        if not password:
            break
        
        passwords.append(password)
        reports.append(analyze_password(password))
        i += 1
    
    if not passwords:
        print(f"{YELLOW}No passwords entered. Returning to main menu.{RESET}")
        return None
    
    # Display comparison table
    print("\n" + "=" * 80)
    print(f"{BOLD}PASSWORD COMPARISON{RESET}")
    print("=" * 80)
    
    # Table headers
    print(f"{'#':<3} {'Password':<20} {'Score':<8} {'Strength':<12} {'Length':<8} {'Entropy':<8}")
    print("-" * 80)
    
    # Table rows
    for i, (password, report) in enumerate(zip(passwords, reports), 1):
        # Mask password except first and last character
        if len(password) > 2:
            masked = password[0] + '*' * (len(password) - 2) + password[-1]
        else:
            masked = '*' * len(password)
        
        score = report['overall_score']
        strength = report['strength']
        
        # Apply color based on strength
        if strength in ["Very Strong", "Strong"]:
            strength_color = GREEN
        elif strength == "Moderate":
            strength_color = YELLOW
        else:
            strength_color = RED
        
        print(f"{i:<3} {masked:<20} {score:<8.2f} {strength_color}{strength:<12}{RESET} "
              f"{report['password_length']:<8} {report['entropy_bits']:<8.2f}")
    
    print("-" * 80)
    
    # Identify the best password
    best_idx = max(range(len(reports)), key=lambda i: reports[i]['overall_score'])
    print(f"\n{GREEN}Best password: #{best_idx + 1} with score {reports[best_idx]['overall_score']:.2f}{RESET}")
    
    input(f"\n{BOLD}Press Enter to continue...{RESET}")
    return reports[best_idx]  # Return the best report


def save_report_flow(report):
    """Handle saving the report to a file."""
    if not report:
        print(f"{YELLOW}No report available to save. Analyze a password first.{RESET}")
        input(f"\n{BOLD}Press Enter to continue...{RESET}")
        return
    
    filename = input(f"\n{BOLD}Enter filename to save report (default: password_report.json):{RESET} ")
    if not filename:
        filename = "password_report.json"
    
    # Ensure filename has .json extension
    if not filename.endswith('.json'):
        filename += '.json'
    
    try:
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\n{GREEN}Report saved successfully to {filename}{RESET}")
    except Exception as e:
        print(f"\n{RED}Error saving report: {e}{RESET}")
    
    input(f"\n{BOLD}Press Enter to continue...{RESET}")


def show_help():
    """Display help information."""
    help_text = f"""
{BOLD}About Password Strength Analyzer{RESET}

This tool analyzes passwords according to NIST SP 800-63B and OWASP guidelines:

1. {BLUE}Length{RESET} - Passwords should be at least 8 characters, ideally 12+

2. {BLUE}Complexity{RESET} - Evaluated based on:
   • Lowercase letters (a-z)
   • Uppercase letters (A-Z)
   • Numbers (0-9)
   • Special characters (!@#$, etc.)

3. {BLUE}Pattern Analysis{RESET} - Checks for:
   • Common passwords
   • Dictionary words
   • Keyboard patterns (qwerty, 12345)
   • Repeated characters (aaa, 111)
   • Dates and years
   • Common substitutions (p4ssw0rd)

The report provides:
• Overall strength score (0-100)
• Detailed analysis of issues
• Specific recommendations for improvement
• Password entropy calculation (measure of randomness)

{BOLD}Privacy Note:{RESET} All analysis is performed locally. 
No passwords are transmitted over the network or stored permanently.
"""
    print(help_text)
    input(f"\n{BOLD}Press Enter to continue...{RESET}")


def main():
    """Main function to run the interactive CLI."""
    parser = argparse.ArgumentParser(description="Password Strength Analyzer")
    parser.add_argument("--no-clear", action="store_true", help="Don't clear the screen between operations")
    args = parser.parse_args()
    
    last_report = None
    
    while True:
        if not args.no_clear:
            clear_screen()
        
        print_banner()
        print_menu()
        
        choice = input(f"\n{BOLD}Enter your choice (1-6):{RESET} ")
        
        if choice == '1':
            last_report = analyze_password_flow()
        elif choice == '2':
            last_report = generate_password_flow()
        elif choice == '3':
            last_report = compare_passwords_flow()
        elif choice == '4':
            save_report_flow(last_report)
        elif choice == '5':
            show_help()
        elif choice == '6':
            print(f"\n{GREEN}Thank you for using Password Strength Analyzer. Goodbye!{RESET}")
            sys.exit(0)
        else:
            print(f"\n{RED}Invalid choice. Please enter a number between 1 and 6.{RESET}")
            time.sleep(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{YELLOW}Program interrupted. Exiting...{RESET}")
        sys.exit(0)