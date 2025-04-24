# Password Strength Analyzer

## Overview
This project provides a comprehensive password strength analysis tool that evaluates passwords against NIST SP 800-63B and OWASP guidelines. The analyzer checks password complexity, detects common patterns, and calculates entropy to provide a holistic security assessment with specific recommendations for improvement.

## Why Analyze Password Strength?
- Weak passwords remain one of the top causes of security breaches
- Users often underestimate the vulnerability of their password choices
- NIST and OWASP guidelines are continually updated but not widely understood
- Password managers and generators need evaluation metrics

## Features

### Password Strength Assessment
- Overall security score (0-100)
- Strength classification (Very Weak, Weak, Moderate, Strong, Very Strong)
- Detailed breakdown of contributing factors

### Security Checks
- **Length Analysis**: Enforces minimum length requirements (8+ chars) with bonuses for longer passwords
- **Complexity Verification**: Checks for character variety (uppercase, lowercase, numbers, symbols)
- **Pattern Detection**: Identifies vulnerable patterns:
  - Common passwords (from known breach lists)
  - Dictionary words
  - Keyboard sequences (qwerty, 12345)
  - Repeated characters (aaa, 111)
  - Date formats and years
  - Common character substitutions (p4ssw0rd, l33t speak)

### Additional Tools
- Password entropy calculation (bits of randomness)
- Strong password generation with configurable criteria
- Password comparison to evaluate multiple options
- Detailed recommendations for improvement
- Report saving for documentation purposes

## Usage

### Basic Command Line
```bash
# Simple password analysis
python src/password_analyzer.py

# Save analysis report to file
python src/password_analyzer.py --output report.json
```

### Interactive CLI
```bash
python src/cli.py
```

The interactive CLI provides:
- Menu-based interface with color-coded results
- Password comparison functionality
- Integrated password generation
- Detailed help and educational content

## 📸 Screenshots

### Password Analysis Report
![Password Analysis Report](screenshots/password_analysis.png)

### Multiple Password Comparison
![Password Comparison](screenshots/password_comparison.png)

### Password Generation
![Password Generation](screenshots/password_generation.png)

## Technical Details

### Scoring Methodology
The overall password strength score is calculated using a weighted combination of:

1. **Entropy (50%)**: Measures randomness based on character set and length
2. **Complexity (30%)**: Evaluates character variety and distribution
3. **Pattern Safety (20%)**: Penalizes common patterns and vulnerabilities

Each component is scored from 0-100 and weighted to produce the final score.

### Implementation Notes
- All password analysis is performed locally
- No passwords are transmitted over a network
- The tool uses relative dictionaries that can be expanded for more comprehensive checks
- Secure input handling using Python's getpass module

## References and Standards
- [NIST SP 800-63B Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [OWASP Authentication Best Practices](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [Have I Been Pwned](https://haveibeenpwned.com/) (Research on password breaches)

## Future Improvements
- Integration with Have I Been Pwned API to check for compromised passwords
- Support for passphrase evaluation with linguistic analysis
- Additional language dictionaries for international usage
- Web interface with client-side JavaScript implementation