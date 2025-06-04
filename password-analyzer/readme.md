# Password Strength Analyzer

## Overview
This project provides a comprehensive password strength analysis tool that evaluates passwords against NIST SP 800-63B and OWASP guidelines. The analyzer checks password complexity, detects common patterns, and calculates entropy to provide a holistic security assessment with specific recommendations for improvement.

## Prerequisites

-   Python 3.6 or higher is recommended (due to features like `pathlib` and f-strings).
-   The main script `src/password_analyzer.py` does not require any external Python libraries to be installed.
-   The interactive `src/cli.py` may have additional dependencies for its enhanced interface (e.g., for colored output); if you plan to use `cli.py` extensively, check its imports or consider creating a `requirements.txt` if it uses libraries like `rich`.

## Setup

1.  **Clone the Repository:**
    ```bash
    git clone https://github.com/lucchesi-sec/cybersec-projects.git # Or your fork/clone URL
    cd cybersec-projects/password-analyzer
    ```
2.  **Data Files:** The analyzer uses wordlists for improved detection. These are stored in the `data/` directory:
    *   `data/common_passwords.txt`
    *   `data/english_words.txt`
    If these files do not exist when `src/password_analyzer.py` is first run, the script will automatically create them with a small set of default entries to ensure basic functionality. You can enhance detection by expanding these files (see "Customizing Dictionaries" below).

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

### Password Analyzer Script (`src/password_analyzer.py`)
This script analyzes a single password. By default, it securely prompts for the password to avoid it being stored in your shell history.

**Basic Usage (prompts for password):**
```bash
python src/password_analyzer.py
```

**Command-line Options:**
-   `-p PASSWORD`, `--password PASSWORD`:
    Allows you to supply the password directly as an argument.
    *Example:* `python src/password_analyzer.py -p "P@$$wOrd123!"`
    **Note:** Using this option is generally not recommended for security reasons, as the password may be saved in your shell's command history.
-   `-o FILEPATH`, `--output FILEPATH`:
    Saves the detailed analysis report in JSON format to the specified `FILEPATH`.
    *Example:* `python src/password_analyzer.py -o analysis_report.json`
    (You will still be prompted for the password unless `-p` is also used.)
-   `-q`, `--quiet`:
    Suppresses the human-readable console report. This is useful if you only want the JSON output via the `-o` flag.
    *Example:* `python src/password_analyzer.py -o report.json -q`

**Output:**
-   If not in quiet mode (`-q`), a human-readable strength report is printed to the console. This includes the overall score, detected issues, recommendations, and a strength category (e.g., "Very Weak", "Strong").
-   If the `-o` option is used, a JSON file is created containing a detailed breakdown of the analysis, including length, entropy, scores, issues, recommendations, and a timestamp. Example structure:
    ```json
    {
      "password_length": 12,
      "entropy_bits": 76.85,
      "complexity_score": 100,
      "pattern_score": 80,
      "overall_score": 86.43,
      "strength": "Very Strong",
      "issues": [
        "Contains dictionary word 'password'"
      ],
      "recommendations": [
        "Avoid using dictionary words"
      ],
      "timestamp": "YYYY-MM-DDTHH:MM:SS.ffffff"
    }
    ```
    *(Note: Values in the example JSON are illustrative.)*

### Interactive CLI (`src/cli.py`)
For a more user-friendly experience with additional features:
```bash
python src/cli.py
```
The interactive CLI provides:
- Menu-based interface for various functions (analyze single password, compare multiple passwords, generate strong passwords).
- Color-coded results for better readability.
- Integrated password generation tool with configurable criteria.
- Detailed help and educational content within the interface.
Follow the on-screen prompts to navigate and use its features.

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

## Customizing Dictionaries
The accuracy of the analyzer, particularly in detecting common passwords and dictionary words, is significantly influenced by the wordlists it uses. The script relies on two primary files located in the `data/` directory:

-   `data/common_passwords.txt`: This file should contain a list of commonly used or breached passwords, one per line.
-   `data/english_words.txt`: This file should contain a list of English dictionary words, one per line.

If these files are not present when `src/password_analyzer.py` is run for the first time, the script will automatically create them with a small set of default entries to ensure basic functionality.

**To enhance the analyzer's detection capabilities:**
1.  **Add Entries:** You can manually edit these `.txt` files to add more passwords or words. Ensure each new entry is on a new line.
2.  **Use Comprehensive Lists:** For more robust analysis, consider replacing the default files with larger, more comprehensive wordlists available from public security resources (e.g., parts of SecLists). Make sure the format remains one entry per line.

The script loads these dictionary files at startup.

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
