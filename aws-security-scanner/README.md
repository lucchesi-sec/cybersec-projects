# AWS Security Scanner

A simple Python tool that scans AWS resources for common security misconfigurations. The focus is on S3 buckets, which are frequently misconfigured and can lead to data breaches.

## Features

- Detects publicly accessible S3 buckets
- Checks if S3 bucket encryption is enabled
- Verifies if S3 bucket access logging is configured
- Checks for S3 bucket versioning status
- Checks for S3 MFA Delete status
- Checks for secure bucket policies (basic check)
- Generates a simple report with findings and remediation steps

## Requirements

- Python 3.7+
- AWS account with programmatic access (credentials configured via AWS CLI, environment variables, or IAM roles)
- Boto3, Colorama, and Tabulate Python libraries (see `requirements.txt`)

## Setup

1. Clone this repository
2. Set up your AWS credentials (using `aws configure` or environment variables)
3. Install required packages:
   ```
   pip install -r requirements.txt
   ```

## Usage

```bash
# Scan all S3 buckets in your account
python s3_scanner.py

# Generate a detailed report
python s3_scanner.py --report detailed

# Scan specific buckets
python s3_scanner.py --buckets bucket1,bucket2

# Save detailed report to a file
python s3_scanner.py --report detailed --output detailed_report.txt
```

## Security Best Practices Demonstrated

This script helps identify these common AWS misconfigurations:

1. **Public S3 Buckets**: S3 buckets should not be publicly accessible unless absolutely necessary.
2. **Missing Encryption**: S3 buckets should use server-side encryption at rest to protect sensitive data.
3. **Access Logging**: Critical buckets should have access logging enabled to track requests and identify potential security incidents.
4. **Bucket Versioning**: Enabling versioning helps protect against accidental data deletion or overwrites.
5. **MFA Delete**: For versioned buckets, MFA Delete adds an extra layer of security by requiring multi-factor authentication for permanently deleting object versions.
6. **Insecure Bucket Policies**: Bucket policies should follow the principle of least privilege and avoid overly permissive configurations.

## Project Structure

```
aws-security-scanner/
├── s3_scanner.py         # Main scanner script
├── requirements.txt      # Project dependencies
├── README.md             # Project documentation
└── examples/             # Example output reports
```

## Limitations

This is a basic scanner for educational purposes. For production environments, consider more comprehensive tools like AWS Config, Security Hub, or commercial security posture management solutions.

## Next Steps

Future enhancements could include:
- Scanning additional AWS resources (EC2, RDS, IAM, etc.)
- More sophisticated bucket policy analysis
- Integration with AWS Security Hub
- CloudFormation template scanning
- Automated remediation suggestions
