#!/usr/bin/env python3
"""
AWS S3 Security Scanner
A basic tool to detect common security misconfigurations in AWS S3 buckets.
"""

import boto3
import argparse
import sys
from datetime import datetime
from colorama import init, Fore, Style
from tabulate import tabulate
from botocore.exceptions import ClientError

# Initialize colorama for colored terminal output
init()

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Scan AWS S3 buckets for security misconfigurations')
    parser.add_argument('--buckets', help='Comma-separated list of bucket names to scan (default: all buckets)')
    parser.add_argument('--report', choices=['basic', 'detailed'], default='basic',
                      help='Report format (default: basic)')
    parser.add_argument('--output', help='Output file for the report (default: console only)')
    return parser.parse_args()

def get_s3_client():
    """Create and return an S3 client using default credentials."""
    try:
        return boto3.client('s3')
    except Exception as e:
        print(f"{Fore.RED}Error connecting to AWS: {str(e)}{Style.RESET_ALL}")
        print("Make sure your AWS credentials are configured correctly.")
        sys.exit(1)

def get_all_buckets(s3_client):
    """Get list of all S3 buckets in the account."""
    try:
        response = s3_client.list_buckets()
        return [bucket['Name'] for bucket in response['Buckets']]
    except Exception as e:
        print(f"{Fore.RED}Error retrieving S3 buckets: {str(e)}{Style.RESET_ALL}")
        return []

def check_bucket_public_access(s3_client, bucket_name):
    """Check if a bucket has any form of public access enabled."""
    try:
        # Check for public access block settings
        try:
            public_access_block = s3_client.get_public_access_block(Bucket=bucket_name)
            block_config = public_access_block['PublicAccessBlockConfiguration']

            # If all four settings are True, the bucket is protected from public access
            if (block_config.get('BlockPublicAcls', False) and
                block_config.get('IgnorePublicAcls', False) and
                block_config.get('BlockPublicPolicy', False) and
                block_config.get('RestrictPublicBuckets', False)):
                return False
        except ClientError:
            # If public access block is not configured, continue with other checks
            pass

        # Check bucket ACL
        acl = s3_client.get_bucket_acl(Bucket=bucket_name)
        for grant in acl['Grants']:
            grantee = grant.get('Grantee', {})
            if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                return True

        # Check bucket policy
        try:
            policy = s3_client.get_bucket_policy(Bucket=bucket_name)
            # Simple check for "Principal": "*" in the policy
            # This is a basic check and doesn't account for complex conditions
            if '"Principal": "*"' in policy['Policy'] or '"Principal":"*"' in policy['Policy']:
                return True
        except ClientError:
            # If no bucket policy exists, skip this check
            pass

        return False
    except Exception as e:
        print(f"{Fore.YELLOW}Warning: Could not check public access for {bucket_name}: {str(e)}{Style.RESET_ALL}")
        return "Unknown"

def check_bucket_encryption(s3_client, bucket_name):
    """Check if default encryption is enabled on the bucket."""
    try:
        encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
        if 'ServerSideEncryptionConfiguration' in encryption:
            return True
        return False
    except ClientError as e:
        if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
            return False
        print(f"{Fore.YELLOW}Warning: Could not check encryption for {bucket_name}: {str(e)}{Style.RESET_ALL}")
        return "Unknown"

def check_bucket_logging(s3_client, bucket_name):
    """Check if logging is enabled on the bucket."""
    try:
        logging = s3_client.get_bucket_logging(Bucket=bucket_name)
        if 'LoggingEnabled' in logging:
            return True
        return False
    except Exception as e:
        print(f"{Fore.YELLOW}Warning: Could not check logging for {bucket_name}: {str(e)}{Style.RESET_ALL}")
        return "Unknown"

def scan_bucket(s3_client, bucket_name):
    """Scan a single bucket for security issues."""
    print(f"Scanning bucket: {Fore.CYAN}{bucket_name}{Style.RESET_ALL}...")

    results = {
        'name': bucket_name,
        'public_access': check_bucket_public_access(s3_client, bucket_name),
        'encryption': check_bucket_encryption(s3_client, bucket_name),
        'logging': check_bucket_logging(s3_client, bucket_name)
    }

    return results

def format_check_result(result):
    """Format a check result with appropriate color."""
    if result == True:
        return f"{Fore.GREEN}✓{Style.RESET_ALL}"
    elif result == False:
        return f"{Fore.RED}✗{Style.RESET_ALL}"
    else:
        return f"{Fore.YELLOW}?{Style.RESET_ALL}"

def print_report(scan_results, report_type='basic'):
    """Print a report of the scan results."""
    if not scan_results:
        print(f"{Fore.YELLOW}No S3 buckets were scanned.{Style.RESET_ALL}")
        return

    print(f"\n{Fore.CYAN}=== AWS S3 Security Scan Results ==={Style.RESET_ALL}")
    print(f"Scan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Scanned {len(scan_results)} bucket(s)\n")

    # Convert to a format suitable for tabulate
    table_data = []
    for result in scan_results:
        is_secure = True

        # Public access check (should be False for secure)
        if result['public_access'] != False:
            is_secure = False
            public_status = f"{Fore.RED}Public{Style.RESET_ALL}" if result['public_access'] == True else f"{Fore.YELLOW}Unknown{Style.RESET_ALL}"
        else:
            public_status = f"{Fore.GREEN}Private{Style.RESET_ALL}"

        # Encryption check (should be True for secure)
        encryption_status = format_check_result(result['encryption'])
        if result['encryption'] != True:
            is_secure = False

        # Logging check (should be True for secure)
        logging_status = format_check_result(result['logging'])
        if result['logging'] != True:
            is_secure = False

        # Overall status
        overall = f"{Fore.GREEN}Secure{Style.RESET_ALL}" if is_secure else f"{Fore.RED}Insecure{Style.RESET_ALL}"

        table_data.append([
            result['name'],
            public_status,
            encryption_status,
            logging_status,
            overall
        ])

    # Print table
    headers = ["Bucket Name", "Public Access", "Encryption", "Logging", "Overall"]
    print(tabulate(table_data, headers=headers, tablefmt="grid"))

    # Print detailed recommendations for insecure buckets
    if report_type == 'detailed':
        print(f"\n{Fore.CYAN}=== Detailed Recommendations ==={Style.RESET_ALL}")
        for result in scan_results:
            issues = []

            if result['public_access'] == True:
                issues.append("Bucket has public access enabled.")
            elif result['public_access'] == "Unknown":
                issues.append("Could not determine public access status.")

            if result['encryption'] == False:
                issues.append("Default encryption is not enabled.")
            elif result['encryption'] == "Unknown":
                issues.append("Could not determine encryption status.")

            if result['logging'] == False:
                issues.append("Access logging is not enabled.")
            elif result['logging'] == "Unknown":
                issues.append("Could not determine logging status.")

            if issues:
                print(f"\n{Fore.YELLOW}Issues for {result['name']}:{Style.RESET_ALL}")
                for i, issue in enumerate(issues, 1):
                    print(f"  {i}. {issue}")

                # Print recommendations
                print(f"{Fore.GREEN}Recommendations:{Style.RESET_ALL}")
                if result['public_access'] == True:
                    print("  • Enable S3 Block Public Access at the bucket level")
                    print("  • Review and update bucket ACLs and policies")
                if result['encryption'] == False:
                    print("  • Enable default encryption with SSE-S3 or SSE-KMS")
                if result['logging'] == False:
                    print("  • Enable access logging to track requests to the bucket")

def save_report_to_file(scan_results, filename):
    """Save the report to a file."""
    try:
        with open(filename, 'w') as f:
            f.write("AWS S3 Security Scan Results\n")
            f.write("==========================\n")
            f.write(f"Scan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Scanned {len(scan_results)} bucket(s)\n\n")

            # Write results in a simple text format
            for result in scan_results:
                f.write(f"Bucket: {result['name']}\n")
                f.write(f"  Public Access: {'Yes' if result['public_access'] == True else 'No' if result['public_access'] == False else 'Unknown'}\n")
                f.write(f"  Encryption: {'Enabled' if result['encryption'] == True else 'Disabled' if result['encryption'] == False else 'Unknown'}\n")
                f.write(f"  Logging: {'Enabled' if result['logging'] == True else 'Disabled' if result['logging'] == False else 'Unknown'}\n")
                f.write("\n")

        print(f"{Fore.GREEN}Report saved to {filename}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Error saving report: {str(e)}{Style.RESET_ALL}")

def main():
    """Main function."""
    args = parse_arguments()

    print(f"{Fore.CYAN}AWS S3 Security Scanner{Style.RESET_ALL}")
    print("Checking for common security misconfigurations in S3 buckets...")

    s3_client = get_s3_client()

    # Determine which buckets to scan
    if args.buckets:
        bucket_names = [b.strip() for b in args.buckets.split(',')]
        print(f"Will scan specified buckets: {', '.join(bucket_names)}")
    else:
        bucket_names = get_all_buckets(s3_client)
        print(f"Found {len(bucket_names)} buckets to scan")

    # Scan each bucket
    scan_results = []
    for bucket_name in bucket_names:
        result = scan_bucket(s3_client, bucket_name)
        scan_results.append(result)

    # Display results
    print_report(scan_results, args.report)

    # Save to file if requested
    if args.output:
        save_report_to_file(scan_results, args.output)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Scan cancelled by user.{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)
