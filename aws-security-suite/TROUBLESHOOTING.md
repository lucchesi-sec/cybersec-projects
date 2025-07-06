# AWS Security Suite - Troubleshooting Guide

## Table of Contents
1. [Installation Issues](#installation-issues)
2. [Authentication Problems](#authentication-problems)
3. [Permission Errors](#permission-errors)
4. [Performance Issues](#performance-issues)
5. [Scanning Problems](#scanning-problems)
6. [Output and Formatting Issues](#output-and-formatting-issues)
7. [Common Error Messages](#common-error-messages)
8. [Debug Mode](#debug-mode)

## Installation Issues

### Python Version Compatibility
**Problem**: Installation fails with Python version errors
```
ERROR: Package requires Python >=3.8
```

**Solution**:
```bash
# Check Python version
python --version

# Use Python 3.8 or higher
python3 --version

# Install with specific Python version
python3.9 -m pip install -e .
```

### Dependency Conflicts
**Problem**: Conflicting package versions during installation
```
ERROR: Cannot install aws-security-suite because these packages have conflicting dependencies
```

**Solution**:
```bash
# Create a clean virtual environment
python -m venv aws-security-env
source aws-security-env/bin/activate  # Linux/Mac
# aws-security-env\Scripts\activate   # Windows

# Install in clean environment
pip install -e .
```

### Missing System Dependencies
**Problem**: Installation fails due to missing system libraries

**Solution**:
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install python3-dev build-essential

# CentOS/RHEL
sudo yum install python3-devel gcc

# macOS
xcode-select --install
```

## Authentication Problems

### AWS Credentials Not Found
**Problem**: 
```
NoCredentialsError: Unable to locate credentials
```

**Solutions**:
1. **Configure AWS CLI**:
   ```bash
   aws configure
   ```

2. **Set environment variables**:
   ```bash
   export AWS_ACCESS_KEY_ID=your_access_key
   export AWS_SECRET_ACCESS_KEY=your_secret_key
   export AWS_DEFAULT_REGION=us-east-1
   ```

3. **Use IAM roles** (recommended for EC2/Lambda):
   ```bash
   # No additional configuration needed if running on EC2 with IAM role
   aws-security-suite scan
   ```

### Assume Role Issues
**Problem**: Cannot assume specified role
```
AccessDenied: User is not authorized to perform: sts:AssumeRole
```

**Solution**:
1. **Verify role ARN**:
   ```bash
   aws sts get-caller-identity
   aws sts assume-role --role-arn arn:aws:iam::123456789012:role/SecurityAuditRole --role-session-name test
   ```

2. **Check trust policy** on target role:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Principal": {
           "AWS": "arn:aws:iam::YOUR_ACCOUNT:user/YOUR_USER"
         },
         "Action": "sts:AssumeRole"
       }
     ]
   }
   ```

### Session Token Expiration
**Problem**: Temporary credentials have expired
```
TokenRefreshError: Unable to refresh credentials
```

**Solution**:
```bash
# Refresh AWS SSO session
aws sso login --profile your-profile

# Or re-run aws configure for long-term credentials
aws configure
```

## Permission Errors

### Insufficient IAM Permissions
**Problem**: Access denied for specific AWS services
```
AccessDenied: User is not authorized to perform: ec2:DescribeInstances
```

**Solution**:
1. **Use the minimal permissions policy**:
   ```bash
   # Show required permissions for scanning
   aws-security-suite permissions

   # Show permissions for remediation
   aws-security-suite permissions --remediation
   ```

2. **Apply the provided IAM policy** to your user/role

3. **Test permissions**:
   ```bash
   # Test EC2 permissions
   aws ec2 describe-instances --max-items 1

   # Test S3 permissions
   aws s3api list-buckets
   ```

### Cross-Account Permission Issues
**Problem**: Cannot access resources in other accounts
```
AccessDenied: Cross-account access denied
```

**Solution**:
1. **Verify cross-account role permissions**
2. **Check resource-based policies** (S3 bucket policies, etc.)
3. **Use organization-wide scanning** if available:
   ```bash
   aws-security-suite scan --organization-role OrganizationAccountAccessRole
   ```

## Performance Issues

### Slow Scanning Performance
**Problem**: Scans take very long to complete

**Solutions**:
1. **Increase concurrency**:
   ```bash
   aws-security-suite scan --max-concurrent-regions 5 --max-concurrent-services 8
   ```

2. **Scan specific regions**:
   ```bash
   aws-security-suite scan --regions us-east-1,us-west-2
   ```

3. **Scan specific services**:
   ```bash
   aws-security-suite scan --services ec2,s3
   ```

4. **Use async scanning** for large environments:
   ```bash
   aws-security-suite scan --async-mode
   ```

### Rate Limiting Issues
**Problem**: AWS API rate limits being hit
```
Throttling: Rate exceeded
```

**Solution**:
```bash
# Reduce API call rate
aws-security-suite scan --rate-limit 5  # 5 calls per second

# Add delays between operations
aws-security-suite scan --delay 100  # 100ms delay
```

### Memory Usage Problems
**Problem**: High memory consumption during scanning

**Solution**:
```bash
# Process regions sequentially instead of concurrently
aws-security-suite scan --sequential-regions

# Reduce batch sizes
aws-security-suite scan --batch-size 50

# Scan one service at a time
for service in ec2 s3 rds lambda; do
  aws-security-suite scan --services $service
done
```

## Scanning Problems

### No Resources Found
**Problem**: Scanner reports no resources but you know they exist

**Troubleshooting**:
1. **Check region**:
   ```bash
   # List all regions where you have resources
   aws ec2 describe-regions --query 'Regions[].RegionName'
   
   # Scan specific region
   aws-security-suite scan --regions us-west-2
   ```

2. **Verify service availability**:
   ```bash
   # Check if service is available in region
   aws ec2 describe-instances --region us-west-2 --max-items 1
   ```

3. **Check resource filters**:
   ```bash
   # Scan without filters
   aws-security-suite scan --no-filters
   ```

### Incomplete Scan Results
**Problem**: Some resources missing from scan results

**Solution**:
1. **Enable debug logging**:
   ```bash
   aws-security-suite scan --debug --log-level DEBUG
   ```

2. **Check for errors in specific services**:
   ```bash
   # Scan each service individually
   aws-security-suite scan --services ec2 --debug
   ```

3. **Verify resource tags/filters**:
   ```bash
   # Scan with verbose output
   aws-security-suite scan --verbose
   ```

### Plugin Loading Errors
**Problem**: Specific scanners fail to load
```
ImportError: Cannot import plugin module
```

**Solution**:
1. **Reinstall the package**:
   ```bash
   pip uninstall aws-security-suite
   pip install -e .
   ```

2. **Check plugin directory**:
   ```bash
   ls -la plugins/
   python -c "import plugins.ec2.scanner; print('EC2 plugin OK')"
   ```

## Output and Formatting Issues

### JSON Parsing Errors
**Problem**: Output cannot be parsed as JSON
```
JSONDecodeError: Expecting value
```

**Solution**:
1. **Use proper JSON format**:
   ```bash
   aws-security-suite scan --format json > findings.json
   # Validate JSON
   python -m json.tool findings.json
   ```

2. **Check for mixed output**:
   ```bash
   # Redirect stderr to separate file
   aws-security-suite scan --format json 2>errors.log > findings.json
   ```

### Character Encoding Issues
**Problem**: Special characters cause display problems

**Solution**:
```bash
# Set UTF-8 encoding
export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8

# Use ASCII-only output
aws-security-suite scan --ascii-only
```

## Common Error Messages

### "ModuleNotFoundError: No module named 'boto3'"
**Solution**:
```bash
pip install boto3 botocore
# Or reinstall the package
pip install -e .
```

### "SSL Certificate Verify Failed"
**Solution**:
```bash
# Update certificates
pip install --upgrade certifi

# Or temporarily disable SSL verification (not recommended for production)
export PYTHONHTTPSVERIFY=0
```

### "Connection Timeout"
**Solution**:
```bash
# Increase timeout values
aws-security-suite scan --timeout 300

# Check network connectivity
aws ec2 describe-regions --region us-east-1
```

### "Service Unavailable in Region"
**Solution**:
```bash
# Check service availability
aws ec2 describe-availability-zones --region us-east-1

# Skip unavailable regions
aws-security-suite scan --skip-unavailable-regions
```

## Debug Mode

### Enable Debug Logging
```bash
# Basic debug mode
aws-security-suite scan --debug

# Verbose debug with specific log level
aws-security-suite scan --log-level DEBUG --log-file debug.log

# Debug specific plugin
aws-security-suite scan --services ec2 --debug --verbose
```

### Debug Output Analysis
```bash
# Search for specific errors
grep -i "error" debug.log

# Find rate limiting issues
grep -i "throttl" debug.log

# Check API call patterns
grep -i "calling" debug.log | head -20
```

### Collecting Debug Information
When reporting issues, include:

1. **System information**:
   ```bash
   python --version
   pip list | grep -E "(boto|aws)"
   aws --version
   ```

2. **AWS environment**:
   ```bash
   aws sts get-caller-identity
   aws configure list
   ```

3. **Error reproduction**:
   ```bash
   aws-security-suite scan --debug --services ec2 --regions us-east-1 2>&1 | tee debug-output.log
   ```

## Getting Help

### Check Documentation
- Review the [USER_GUIDE.md](./USER_GUIDE.md) for usage examples
- Check [README.md](./README.md) for basic setup

### Enable Verbose Output
```bash
aws-security-suite scan --verbose --debug
```

### Report Issues
When reporting bugs, include:
- Full error message and stack trace
- System information (OS, Python version)
- AWS region and services being scanned
- Debug log output (with sensitive information removed)

### Performance Optimization
For large environments:
```bash
# Optimized scanning command
aws-security-suite scan \
  --max-concurrent-regions 3 \
  --max-concurrent-services 4 \
  --rate-limit 10 \
  --timeout 300 \
  --batch-size 100
```