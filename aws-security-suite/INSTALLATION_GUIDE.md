# AWS Security Suite - Installation Guide

## Table of Contents
1. [System Requirements](#system-requirements)
2. [Quick Installation](#quick-installation)
3. [Development Installation](#development-installation)
4. [AWS Configuration](#aws-configuration)
5. [Verification](#verification)
6. [Docker Installation](#docker-installation)
7. [Enterprise Deployment](#enterprise-deployment)
8. [Troubleshooting Installation](#troubleshooting-installation)

## System Requirements

### Supported Operating Systems
- **Linux**: Ubuntu 18.04+, CentOS 7+, Amazon Linux 2
- **macOS**: 10.14+ (Mojave and later)
- **Windows**: Windows 10, Windows Server 2016+

### Python Requirements
- **Python**: 3.8 or higher (3.9+ recommended)
- **pip**: 21.0 or higher
- **virtualenv**: Recommended for isolation

### System Dependencies
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install python3 python3-pip python3-venv git

# CentOS/RHEL
sudo yum install python3 python3-pip git

# macOS (with Homebrew)
brew install python3 git

# Windows (with Chocolatey)
choco install python3 git
```

### Hardware Requirements
- **Memory**: 512MB minimum, 2GB recommended for large environments
- **Storage**: 100MB for installation, additional space for logs and reports
- **Network**: Internet access for AWS API calls

## Quick Installation

### 1. Clone Repository
```bash
git clone https://github.com/your-org/cybersec-projects.git
cd cybersec-projects/aws-security-suite
```

### 2. Install Package
```bash
# Install in current environment
pip install -e .

# Or install with all optional dependencies
pip install -e ".[dev,test]"
```

### 3. Verify Installation
```bash
aws-security-suite --version
aws-security-suite list-services
```

### 4. Basic Configuration
```bash
# Configure AWS credentials
aws configure

# Test basic functionality
aws-security-suite scan --services s3 --regions us-east-1 --dry-run
```

## Development Installation

### 1. Create Virtual Environment
```bash
# Create virtual environment
python3 -m venv aws-security-env

# Activate virtual environment
source aws-security-env/bin/activate  # Linux/macOS
# aws-security-env\Scripts\activate   # Windows
```

### 2. Install Development Dependencies
```bash
# Install package in development mode
pip install -e ".[dev,test]"

# Install pre-commit hooks
pre-commit install
```

### 3. Verify Development Setup
```bash
# Run tests
pytest

# Run linting
black . --check
isort . --check
flake8 .

# Type checking
mypy .
```

### 4. Development Workflow
```bash
# Before committing changes
make test           # Run full test suite
make lint          # Check code formatting
make type-check    # Verify type annotations
make security      # Security linting with bandit
```

## AWS Configuration

### Method 1: AWS CLI Configuration
```bash
# Interactive configuration
aws configure

# Set specific profile
aws configure --profile security-scanning
export AWS_PROFILE=security-scanning
```

### Method 2: Environment Variables
```bash
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_DEFAULT_REGION=us-east-1
export AWS_SESSION_TOKEN=your_session_token  # If using temporary credentials
```

### Method 3: IAM Roles (Recommended)
```bash
# For EC2 instances - no configuration needed
# Role should be attached to EC2 instance

# For Lambda functions - use execution role
# For ECS/Fargate - use task role
```

### Method 4: AWS SSO
```bash
# Configure SSO
aws configure sso

# Login to SSO
aws sso login --profile your-sso-profile

# Use SSO profile
export AWS_PROFILE=your-sso-profile
```

### Required IAM Permissions

#### Minimal Read-Only Policy
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:Describe*",
                "s3:GetBucket*",
                "s3:ListAllMyBuckets",
                "rds:Describe*",
                "lambda:Get*",
                "lambda:List*",
                "iam:Get*",
                "iam:List*",
                "cloudtrail:Describe*",
                "cloudwatch:Describe*",
                "config:Describe*",
                "logs:Describe*"
            ],
            "Resource": "*"
        }
    ]
}
```

#### Full Remediation Policy
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:*",
                "s3:*",
                "rds:*",
                "lambda:*",
                "iam:*",
                "cloudtrail:*",
                "cloudwatch:*",
                "config:*",
                "logs:*"
            ],
            "Resource": "*"
        }
    ]
}
```

## Verification

### 1. Basic Functionality Test
```bash
# Test AWS connectivity
aws-security-suite test-connection

# List available scanners
aws-security-suite list-services

# Show required permissions
aws-security-suite permissions
```

### 2. Run Sample Scan
```bash
# Quick scan of S3 buckets
aws-security-suite scan --services s3 --regions us-east-1

# Comprehensive test scan
aws-security-suite scan --services s3,ec2 --regions us-east-1,us-west-2 --format json
```

### 3. Verify Async Capabilities
```bash
# Test async scanning performance
aws-security-suite scan --services s3 --async-mode --benchmark

# Test concurrent region scanning
aws-security-suite scan --services ec2 --regions us-east-1,us-west-2,eu-west-1 --max-concurrent-regions 3
```

### 4. Test Remediation
```bash
# Dry-run remediation test
aws-security-suite remediate --dry-run --services s3

# Test specific finding remediation
aws-security-suite remediate --finding-type S3_PUBLIC_ACCESS_ENABLED --dry-run
```

## Docker Installation

### 1. Build Docker Image
```bash
# Build from source
docker build -t aws-security-suite .

# Or use pre-built image
docker pull your-registry/aws-security-suite:latest
```

### 2. Run with Docker
```bash
# Using AWS credentials from host
docker run --rm \
  -e AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY \
  -e AWS_DEFAULT_REGION \
  aws-security-suite scan --services s3

# Using AWS credentials file
docker run --rm \
  -v ~/.aws:/root/.aws:ro \
  aws-security-suite scan --services s3

# With custom output directory
docker run --rm \
  -v ~/.aws:/root/.aws:ro \
  -v $(pwd)/reports:/app/reports \
  aws-security-suite scan --format json > reports/findings.json
```

### 3. Docker Compose
```yaml
# docker-compose.yml
version: '3.8'
services:
  aws-security-suite:
    build: .
    environment:
      - AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}
      - AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}
      - AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION}
    volumes:
      - ./reports:/app/reports
    command: scan --format json --output reports/findings.json
```

```bash
# Run with Docker Compose
docker-compose up
```

## Enterprise Deployment

### 1. CI/CD Integration

#### GitHub Actions
```yaml
# .github/workflows/security-scan.yml
name: AWS Security Scan
on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM
  workflow_dispatch:

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.9'
          
      - name: Install AWS Security Suite
        run: |
          cd aws-security-suite
          pip install -e .
          
      - name: Run Security Scan
        run: |
          aws-security-suite scan \
            --format json \
            --output security-findings.json \
            --severity critical,high
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          
      - name: Upload Results
        uses: actions/upload-artifact@v3
        with:
          name: security-findings
          path: security-findings.json
```

#### Jenkins Pipeline
```groovy
pipeline {
    agent any
    
    triggers {
        cron('H 2 * * *')  // Daily at 2 AM
    }
    
    stages {
        stage('Setup') {
            steps {
                sh 'pip install -e aws-security-suite/'
            }
        }
        
        stage('Security Scan') {
            steps {
                withCredentials([aws(credentialsId: 'aws-security-scan')]) {
                    sh '''
                        aws-security-suite scan \
                            --format json \
                            --output security-findings.json \
                            --severity critical,high
                    '''
                }
            }
        }
        
        stage('Archive Results') {
            steps {
                archiveArtifacts artifacts: 'security-findings.json'
                
                script {
                    def findings = readJSON file: 'security-findings.json'
                    def criticalCount = findings.findings.findAll { it.severity == 'CRITICAL' }.size()
                    
                    if (criticalCount > 0) {
                        currentBuild.result = 'UNSTABLE'
                        echo "Found ${criticalCount} critical security findings"
                    }
                }
            }
        }
    }
}
```

### 2. Kubernetes Deployment
```yaml
# kubernetes/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: aws-security-suite
spec:
  replicas: 1
  selector:
    matchLabels:
      app: aws-security-suite
  template:
    metadata:
      labels:
        app: aws-security-suite
    spec:
      serviceAccountName: aws-security-suite
      containers:
      - name: scanner
        image: aws-security-suite:latest
        env:
        - name: AWS_REGION
          value: "us-east-1"
        command:
        - /bin/sh
        - -c
        - |
          while true; do
            aws-security-suite scan --format json > /tmp/findings.json
            sleep 3600  # Scan every hour
          done
        volumeMounts:
        - name: findings
          mountPath: /tmp
      volumes:
      - name: findings
        emptyDir: {}

---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: aws-security-suite
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::ACCOUNT:role/aws-security-suite-role
```

### 3. Monitoring and Alerting
```bash
# CloudWatch integration
aws logs create-log-group --log-group-name /aws/security-suite/findings

# Send findings to CloudWatch
aws-security-suite scan --format json | \
aws logs put-log-events \
  --log-group-name /aws/security-suite/findings \
  --log-stream-name $(date +%Y%m%d) \
  --log-events timestamp=$(date +%s000),message="$(cat)"
```

## Troubleshooting Installation

### Common Issues

#### Permission Denied Errors
```bash
# Fix pip permissions
pip install --user -e .

# Or use virtual environment
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

#### SSL Certificate Errors
```bash
# Update certificates
pip install --upgrade certifi

# Or disable SSL verification (not recommended)
pip install --trusted-host pypi.org --trusted-host pypi.python.org -e .
```

#### Import Errors
```bash
# Reinstall dependencies
pip install --force-reinstall -e .

# Check Python path
python -c "import sys; print(sys.path)"
```

### Platform-Specific Issues

#### macOS
```bash
# Install Xcode command line tools
xcode-select --install

# Update PATH for Python 3
echo 'export PATH="/usr/local/opt/python@3.9/bin:$PATH"' >> ~/.zshrc
```

#### Windows
```powershell
# Install with PowerShell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
pip install -e .

# Fix long path issues
git config --system core.longpaths true
```

#### Amazon Linux/EC2
```bash
# Install Python 3.8+ on Amazon Linux
sudo amazon-linux-extras enable python3.8
sudo yum install python3.8 python3.8-pip

# Use Python 3.8
python3.8 -m pip install -e .
```

### Getting Help

#### Check Installation
```bash
# Verify installation
python -c "import aws_security_suite; print('Installation successful')"

# Check dependencies
pip check

# Show package information
pip show aws-security-suite
```

#### Debug Information
```bash
# System information
python --version
pip --version
aws --version

# Package versions
pip list | grep -E "(boto|aws)"

# Environment variables
env | grep AWS
```

For additional troubleshooting, see [TROUBLESHOOTING.md](./TROUBLESHOOTING.md).