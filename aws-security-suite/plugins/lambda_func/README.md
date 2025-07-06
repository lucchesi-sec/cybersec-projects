# Lambda Security Scanner Plugin

## Overview

The Lambda Security Scanner Plugin provides comprehensive security analysis for AWS Lambda functions, layers, and related resources. It performs security assessments across four core areas: function configuration, access control, runtime security, and monitoring.

## Security Checks

### 1. Function Configuration Security

#### Runtime Environment
- **LAMBDA_DEPRECATED_RUNTIME**: Detects functions using deprecated runtime versions
- **LAMBDA_EXCESSIVE_TIMEOUT**: Flags functions with timeouts > 10 minutes
- **LAMBDA_MINIMAL_TIMEOUT**: Identifies functions with very low timeouts < 3 seconds
- **LAMBDA_LOW_MEMORY_ALLOCATION**: Functions with memory < 512MB
- **LAMBDA_RESERVED_CONCURRENCY_ZERO**: Functions with zero reserved concurrency

#### Code and Deployment
- **LAMBDA_LARGE_DEPLOYMENT_PACKAGE**: Deployment packages > 50MB
- **LAMBDA_NO_LAYERS**: Functions not using any layers
- **LAMBDA_CODE_IN_S3**: Functions with code stored in S3 (informational)

### 2. Access Control Security

#### IAM Execution Roles
- **LAMBDA_NO_EXECUTION_ROLE**: Functions without execution roles
- **LAMBDA_OVERPRIVILEGED_ROLE**: Functions using overly permissive AWS managed policies
- **LAMBDA_INLINE_POLICIES**: Functions with inline policies (governance concern)

#### Resource-Based Policies
- **LAMBDA_FUNCTION_PUBLIC_ACCESS**: Functions allowing public access
- **LAMBDA_FUNCTION_WILDCARD_ACTIONS**: Policies using wildcard actions

#### Layer Security
- **LAMBDA_LAYER_PUBLIC_ACCESS**: Layers allowing public access

### 3. Runtime Security

#### Environment Variables
- **LAMBDA_SENSITIVE_ENV_VARS**: Detection of potentially sensitive data in environment variables
- **LAMBDA_ENV_VARS_NOT_ENCRYPTED**: Environment variables not encrypted with KMS

#### VPC Configuration
- **LAMBDA_NOT_IN_VPC**: Functions not configured for VPC (informational)
- **LAMBDA_VPC_NO_SUBNETS**: VPC-enabled functions without subnets
- **LAMBDA_VPC_NO_SECURITY_GROUPS**: VPC-enabled functions without security groups
- **LAMBDA_VPC_SINGLE_AZ**: Functions only in single availability zone

### 4. Monitoring and Observability

#### Error Handling
- **LAMBDA_NO_DLQ**: Functions without dead letter queues
- **LAMBDA_ESM_NO_FAILURE_DESTINATION**: Event source mappings without failure destinations

#### Observability
- **LAMBDA_XRAY_TRACING_DISABLED**: Functions without X-Ray tracing enabled

#### Event Source Mappings
- **LAMBDA_ESM_ORPHANED**: Event source mappings referencing missing functions
- **LAMBDA_ESM_INEFFICIENT_BATCH_SIZE**: Kinesis mappings with inefficient batch sizes

## Required AWS Permissions

The plugin requires the following IAM permissions:

### Lambda Core Permissions
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "lambda:ListFunctions",
                "lambda:GetFunction",
                "lambda:GetFunctionConfiguration",
                "lambda:GetPolicy",
                "lambda:ListVersionsByFunction",
                "lambda:ListAliases",
                "lambda:ListLayers",
                "lambda:ListLayerVersions",
                "lambda:GetLayerVersion",
                "lambda:GetLayerVersionPolicy",
                "lambda:ListEventSourceMappings",
                "lambda:GetEventSourceMapping"
            ],
            "Resource": "*"
        }
    ]
}
```

### Supporting Service Permissions
```json
{
    "Effect": "Allow",
    "Action": [
        "iam:GetRole",
        "iam:ListAttachedRolePolicies",
        "iam:ListRolePolicies",
        "iam:GetRolePolicy",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "ec2:DescribeVpcs",
        "ec2:DescribeSubnets",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeRegions",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams",
        "cloudwatch:GetMetricStatistics",
        "cloudwatch:ListMetrics",
        "xray:GetTracingSummaries",
        "xray:BatchGetTraces"
    ],
    "Resource": "*"
}
```

## Remediation Support

The plugin supports automated remediation for the following findings:

- `LAMBDA_DEPRECATED_RUNTIME`: Update to supported runtime version
- `LAMBDA_SENSITIVE_ENV_VARS`: Migrate to AWS Systems Manager Parameter Store or Secrets Manager
- `LAMBDA_ENV_VARS_NOT_ENCRYPTED`: Enable KMS encryption for environment variables
- `LAMBDA_NO_DLQ`: Configure dead letter queue
- `LAMBDA_VPC_NO_SUBNETS`: Configure appropriate VPC subnets
- `LAMBDA_NO_EXECUTION_ROLE`: Create and assign execution role
- `LAMBDA_OVERPRIVILEGED_ROLE`: Create least-privilege custom policies
- `LAMBDA_LAYER_PUBLIC_ACCESS`: Restrict layer access to specific accounts
- `LAMBDA_FUNCTION_PUBLIC_ACCESS`: Remove public access from function policies
- `LAMBDA_FUNCTION_WILDCARD_ACTIONS`: Replace wildcards with specific actions
- `LAMBDA_ESM_ORPHANED`: Remove orphaned event source mappings
- `LAMBDA_XRAY_TRACING_DISABLED`: Enable X-Ray tracing

## Usage

### Command Line Interface

```bash
# Scan all Lambda functions
aws-security-suite scan --services lambda

# Scan Lambda functions in specific regions
aws-security-suite scan --services lambda --regions us-east-1,us-west-2

# Filter by severity
aws-security-suite scan --services lambda --severity critical,high
```

### Programmatic Usage

```python
from core.audit_context import AuditContext
from plugins.lambda_func.scanner import scan_lambda

# Create audit context
context = AuditContext(
    profile_name="default",
    regions=["us-east-1"],
    services=["lambda"]
)

# Run Lambda security scan
findings = await scan_lambda(context)

# Process findings
for finding in findings:
    print(f"{finding.severity}: {finding.check_title}")
    print(f"Resource: {finding.resource_name}")
    print(f"Description: {finding.description}")
    print(f"Recommendation: {finding.recommendation}")
```

## Security Best Practices

### Function Configuration
1. **Use supported runtimes**: Always use actively supported runtime versions
2. **Optimize timeouts**: Set appropriate timeouts based on function requirements
3. **Right-size memory**: Allocate sufficient memory for optimal performance
4. **Use layers**: Leverage layers for shared code and dependencies

### Access Control
1. **Least privilege**: Apply minimal required permissions to execution roles
2. **Avoid AWS managed policies**: Use custom policies with specific permissions
3. **Restrict function access**: Never allow public access unless absolutely necessary
4. **Secure layers**: Restrict layer access to specific AWS accounts

### Runtime Security
1. **Protect sensitive data**: Use AWS Systems Manager Parameter Store or Secrets Manager
2. **Encrypt environment variables**: Enable KMS encryption for all environment variables
3. **VPC configuration**: Use VPC when accessing private resources
4. **Multi-AZ deployment**: Configure subnets across multiple availability zones

### Monitoring and Observability
1. **Dead letter queues**: Configure DLQs for error handling
2. **X-Ray tracing**: Enable tracing for debugging and performance analysis
3. **CloudWatch Logs**: Ensure proper log retention and monitoring
4. **Failure destinations**: Configure failure destinations for event source mappings

## Integration with AWS Security Services

The Lambda plugin integrates well with other AWS security services:

- **AWS Config**: Use Config rules to continuously monitor Lambda configuration
- **AWS CloudTrail**: Monitor Lambda API calls and configuration changes
- **AWS GuardDuty**: Detect malicious activity in Lambda functions
- **AWS Security Hub**: Centralize security findings from multiple sources
- **AWS Systems Manager**: Manage sensitive configuration data securely

## Performance Considerations

- The plugin uses pagination to handle accounts with large numbers of Lambda functions
- Regional scanning is performed in parallel for better performance
- IAM role analysis is cached to avoid redundant API calls
- Failed function configuration requests don't stop the overall scan

## Troubleshooting

### Common Issues

1. **Permission Denied Errors**: Ensure all required IAM permissions are granted
2. **Region Access Issues**: Verify that Lambda service is available in target regions
3. **Large Account Timeouts**: Use region filtering to reduce scan scope
4. **Rate Limiting**: The plugin respects AWS API rate limits automatically

### Debug Logging

Enable verbose logging to troubleshoot issues:

```bash
aws-security-suite scan --services lambda --verbose
```

## Contributing

To extend the Lambda plugin:

1. Add new security checks to the appropriate analysis functions
2. Update the `register()` function with new remediation mappings
3. Add corresponding test cases
4. Update this documentation

## Security Considerations

- The plugin never logs sensitive data from environment variables
- All API calls use least-privilege IAM permissions
- Function code is analyzed through metadata only (no code downloading)
- Temporary credentials are supported for cross-account scanning