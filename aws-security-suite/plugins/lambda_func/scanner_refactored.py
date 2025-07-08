"""
Lambda Security Scanner Plugin
Comprehensive security analysis for AWS Lambda functions, layers, and related resources.
Refactored version with modular architecture.
"""

import asyncio
import logging
from typing import List

from core.finding import Finding
from core.audit_context import AuditContext
from core.plugin import ScannerPlugin

# Import utility functions
from .utils.lambda_utils import get_available_regions

# Import analyzers
from .analyzers.function_analyzer import (
    scan_lambda_functions,
    analyze_function_configuration,
    analyze_function_code_security,
    analyze_function_execution_role
)
from .analyzers.environment_analyzer import (
    check_environment_variables,
    check_dead_letter_queue
)
from .analyzers.vpc_analyzer import analyze_function_vpc_config
from .analyzers.layer_analyzer import scan_lambda_layers
from .analyzers.event_source_analyzer import scan_event_source_mappings
from .analyzers.permission_analyzer import scan_function_permissions
from .analyzers.monitoring_analyzer import check_function_monitoring

logger = logging.getLogger(__name__)


async def scan_lambda(context: AuditContext) -> List[Finding]:
    """Main Lambda scanning function - orchestrates all analyzers."""
    findings = []
    
    try:
        # Get all regions for Lambda scanning
        regions = await get_available_regions(context)
        
        # Process each region
        for region in regions:
            logger.info(f"Scanning Lambda resources in region: {region}")
            region_findings = await _scan_region(context, region)
            findings.extend(region_findings)
            
    except Exception as e:
        logger.error(f"Lambda scan failed: {e}")
        
    return findings


async def _scan_region(context: AuditContext, region: str) -> List[Finding]:
    """Scan Lambda resources in a specific region."""
    findings = []
    
    try:
        # Get region-specific Lambda client
        lambda_client = context.get_client('lambda', region_name=region)
        
        # Run all analyzers in parallel for better performance
        tasks = [
            # Scan Lambda functions (includes config, code, role analysis)
            _scan_functions_with_details(lambda_client, context, region),
            
            # Scan Lambda layers
            scan_lambda_layers(lambda_client, context, region),
            
            # Scan event source mappings
            scan_event_source_mappings(lambda_client, context, region),
            
            # Scan function permissions
            scan_function_permissions(lambda_client, context, region)
        ]
        
        # Execute all tasks concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Analyzer failed in region {region}: {result}")
            else:
                findings.extend(result)
                
    except Exception as e:
        logger.error(f"Failed to scan region {region}: {e}")
    
    return findings


async def _scan_functions_with_details(lambda_client, context: AuditContext, region: str) -> List[Finding]:
    """Enhanced function scanning that includes all sub-analyzers."""
    findings = []
    
    try:
        paginator = lambda_client.get_paginator('list_functions')
        
        for page in paginator.paginate():
            for function in page['Functions']:
                function_name = function['FunctionName']
                
                try:
                    # Get detailed function configuration
                    function_config = lambda_client.get_function_configuration(
                        FunctionName=function_name
                    )
                    
                    # Run all function-specific analyzers
                    analyzer_tasks = [
                        # Core function analysis
                        analyze_function_configuration(function_config, context, region),
                        analyze_function_code_security(lambda_client, function_name, function_config, context, region),
                        analyze_function_execution_role(function_config, context, region),
                        
                        # VPC configuration
                        analyze_function_vpc_config(function_config, context, region),
                        
                        # Environment and configuration
                        check_environment_variables(function_config, context, region),
                        check_dead_letter_queue(function_config, context, region),
                        
                        # Monitoring
                        check_function_monitoring(lambda_client, function_name, context, region)
                    ]
                    
                    # Execute analyzers concurrently for each function
                    function_results = await asyncio.gather(*analyzer_tasks, return_exceptions=True)
                    
                    # Process results
                    for result in function_results:
                        if isinstance(result, Exception):
                            logger.warning(f"Analyzer failed for function {function_name}: {result}")
                        else:
                            findings.extend(result)
                            
                except Exception as e:
                    logger.warning(f"Failed to analyze function {function_name}: {e}")
                    
    except Exception as e:
        logger.error(f"Failed to scan functions in {region}: {e}")
    
    return findings


def register() -> ScannerPlugin:
    """Register Lambda scanner plugin."""
    return ScannerPlugin(
        service="lambda",
        required_permissions=[
            # Lambda Functions
            "lambda:ListFunctions",
            "lambda:GetFunction",
            "lambda:GetFunctionConfiguration",
            "lambda:GetPolicy",
            "lambda:ListVersionsByFunction",
            "lambda:ListAliases",
            "lambda:ListTags",
            
            # Lambda Layers
            "lambda:ListLayers",
            "lambda:ListLayerVersions",
            "lambda:GetLayerVersion",
            "lambda:GetLayerVersionPolicy",
            
            # Event Source Mappings
            "lambda:ListEventSourceMappings",
            "lambda:GetEventSourceMapping",
            
            # For analyzing execution roles
            "iam:GetRole",
            "iam:ListAttachedRolePolicies",
            "iam:ListRolePolicies",
            "iam:GetRolePolicy",
            "iam:GetPolicy",
            "iam:GetPolicyVersion",
            
            # For VPC analysis
            "ec2:DescribeVpcs",
            "ec2:DescribeSubnets",
            "ec2:DescribeSecurityGroups",
            "ec2:DescribeRegions",
            
            # For monitoring checks
            "logs:DescribeLogGroups",
            "logs:DescribeLogStreams",
            
            # For CloudWatch metrics
            "cloudwatch:GetMetricStatistics",
            "cloudwatch:ListMetrics",
            "cloudwatch:DescribeAlarms",
            
            # For X-Ray tracing
            "xray:GetTracingSummaries",
            "xray:BatchGetTraces"
        ],
        scan_function=scan_lambda,
        remediation_map={
            # Function configuration
            "LAMBDA_DEPRECATED_RUNTIME": "update_runtime",
            "LAMBDA_EXCESSIVE_TIMEOUT": "adjust_timeout",
            "LAMBDA_RESERVED_CONCURRENCY_ZERO": "update_concurrency",
            
            # Environment and secrets
            "LAMBDA_SENSITIVE_ENV_VARS": "migrate_to_secrets_manager",
            "LAMBDA_ENV_VARS_NOT_ENCRYPTED": "enable_env_var_encryption",
            "LAMBDA_HARDCODED_AWS_CREDENTIALS": "remove_hardcoded_credentials",
            
            # Dead letter queue
            "LAMBDA_NO_DLQ": "configure_dead_letter_queue",
            
            # VPC configuration
            "LAMBDA_VPC_NO_SUBNETS": "configure_vpc_subnets",
            "LAMBDA_VPC_NO_SECURITY_GROUPS": "configure_security_groups",
            "LAMBDA_IN_PUBLIC_SUBNET": "move_to_private_subnet",
            
            # Execution role
            "LAMBDA_NO_EXECUTION_ROLE": "create_execution_role",
            "LAMBDA_OVERPRIVILEGED_ROLE": "reduce_role_permissions",
            "LAMBDA_INLINE_POLICIES": "convert_to_managed_policies",
            
            # Layers
            "LAMBDA_LAYER_PUBLIC_ACCESS": "restrict_layer_access",
            "LAMBDA_LAYER_DEPRECATED_RUNTIME_SUPPORT": "update_layer_runtimes",
            
            # Permissions
            "LAMBDA_FUNCTION_PUBLIC_ACCESS": "restrict_function_access",
            "LAMBDA_FUNCTION_WILDCARD_ACTIONS": "specify_precise_actions",
            "LAMBDA_FUNCTION_PUBLIC_INVOKE": "restrict_invoke_permissions",
            "LAMBDA_FUNCTION_DANGEROUS_PERMISSIONS": "remove_dangerous_permissions",
            
            # Event source mappings
            "LAMBDA_ESM_ORPHANED": "remove_orphaned_mapping",
            "LAMBDA_ESM_NO_FAILURE_DESTINATION": "configure_failure_destination",
            "LAMBDA_ESM_NO_RETRIES": "configure_retry_attempts",
            
            # Monitoring
            "LAMBDA_XRAY_TRACING_DISABLED": "enable_xray_tracing",
            "LAMBDA_LOGS_NO_RETENTION": "set_log_retention",
            "LAMBDA_LOGS_NOT_ENCRYPTED": "enable_log_encryption",
            "LAMBDA_NO_CLOUDWATCH_ALARMS": "create_cloudwatch_alarms"
        }
    )