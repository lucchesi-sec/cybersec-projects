"""
Lambda Event Source Mapping Analyzer
Analyzes Lambda event source mappings for configuration and security issues.
"""

import logging
from typing import List, Dict
from botocore.exceptions import ClientError

from core.finding import Finding, Severity, Status
from core.audit_context import AuditContext
from ..constants import (
    KINESIS_RECOMMENDED_BATCH_SIZE, SQS_RECOMMENDED_BATCH_SIZE, 
    DYNAMODB_RECOMMENDED_BATCH_SIZE
)

logger = logging.getLogger(__name__)


async def scan_event_source_mappings(lambda_client, context: AuditContext, region: str) -> List[Finding]:
    """Scan Lambda event source mappings for security issues."""
    findings = []
    
    try:
        paginator = lambda_client.get_paginator('list_event_source_mappings')
        
        for page in paginator.paginate():
            for mapping in page['EventSourceMappings']:
                mapping_findings = await analyze_event_source_mapping(
                    mapping, context, region
                )
                findings.extend(mapping_findings)
                
    except ClientError as e:
        logger.error(f"Failed to list event source mappings in {region}: {e}")
    
    return findings


async def analyze_event_source_mapping(
    mapping: Dict, context: AuditContext, region: str
) -> List[Finding]:
    """Analyze event source mapping for security issues."""
    findings = []
    uuid = mapping['UUID']
    function_arn = mapping.get('FunctionArn', '')
    event_source_arn = mapping.get('EventSourceArn', '')
    
    # Extract function name from ARN
    function_name = function_arn.split(':')[-1] if function_arn else 'Unknown'
    
    # Check if mapping is enabled but function doesn't exist
    state = mapping.get('State', '')
    if state == 'Enabled' and not function_arn:
        findings.append(Finding(
            service="lambda",
            resource_id=f"arn:aws:lambda:{region}:{context.account_id}:event-source-mapping:{uuid}",
            resource_name=f"ESM-{uuid[:8]}",
            check_id="LAMBDA_ESM_ORPHANED",
            check_title="Event Source Mapping References Missing Function",
            status=Status.FAIL,
            severity=Severity.MEDIUM,
            region=region,
            account_id=context.account_id,
            description=f"Event source mapping {uuid} is enabled but references missing function",
            recommendation="Remove orphaned event source mapping or fix function reference",
            remediation_available=True,
            context={"mapping_uuid": uuid, "state": state}
        ))
    
    # Analyze batch size based on event source type
    batch_size_findings = await _analyze_batch_size(
        mapping, event_source_arn, function_name, uuid, context, region
    )
    findings.extend(batch_size_findings)
    
    # Check for DLQ configuration on event source mapping
    failure_destination = mapping.get('DestinationConfig', {}).get('OnFailure', {})
    if not failure_destination and state == 'Enabled':
        findings.append(Finding(
            service="lambda",
            resource_id=f"arn:aws:lambda:{region}:{context.account_id}:event-source-mapping:{uuid}",
            resource_name=f"ESM-{uuid[:8]}",
            check_id="LAMBDA_ESM_NO_FAILURE_DESTINATION",
            check_title="Event Source Mapping Missing Failure Destination",
            status=Status.WARNING,
            severity=Severity.MEDIUM,
            region=region,
            account_id=context.account_id,
            description=f"Event source mapping for function '{function_name}' has no failure destination",
            recommendation="Configure failure destination for better error handling",
            context={"function_name": function_name}
        ))
    
    # Check additional configurations
    additional_findings = await _analyze_esm_advanced_config(
        mapping, function_name, uuid, context, region
    )
    findings.extend(additional_findings)
    
    return findings


async def _analyze_batch_size(
    mapping: Dict, event_source_arn: str, function_name: str, 
    uuid: str, context: AuditContext, region: str
) -> List[Finding]:
    """Analyze batch size configuration for different event source types."""
    findings = []
    batch_size = mapping.get('BatchSize', 1)
    
    # Determine event source type
    event_source_type = 'unknown'
    recommended_batch_size = 10  # Default
    
    if 'kinesis' in event_source_arn.lower():
        event_source_type = 'kinesis'
        recommended_batch_size = KINESIS_RECOMMENDED_BATCH_SIZE
    elif 'sqs' in event_source_arn.lower():
        event_source_type = 'sqs'
        recommended_batch_size = SQS_RECOMMENDED_BATCH_SIZE
    elif 'dynamodb' in event_source_arn.lower():
        event_source_type = 'dynamodb'
        recommended_batch_size = DYNAMODB_RECOMMENDED_BATCH_SIZE
    
    # Check batch size efficiency
    if batch_size == 1 and event_source_type != 'unknown':
        findings.append(Finding(
            service="lambda",
            resource_id=f"arn:aws:lambda:{region}:{context.account_id}:event-source-mapping:{uuid}",
            resource_name=f"ESM-{uuid[:8]}",
            check_id="LAMBDA_ESM_INEFFICIENT_BATCH_SIZE",
            check_title="Event Source Mapping Has Inefficient Batch Size",
            status=Status.WARNING,
            severity=Severity.LOW,
            region=region,
            account_id=context.account_id,
            description=f"{event_source_type.capitalize()} event source mapping has batch size of 1, which may be inefficient",
            recommendation=f"Consider increasing batch size (recommended: {recommended_batch_size}) for better performance and cost optimization",
            context={
                "batch_size": batch_size,
                "event_source": event_source_arn,
                "event_source_type": event_source_type,
                "recommended_batch_size": recommended_batch_size
            }
        ))
    elif batch_size > recommended_batch_size * 2:
        findings.append(Finding(
            service="lambda",
            resource_id=f"arn:aws:lambda:{region}:{context.account_id}:event-source-mapping:{uuid}",
            resource_name=f"ESM-{uuid[:8]}",
            check_id="LAMBDA_ESM_HIGH_BATCH_SIZE",
            check_title="Event Source Mapping Has Very High Batch Size",
            status=Status.WARNING,
            severity=Severity.LOW,
            region=region,
            account_id=context.account_id,
            description=f"{event_source_type.capitalize()} event source mapping has high batch size of {batch_size}",
            recommendation="Consider reducing batch size to avoid timeout issues",
            context={
                "batch_size": batch_size,
                "event_source_type": event_source_type,
                "recommended_batch_size": recommended_batch_size
            }
        ))
    
    return findings


async def _analyze_esm_advanced_config(
    mapping: Dict, function_name: str, uuid: str, 
    context: AuditContext, region: str
) -> List[Finding]:
    """Analyze advanced event source mapping configurations."""
    findings = []
    
    # Check parallelization factor for Kinesis
    parallelization_factor = mapping.get('ParallelizationFactor')
    if parallelization_factor and parallelization_factor > 10:
        findings.append(Finding(
            service="lambda",
            resource_id=f"arn:aws:lambda:{region}:{context.account_id}:event-source-mapping:{uuid}",
            resource_name=f"ESM-{uuid[:8]}",
            check_id="LAMBDA_ESM_HIGH_PARALLELIZATION",
            check_title="Event Source Mapping Has High Parallelization Factor",
            status=Status.WARNING,
            severity=Severity.LOW,
            region=region,
            account_id=context.account_id,
            description=f"Event source mapping has parallelization factor of {parallelization_factor}",
            recommendation="Ensure Lambda function can handle high concurrent executions",
            context={"parallelization_factor": parallelization_factor}
        ))
    
    # Check maximum retry attempts
    maximum_retry_attempts = mapping.get('MaximumRetryAttempts')
    if maximum_retry_attempts == 0:
        findings.append(Finding(
            service="lambda",
            resource_id=f"arn:aws:lambda:{region}:{context.account_id}:event-source-mapping:{uuid}",
            resource_name=f"ESM-{uuid[:8]}",
            check_id="LAMBDA_ESM_NO_RETRIES",
            check_title="Event Source Mapping Has No Retry Attempts",
            status=Status.WARNING,
            severity=Severity.MEDIUM,
            region=region,
            account_id=context.account_id,
            description=f"Event source mapping for function '{function_name}' has no retry attempts configured",
            recommendation="Configure retry attempts for better fault tolerance",
            context={"maximum_retry_attempts": 0}
        ))
    
    # Check maximum record age for streaming sources
    maximum_record_age = mapping.get('MaximumRecordAgeInSeconds')
    if maximum_record_age and maximum_record_age < 60:  # Less than 1 minute
        findings.append(Finding(
            service="lambda",
            resource_id=f"arn:aws:lambda:{region}:{context.account_id}:event-source-mapping:{uuid}",
            resource_name=f"ESM-{uuid[:8]}",
            check_id="LAMBDA_ESM_LOW_MAX_RECORD_AGE",
            check_title="Event Source Mapping Has Low Maximum Record Age",
            status=Status.WARNING,
            severity=Severity.LOW,
            region=region,
            account_id=context.account_id,
            description=f"Event source mapping has maximum record age of {maximum_record_age} seconds",
            recommendation="Consider increasing maximum record age for better retry handling",
            context={"maximum_record_age": maximum_record_age}
        ))
    
    # Check bisect batch on function error (for streaming sources)
    bisect_batch = mapping.get('BisectBatchOnFunctionError', False)
    if not bisect_batch and mapping.get('EventSourceArn', '').lower().find('kinesis') != -1:
        findings.append(Finding(
            service="lambda",
            resource_id=f"arn:aws:lambda:{region}:{context.account_id}:event-source-mapping:{uuid}",
            resource_name=f"ESM-{uuid[:8]}",
            check_id="LAMBDA_ESM_NO_BISECT_ON_ERROR",
            check_title="Kinesis Event Source Mapping Missing Bisect on Error",
            status=Status.INFO,
            severity=Severity.LOW,
            region=region,
            account_id=context.account_id,
            description="Kinesis event source mapping does not bisect batch on function error",
            recommendation="Enable bisect batch on function error for better error isolation",
            context={"bisect_batch_on_function_error": False}
        ))
    
    return findings