"""
Lambda Monitoring Analyzer
Analyzes Lambda function monitoring, logging, and observability configurations.
"""

import logging
from typing import List, Dict
from botocore.exceptions import ClientError

from core.finding import Finding, Severity, Status
from core.audit_context import AuditContext

logger = logging.getLogger(__name__)


async def check_function_monitoring(
    lambda_client, function_name: str, context: AuditContext, region: str
) -> List[Finding]:
    """Check if function has proper monitoring and alerting configured."""
    findings = []
    function_arn = f"arn:aws:lambda:{region}:{context.account_id}:function:{function_name}"
    
    try:
        # Get function configuration for tracing and other monitoring settings
        function_config = lambda_client.get_function_configuration(FunctionName=function_name)
        
        # Check X-Ray tracing
        tracing_findings = await _check_xray_tracing(
            function_name, function_arn, function_config, context, region
        )
        findings.extend(tracing_findings)
        
        # Check CloudWatch Logs configuration
        logs_findings = await _check_cloudwatch_logs(
            function_name, function_arn, function_config, context, region
        )
        findings.extend(logs_findings)
        
        # Check for enhanced monitoring
        monitoring_findings = await _check_enhanced_monitoring(
            function_name, function_arn, function_config, context, region
        )
        findings.extend(monitoring_findings)
        
    except ClientError as e:
        logger.warning(f"Failed to check monitoring for function {function_name}: {e}")
    
    return findings


async def _check_xray_tracing(
    function_name: str, function_arn: str, function_config: Dict,
    context: AuditContext, region: str
) -> List[Finding]:
    """Check X-Ray tracing configuration."""
    findings = []
    
    tracing_config = function_config.get('TracingConfig', {})
    tracing_mode = tracing_config.get('Mode', 'PassThrough')
    
    if tracing_mode != 'Active':
        findings.append(Finding(
            service="lambda",
            resource_id=function_arn,
            resource_name=function_name,
            check_id="LAMBDA_XRAY_TRACING_DISABLED",
            check_title="Lambda Function X-Ray Tracing Disabled",
            status=Status.WARNING,
            severity=Severity.LOW,
            region=region,
            account_id=context.account_id,
            description=f"Lambda function '{function_name}' does not have X-Ray tracing enabled",
            recommendation="Enable X-Ray tracing for better observability",
            remediation_available=True,
            context={"tracing_mode": tracing_mode}
        ))
    else:
        # X-Ray is enabled - this is good
        findings.append(Finding(
            service="lambda",
            resource_id=function_arn,
            resource_name=function_name,
            check_id="LAMBDA_XRAY_TRACING_ENABLED",
            check_title="Lambda Function Has X-Ray Tracing Enabled",
            status=Status.PASS,
            severity=Severity.INFO,
            region=region,
            account_id=context.account_id,
            description=f"Lambda function '{function_name}' has X-Ray tracing properly enabled",
            context={"tracing_mode": tracing_mode}
        ))
    
    return findings


async def _check_cloudwatch_logs(
    function_name: str, function_arn: str, function_config: Dict,
    context: AuditContext, region: str
) -> List[Finding]:
    """Check CloudWatch Logs configuration."""
    findings = []
    
    # Lambda automatically creates log groups, but we should check retention
    log_group_name = f"/aws/lambda/{function_name}"
    
    try:
        logs_client = context.get_client('logs', region_name=region)
        
        # Check if log group exists and get its configuration
        try:
            log_groups = logs_client.describe_log_groups(
                logGroupNamePrefix=log_group_name,
                limit=1
            )
            
            if log_groups['logGroups']:
                log_group = log_groups['logGroups'][0]
                retention_days = log_group.get('retentionInDays')
                
                if not retention_days:
                    findings.append(Finding(
                        service="lambda",
                        resource_id=function_arn,
                        resource_name=function_name,
                        check_id="LAMBDA_LOGS_NO_RETENTION",
                        check_title="Lambda Function Logs Have No Retention Policy",
                        status=Status.WARNING,
                        severity=Severity.MEDIUM,
                        region=region,
                        account_id=context.account_id,
                        description=f"Lambda function '{function_name}' logs have no retention policy (never expire)",
                        recommendation="Set appropriate log retention period to manage costs and compliance",
                        context={"log_group": log_group_name}
                    ))
                elif retention_days < 7:
                    findings.append(Finding(
                        service="lambda",
                        resource_id=function_arn,
                        resource_name=function_name,
                        check_id="LAMBDA_LOGS_SHORT_RETENTION",
                        check_title="Lambda Function Logs Have Short Retention Period",
                        status=Status.WARNING,
                        severity=Severity.LOW,
                        region=region,
                        account_id=context.account_id,
                        description=f"Lambda function '{function_name}' logs retained for only {retention_days} days",
                        recommendation="Consider longer retention for debugging and compliance",
                        context={"retention_days": retention_days}
                    ))
                
                # Check if log group is encrypted
                kms_key_id = log_group.get('kmsKeyId')
                if not kms_key_id:
                    findings.append(Finding(
                        service="lambda",
                        resource_id=function_arn,
                        resource_name=function_name,
                        check_id="LAMBDA_LOGS_NOT_ENCRYPTED",
                        check_title="Lambda Function Logs Not Encrypted with KMS",
                        status=Status.WARNING,
                        severity=Severity.MEDIUM,
                        region=region,
                        account_id=context.account_id,
                        description=f"Lambda function '{function_name}' logs are not encrypted with KMS",
                        recommendation="Enable KMS encryption for CloudWatch Logs",
                        context={"log_group": log_group_name}
                    ))
            else:
                # Log group doesn't exist yet (function might not have run)
                findings.append(Finding(
                    service="lambda",
                    resource_id=function_arn,
                    resource_name=function_name,
                    check_id="LAMBDA_LOGS_NOT_CREATED",
                    check_title="Lambda Function Log Group Not Yet Created",
                    status=Status.INFO,
                    severity=Severity.LOW,
                    region=region,
                    account_id=context.account_id,
                    description=f"Lambda function '{function_name}' log group not yet created (function may not have run)",
                    context={"expected_log_group": log_group_name}
                ))
                
        except ClientError as e:
            if e.response['Error']['Code'] != 'ResourceNotFoundException':
                logger.warning(f"Failed to check log group for {function_name}: {e}")
                
    except Exception as e:
        logger.warning(f"Failed to check CloudWatch Logs configuration: {e}")
    
    return findings


async def _check_enhanced_monitoring(
    function_name: str, function_arn: str, function_config: Dict,
    context: AuditContext, region: str
) -> List[Finding]:
    """Check for enhanced monitoring and metrics configuration."""
    findings = []
    
    # Check if Lambda Insights is enabled
    layers = function_config.get('Layers', [])
    insights_enabled = False
    
    for layer in layers:
        layer_arn = layer.get('Arn', '')
        # Lambda Insights layers contain 'LambdaInsightsExtension'
        if 'LambdaInsightsExtension' in layer_arn:
            insights_enabled = True
            break
    
    if not insights_enabled:
        findings.append(Finding(
            service="lambda",
            resource_id=function_arn,
            resource_name=function_name,
            check_id="LAMBDA_INSIGHTS_DISABLED",
            check_title="Lambda Function Does Not Use Lambda Insights",
            status=Status.INFO,
            severity=Severity.LOW,
            region=region,
            account_id=context.account_id,
            description=f"Lambda function '{function_name}' does not have Lambda Insights enabled",
            recommendation="Consider enabling Lambda Insights for enhanced monitoring",
            context={"layers_count": len(layers)}
        ))
    
    # Check for custom metrics (this would require checking function code)
    # For now, we'll just provide a recommendation
    findings.append(Finding(
        service="lambda",
        resource_id=function_arn,
        resource_name=function_name,
        check_id="LAMBDA_CUSTOM_METRICS_CHECK",
        check_title="Lambda Function Custom Metrics",
        status=Status.INFO,
        severity=Severity.INFO,
        region=region,
        account_id=context.account_id,
        description=f"Review if Lambda function '{function_name}' publishes custom CloudWatch metrics",
        recommendation="Consider publishing custom metrics for business-critical functions",
        context={"function_name": function_name}
    ))
    
    # Check if function has CloudWatch alarms configured
    # This would require CloudWatch client to check alarms
    try:
        cloudwatch_client = context.get_client('cloudwatch', region_name=region)
        
        # Check for common Lambda alarms
        alarm_names = [
            f"{function_name}-errors",
            f"{function_name}-throttles",
            f"{function_name}-duration",
            f"{function_name}-concurrent-executions"
        ]
        
        existing_alarms = []
        for alarm_name in alarm_names:
            try:
                alarms = cloudwatch_client.describe_alarms(
                    AlarmNames=[alarm_name],
                    MaxRecords=1
                )
                if alarms['MetricAlarms']:
                    existing_alarms.append(alarm_name)
            except:
                pass
        
        if not existing_alarms:
            findings.append(Finding(
                service="lambda",
                resource_id=function_arn,
                resource_name=function_name,
                check_id="LAMBDA_NO_CLOUDWATCH_ALARMS",
                check_title="Lambda Function Has No CloudWatch Alarms",
                status=Status.WARNING,
                severity=Severity.MEDIUM,
                region=region,
                account_id=context.account_id,
                description=f"Lambda function '{function_name}' has no CloudWatch alarms configured",
                recommendation="Configure alarms for errors, throttles, duration, and concurrent executions",
                context={"checked_alarm_patterns": alarm_names}
            ))
            
    except Exception as e:
        logger.warning(f"Failed to check CloudWatch alarms: {e}")
    
    return findings