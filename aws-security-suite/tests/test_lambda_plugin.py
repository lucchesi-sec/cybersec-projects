#!/usr/bin/env python3
"""
Test script to verify Lambda plugin loads correctly.
"""

import sys
import os

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    # Import the Lambda scanner
    from plugins.lambda_func.scanner import register
    
    # Test plugin registration
    plugin = register()
    
    print("✅ Lambda Plugin Test Results:")
    print(f"   Service: {plugin.service}")
    print(f"   Required Permissions: {len(plugin.required_permissions)} permissions")
    print(f"   Remediation Mappings: {len(plugin.remediation_map)} mappings")
    print(f"   Scan Function: {plugin.scan_function.__name__}")
    
    # Verify critical permissions are included
    critical_perms = [
        "lambda:ListFunctions",
        "lambda:GetFunctionConfiguration", 
        "lambda:GetPolicy",
        "lambda:ListLayers",
        "lambda:ListEventSourceMappings",
        "iam:GetRole"
    ]
    
    missing_perms = []
    for perm in critical_perms:
        if perm not in plugin.required_permissions:
            missing_perms.append(perm)
    
    if missing_perms:
        print(f"❌ Missing critical permissions: {missing_perms}")
    else:
        print("✅ All critical permissions included")
    
    # Test remediation mappings
    expected_remediations = [
        "LAMBDA_DEPRECATED_RUNTIME",
        "LAMBDA_SENSITIVE_ENV_VARS",
        "LAMBDA_ENV_VARS_NOT_ENCRYPTED",
        "LAMBDA_FUNCTION_PUBLIC_ACCESS",
        "LAMBDA_OVERPRIVILEGED_ROLE"
    ]
    
    missing_remediations = []
    for check in expected_remediations:
        if check not in plugin.remediation_map:
            missing_remediations.append(check)
    
    if missing_remediations:
        print(f"❌ Missing remediation mappings: {missing_remediations}")
    else:
        print("✅ Key remediation mappings present")
    
    # Test that scan function is callable
    if callable(plugin.scan_function):
        print("✅ Scan function is callable")
    else:
        print("❌ Scan function is not callable")
    
    print("\n📋 Lambda Plugin Details:")
    print(f"   Total Permissions: {len(plugin.required_permissions)}")
    print(f"   Total Remediations: {len(plugin.remediation_map)}")
    
    print("\n🔍 Security Check Categories:")
    print("   • Function Configuration (runtime, timeout, memory)")
    print("   • Access Control (IAM roles, resource policies)")
    print("   • Runtime Security (environment variables, encryption)")
    print("   • Monitoring (DLQ, X-Ray tracing, CloudWatch)")
    print("   • VPC Configuration (subnets, security groups)")
    print("   • Event Source Mappings")
    print("   • Lambda Layers security")
    
    print("\n✅ Lambda plugin loaded successfully!")
    
except ImportError as e:
    print(f"❌ Failed to import Lambda plugin: {e}")
    sys.exit(1)
except Exception as e:
    print(f"❌ Error testing Lambda plugin: {e}")
    sys.exit(1)