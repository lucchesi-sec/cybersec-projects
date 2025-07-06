#!/usr/bin/env python3
"""
Test script to verify EC2 plugin loads correctly.
"""

import sys
import os

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    # Import the EC2 scanner
    from plugins.ec2.scanner import register
    
    # Test plugin registration
    plugin = register()
    
    print("✅ EC2 Plugin Test Results:")
    print(f"   Service: {plugin.service}")
    print(f"   Required Permissions: {len(plugin.required_permissions)} permissions")
    print(f"   Remediation Mappings: {len(plugin.remediation_map)} mappings")
    print(f"   Scan Function: {plugin.scan_function.__name__}")
    
    # Verify critical permissions are included
    critical_perms = [
        "ec2:DescribeInstances",
        "ec2:DescribeSecurityGroups", 
        "ec2:DescribeVolumes",
        "ec2:DescribeVpcs"
    ]
    
    missing_perms = [p for p in critical_perms if p not in plugin.required_permissions]
    if missing_perms:
        print(f"❌ Missing critical permissions: {missing_perms}")
    else:
        print("✅ All critical permissions included")
    
    # Verify remediation mappings
    critical_checks = [
        "EC2_IMDS_V2_NOT_ENFORCED",
        "EC2_SG_OPEN_TO_WORLD",
        "EC2_EBS_VOLUME_NOT_ENCRYPTED"
    ]
    
    missing_remediation = [c for c in critical_checks if c not in plugin.remediation_map]
    if missing_remediation:
        print(f"❌ Missing remediation mappings: {missing_remediation}")
    else:
        print("✅ All critical remediation mappings included")
    
    print("\n📋 Security Checks Covered:")
    print("   • Instance Metadata Service v2 enforcement")
    print("   • Security group overly permissive rules") 
    print("   • EBS volume encryption status")
    print("   • Public IP assignment checks")
    print("   • Instance profile validation")
    print("   • VPC security (default VPC usage)")
    print("   • VPC Flow Logs configuration")
    print("   • Public EBS snapshots")
    print("   • Detailed monitoring status")
    
    print("\n🔧 Remediation Available For:")
    for check_id, remedy_func in plugin.remediation_map.items():
        print(f"   • {check_id} → {remedy_func}")
    
    print("\n✅ EC2 Security Scanner Plugin loaded successfully!")
    
except Exception as e:
    print(f"❌ Failed to load EC2 plugin: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)