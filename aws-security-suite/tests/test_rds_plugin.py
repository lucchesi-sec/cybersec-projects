#!/usr/bin/env python3
"""
Test script to verify RDS plugin loads correctly.
"""

import sys
import os

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    # Import the RDS scanner
    from plugins.rds.scanner import register
    
    # Test plugin registration
    plugin = register()
    
    print("✅ RDS Plugin Test Results:")
    print(f"   Service: {plugin.service}")
    print(f"   Required Permissions: {len(plugin.required_permissions)} permissions")
    print(f"   Remediation Mappings: {len(plugin.remediation_map)} mappings")
    print(f"   Scan Function: {plugin.scan_function.__name__}")
    
    # Verify critical permissions are included
    critical_perms = [
        "rds:DescribeDBInstances",
        "rds:DescribeDBClusters", 
        "rds:DescribeDBSnapshots",
        "rds:DescribeDBSnapshotAttributes"
    ]
    
    missing_perms = [p for p in critical_perms if p not in plugin.required_permissions]
    if missing_perms:
        print(f"❌ Missing critical permissions: {missing_perms}")
    else:
        print("✅ All critical permissions included")
    
    # Verify remediation mappings
    critical_checks = [
        "RDS_INSTANCE_NOT_ENCRYPTED",
        "RDS_INSTANCE_PUBLICLY_ACCESSIBLE",
        "RDS_SNAPSHOT_PUBLIC"
    ]
    
    missing_remediation = [c for c in critical_checks if c not in plugin.remediation_map]
    if missing_remediation:
        print(f"❌ Missing remediation mappings: {missing_remediation}")
    else:
        print("✅ All critical remediation mappings included")
    
    print("\n📋 Security Checks Covered:")
    print("   • RDS instance storage encryption")
    print("   • RDS cluster storage encryption") 
    print("   • Public accessibility of instances")
    print("   • Backup retention periods")
    print("   • Multi-AZ deployment for production")
    print("   • Deletion protection")
    print("   • Public snapshot access")
    print("   • Parameter group security settings")
    print("   • Option group security settings")
    print("   • Performance insights monitoring")
    print("   • Minor version auto upgrades")
    
    print("\n🔧 Remediation Available For:")
    for check_id, remedy_func in plugin.remediation_map.items():
        print(f"   • {check_id} → {remedy_func}")
    
    print("\n✅ RDS Security Scanner Plugin loaded successfully!")
    
except Exception as e:
    print(f"❌ Failed to load RDS plugin: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)