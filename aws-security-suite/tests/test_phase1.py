#!/usr/bin/env python3
"""
Phase 1 Test Script
Test the basic functionality of the unified AWS Security Suite
"""

import asyncio
import sys
import os

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.audit_context import AuditContext
from core.scanner import Scanner
from core.finding import Finding, Severity, Status
from plugins.s3 import register as s3_register
from plugins.iam import register as iam_register


async def test_basic_functionality():
    """Test basic scanner functionality without AWS calls."""
    print("🧪 Testing AWS Security Suite Phase 1...")
    
    # Test 1: Create audit context
    print("\n✅ Test 1: Creating AuditContext")
    context = AuditContext(
        region="us-east-1",
        regions=["us-east-1"],
        services=["s3", "iam"]
    )
    print(f"   Region: {context.region}")
    print(f"   Regions: {context.regions}")
    print(f"   Services: {context.services}")
    
    # Test 2: Create scanner and register plugins
    print("\n✅ Test 2: Creating Scanner and registering plugins")
    scanner = Scanner(context)
    
    # Register plugins
    s3_plugin = s3_register()
    iam_plugin = iam_register()
    
    scanner.registry.register(s3_plugin)
    scanner.registry.register(iam_plugin)
    
    print(f"   Registered services: {scanner.registry.list_services()}")
    
    # Test 3: Check plugin metadata
    print("\n✅ Test 3: Validating plugin metadata")
    s3_perms = s3_plugin.required_permissions
    iam_perms = iam_plugin.required_permissions
    
    print(f"   S3 permissions ({len(s3_perms)}): {s3_perms[:3]}...")
    print(f"   IAM permissions ({len(iam_perms)}): {iam_perms[:3]}...")
    
    # Test 4: Test Finding dataclass
    print("\n✅ Test 4: Testing Finding dataclass")
    test_finding = Finding(
        service="s3",
        resource_id="arn:aws:s3:::test-bucket",
        resource_name="test-bucket",
        check_id="S3_PUBLIC_ACCESS",
        check_title="S3 Bucket Public Access",
        status=Status.FAIL,
        severity=Severity.HIGH,
        region="us-east-1",
        account_id="123456789012",
        description="Test finding",
        recommendation="Fix it"
    )
    
    print(f"   Finding created: {test_finding.service}/{test_finding.check_id}")
    print(f"   Risk score: {test_finding.get_risk_score()}")
    print(f"   Is actionable: {test_finding.is_actionable()}")
    
    # Test 5: Test Finding serialization
    print("\n✅ Test 5: Testing Finding serialization")
    finding_dict = test_finding.to_dict()
    print(f"   Serialized keys: {list(finding_dict.keys())[:5]}...")
    
    # Test 6: Test permissions aggregation
    print("\n✅ Test 6: Testing permission aggregation")
    all_perms = scanner.registry.get_required_permissions()
    print(f"   Total permissions required: {len(all_perms)}")
    print(f"   Sample permissions: {all_perms[:3]}")
    
    print("\n🎉 Phase 1 basic functionality tests passed!")
    return True


def test_cli_imports():
    """Test that CLI can be imported without errors."""
    print("\n✅ Test 7: Testing CLI imports")
    try:
        import cli
        print("   CLI imported successfully")
        return True
    except Exception as e:
        print(f"   ❌ CLI import failed: {e}")
        return False


def main():
    """Run all Phase 1 tests."""
    print("=" * 60)
    print("AWS Security Suite - Phase 1 Foundation Tests")
    print("=" * 60)
    
    # Test basic functionality
    success = asyncio.run(test_basic_functionality())
    
    # Test CLI imports
    cli_success = test_cli_imports()
    
    if success and cli_success:
        print("\n🎉 ALL PHASE 1 TESTS PASSED! ✅")
        print("\nNext steps:")
        print("   • Install dependencies: pip install boto3 typer rich")
        print("   • Test with AWS: python cli.py list-services")
        print("   • Run actual scan: python cli.py scan --services s3")
        return 0
    else:
        print("\n❌ Some tests failed")
        return 1


if __name__ == "__main__":
    exit(main())