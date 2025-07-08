# Lambda Scanner Refactoring Plan

## Current State Analysis
The `scanner.py` file contains 933 lines with all functionality in a single module. This violates the single responsibility principle and makes the code harder to maintain, test, and extend.

## Identified Responsibilities
1. **Configuration Constants** - Security thresholds and patterns
2. **Function Analysis** - Security checks for Lambda functions
3. **Layer Analysis** - Security checks for Lambda layers
4. **Event Source Mapping Analysis** - ESM security checks
5. **Permission Analysis** - IAM and resource policy checks
6. **VPC Configuration Analysis** - Network security checks
7. **Environment Variable Analysis** - Sensitive data detection
8. **Monitoring Analysis** - CloudWatch and X-Ray checks
9. **Common Utilities** - Region discovery, helper functions

## Proposed Module Structure

```
lambda_func/
├── __init__.py
├── scanner.py (main orchestrator - reduced to ~150 lines)
├── constants.py (~30 lines)
├── analyzers/
│   ├── __init__.py
│   ├── function_analyzer.py (~250 lines)
│   ├── layer_analyzer.py (~100 lines)
│   ├── event_source_analyzer.py (~120 lines)
│   ├── permission_analyzer.py (~150 lines)
│   ├── vpc_analyzer.py (~100 lines)
│   ├── environment_analyzer.py (~100 lines)
│   └── monitoring_analyzer.py (~80 lines)
└── utils/
    ├── __init__.py
    └── lambda_utils.py (~50 lines)
```

## Module Responsibilities

### 1. `constants.py`
- All configuration constants
- Security thresholds
- Sensitive patterns
- Runtime classifications

### 2. `scanner.py` (Main Orchestrator)
- Main scan_lambda function
- Orchestrates all sub-analyzers
- Handles plugin registration
- Manages remediation mapping

### 3. `analyzers/function_analyzer.py`
- `analyze_function_configuration()`
- `analyze_function_code_security()`
- `analyze_function_execution_role()`
- Function timeout and memory checks

### 4. `analyzers/layer_analyzer.py`
- `scan_lambda_layers()`
- `analyze_layer_version()`
- Layer permission checks

### 5. `analyzers/event_source_analyzer.py`
- `scan_event_source_mappings()`
- `analyze_event_source_mapping()`
- Batch size optimization checks
- Failure destination checks

### 6. `analyzers/permission_analyzer.py`
- `scan_function_permissions()`
- `analyze_function_policy()`
- `analyze_function_execution_role()`
- IAM role privilege checks

### 7. `analyzers/vpc_analyzer.py`
- `analyze_function_vpc_config()`
- Subnet configuration checks
- Security group validation
- Multi-AZ checks

### 8. `analyzers/environment_analyzer.py`
- `check_environment_variables()`
- `check_dead_letter_queue()`
- Sensitive data detection
- KMS encryption checks

### 9. `analyzers/monitoring_analyzer.py`
- `check_function_monitoring()`
- X-Ray tracing checks
- CloudWatch configuration

### 10. `utils/lambda_utils.py`
- `get_available_regions()`
- Common helper functions
- Shared utilities

## Benefits of Refactoring

1. **Improved Maintainability** - Each module has a single, clear responsibility
2. **Better Testability** - Smaller modules are easier to unit test
3. **Enhanced Readability** - Developers can quickly find relevant code
4. **Easier Extension** - New analyzers can be added without modifying existing code
5. **Reduced Complexity** - Each file is focused and manageable in size
6. **Better Code Reuse** - Common patterns can be shared via utilities

## Implementation Order

1. Create directory structure
2. Extract constants to `constants.py`
3. Create utility functions in `utils/lambda_utils.py`
4. Extract each analyzer to its respective module
5. Update main scanner to orchestrate analyzers
6. Update imports and ensure backward compatibility