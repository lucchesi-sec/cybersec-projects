"""
Lambda Security Scanner Constants
Defines security thresholds, patterns, and configuration constants.
"""

# High-risk runtime environments that require additional scrutiny
HIGH_RISK_RUNTIMES = [
    'nodejs8.10', 
    'python2.7', 
    'dotnetcore1.0', 
    'dotnetcore2.0',
    'nodejs6.10',
    'nodejs4.3',
    'python3.6',  # EOL as of Dec 2021
    'ruby2.5'     # EOL
]

# Critical environment variable patterns that might contain secrets
SENSITIVE_ENV_PATTERNS = [
    'password', 'passwd', 'pwd', 'secret', 'key', 'token', 'api_key', 
    'access_key', 'secret_key', 'private_key', 'auth', 'credential',
    'db_password', 'database_password', 'mysql_password', 'postgres_password',
    'redis_password', 'rabbitmq_password', 'mongodb_password', 'elasticsearch_password',
    'jwt_secret', 'oauth_secret', 'webhook_secret', 'encryption_key',
    'signing_key', 'api_secret', 'app_secret', 'client_secret'
]

# Lambda function timeout limits (in seconds) that indicate potential issues
EXCESSIVE_TIMEOUT_THRESHOLD = 600  # 10 minutes
MINIMAL_TIMEOUT_THRESHOLD = 3      # 3 seconds
DEFAULT_TIMEOUT = 3                # AWS default

# Memory size thresholds (in MB)
LOW_MEMORY_THRESHOLD = 512
HIGH_MEMORY_THRESHOLD = 3008  # Near max (3008 MB is max allowed)
DEFAULT_MEMORY = 128

# Code size thresholds (in bytes)
LARGE_PACKAGE_THRESHOLD = 50 * 1024 * 1024  # 50MB
MAX_PACKAGE_SIZE = 250 * 1024 * 1024        # 250MB (AWS limit)

# Concurrency thresholds
DEFAULT_CONCURRENT_EXECUTIONS = 1000
LOW_RESERVED_CONCURRENCY = 10

# Batch size recommendations
KINESIS_RECOMMENDED_BATCH_SIZE = 100
SQS_RECOMMENDED_BATCH_SIZE = 10
DYNAMODB_RECOMMENDED_BATCH_SIZE = 25