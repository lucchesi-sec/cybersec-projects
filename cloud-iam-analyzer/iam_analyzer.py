#!/usr/bin/env python3
"""
AWS IAM Policy Analyzer
A tool to identify excessive permissions in AWS IAM policies.
"""

import boto3
import argparse
import json
import re
from colorama import Fore, Style, init

# DEFENSIVE PRACTICE: Initialize colorama for secure terminal output
init()

def validate_policy_arn(arn):
    """Validate IAM policy ARN format"""
    pattern = r'^arn:aws:iam::\d{12}:policy/[\w+=,.@-]+$'
    if not re.match(pattern, arn):
        raise ValueError(f"Invalid policy ARN format: {arn}")
    return arn

def parse_arguments():
    """Parse command line arguments with secure defaults"""
    parser = argparse.ArgumentParser(description='Analyze AWS IAM policies for security risks')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--policy-arn', help='ARN of the policy to analyze')
    group.add_argument('--policy-file', help='Path to JSON file containing policy document')
    group.add_argument('--policy-json', help='Inline JSON policy document')
    parser.add_argument('--output', choices=['text', 'json'], default='text',
                      help='Output format (default: text)')
    args = parser.parse_args()
    
    if args.policy_arn:
        args.policy_arn = validate_policy_arn(args.policy_arn)
    
    return args

def get_iam_client():
    """Create and return IAM client with defensive error handling"""
    try:
        return boto3.client('iam')
    except boto3.client('iam').exceptions.ClientError as e:
        print(f"{Fore.RED}AWS IAM client error: {str(e)}{Style.RESET_ALL}")
        raise
    except Exception as e:
        print(f"{Fore.RED}Error creating IAM client: {str(e)}{Style.RESET_ALL}")
        print("Ensure AWS credentials are properly configured")
        raise

def get_policy_document(iam_client, policy_arn):
    """Retrieve policy document with secure validation"""
    try:
        policy = iam_client.get_policy(PolicyArn=policy_arn)['Policy']
        version = policy['DefaultVersionId']
        document = iam_client.get_policy_version(
            PolicyArn=policy_arn,
            VersionId=version
        )['PolicyVersion']['Document']
        return document
    except iam_client.exceptions.NoSuchEntityException:
        print(f"{Fore.RED}Policy not found: {policy_arn}{Style.RESET_ALL}")
        raise
    except iam_client.exceptions.InvalidInputException as e:
        print(f"{Fore.RED}Invalid input: {str(e)}{Style.RESET_ALL}")
        raise
    except iam_client.exceptions.ServiceFailureException as e:
        print(f"{Fore.RED}AWS service failure: {str(e)}{Style.RESET_ALL}")
        raise
    except Exception as e:
        print(f"{Fore.RED}Error retrieving policy: {str(e)}{Style.RESET_ALL}")
        raise

def load_policy_document(args):
    """Load policy document from various sources"""
    if args.policy_arn:
        iam_client = get_iam_client()
        return get_policy_document(iam_client, args.policy_arn)
    elif args.policy_file:
        try:
            with open(args.policy_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"{Fore.RED}Policy file not found: {args.policy_file}{Style.RESET_ALL}")
            raise
        except json.JSONDecodeError as e:
            print(f"{Fore.RED}Invalid JSON in policy file: {str(e)}{Style.RESET_ALL}")
            raise
    elif args.policy_json:
        try:
            return json.loads(args.policy_json)
        except json.JSONDecodeError as e:
            print(f"{Fore.RED}Invalid JSON policy document: {str(e)}{Style.RESET_ALL}")
            raise

def analyze_policy(document):
    """Analyze policy document for security risks"""
    findings = []
    
    # DEFENSIVE PRACTICE: Validate policy document structure
    if 'Statement' not in document:
        return [{'risk': 'CRITICAL', 'description': 'Policy missing Statement element'}]
    
    # Pre-compile regex patterns for better performance
    high_risk_patterns = [
        re.compile(r'.*:Delete.*'),
        re.compile(r'.*:Put.*'),
        re.compile(r'.*:Create.*'),
        re.compile(r'.*:Update.*'),
        re.compile(r'iam:.*'),
        re.compile(r'sts:AssumeRole.*'),
        re.compile(r'ec2:.*'),
        re.compile(r'rds:.*'),
        re.compile(r's3:.*'),
        re.compile(r'lambda:.*'),
        re.compile(r'logs:.*'),
        re.compile(r'kms:.*')
    ]
    
    critical_actions = {
        'iam:CreateRole', 'iam:AttachRolePolicy', 'iam:PutRolePolicy',
        'sts:AssumeRole', 'ec2:TerminateInstances', 's3:DeleteBucket',
        'rds:DeleteDBInstance', 'lambda:InvokeFunction'
    }
    
    for statement in document['Statement']:
        # Check for overly permissive actions
        if 'Action' in statement and statement.get('Effect') == 'Allow':
            actions = statement['Action']
            if not isinstance(actions, list):
                actions = [actions]
                
            # Check for wildcard actions
            if '*' in actions:
                findings.append({
                    'risk': 'HIGH',
                    'description': 'Wildcard action permission',
                    'statement': statement
                })
                
            # Check for sensitive permissions using pre-compiled patterns
            for action in actions:
                if action in critical_actions:
                    findings.append({
                        'risk': 'HIGH',
                        'description': f'Critical action permission: {action}',
                        'statement': statement
                    })
                elif any(pattern.match(action) for pattern in high_risk_patterns):
                    findings.append({
                        'risk': 'MEDIUM',
                        'description': f'Sensitive action permission: {action}',
                        'statement': statement
                    })
                    
        # Check for resource wildcards
        resources = statement.get('Resource', [])
        if not isinstance(resources, list):
            resources = [resources]
            
        if '*' in resources:
            findings.append({
                'risk': 'HIGH',
                'description': 'Wildcard resource permission',
                'statement': statement
            })
            
    return findings

def main():
    """Main analysis workflow"""
    args = parse_arguments()
    print(f"{Fore.CYAN}AWS IAM Policy Analyzer{Style.RESET_ALL}")
    
    try:
        policy_doc = load_policy_document(args)
        findings = analyze_policy(policy_doc)
        
        if args.output == 'json':
            print(json.dumps(findings, indent=2))
        else:
            if not findings:
                print(f"{Fore.GREEN}No high-risk findings detected{Style.RESET_ALL}")
                return
                
            print(f"\n{Fore.YELLOW}Security Findings:{Style.RESET_ALL}")
            for finding in findings:
                color = Fore.RED if finding['risk'] == 'HIGH' else Fore.YELLOW
                print(f"{color}[{finding['risk']}] {finding['description']}{Style.RESET_ALL}")
                print(f"Statement: {json.dumps(finding['statement'], indent=2)}")
                
    except Exception as e:
        print(f"{Fore.RED}Analysis failed: {str(e)}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
