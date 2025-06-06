#!/usr/bin/env python3
"""
AWS IAM Policy Analyzer
A tool to identify excessive permissions in AWS IAM policies.
"""

import boto3
import argparse
import json
from colorama import Fore, Style, init

# DEFENSIVE PRACTICE: Initialize colorama for secure terminal output
init()

def parse_arguments():
    """Parse command line arguments with secure defaults"""
    parser = argparse.ArgumentParser(description='Analyze AWS IAM policies for security risks')
    parser.add_argument('--policy-arn', help='ARN of the policy to analyze')
    parser.add_argument('--output', choices=['text', 'json'], default='text',
                      help='Output format (default: text)')
    return parser.parse_args()

def get_iam_client():
    """Create and return IAM client with defensive error handling"""
    try:
        return boto3.client('iam')
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
    except Exception as e:
        print(f"{Fore.RED}Error retrieving policy: {str(e)}{Style.RESET_ALL}")
        raise

def analyze_policy(document):
    """Analyze policy document for security risks"""
    findings = []
    
    # DEFENSIVE PRACTICE: Validate policy document structure
    if 'Statement' not in document:
        return [{'risk': 'CRITICAL', 'description': 'Policy missing Statement element'}]
    
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
                
            # Check for sensitive permissions
            sensitive_actions = [
                '*:Delete*', '*:Put*', '*:Update*', 
                'iam:*', 's3:*', 'ec2:*', 'rds:*'
            ]
            for action in actions:
                if any(pattern in action for pattern in sensitive_actions):
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
        iam_client = get_iam_client()
        policy_doc = get_policy_document(iam_client, args.policy_arn)
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
