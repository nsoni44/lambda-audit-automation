"""
AWS Client wrapper for Lambda Security Audit
Handles all AWS API interactions
"""
import boto3
from botocore.exceptions import ClientError
from typing import List, Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


class AWSClientError(Exception):
    """AWS client error"""
    pass


class AWSClient:
    """Wrapper around boto3 clients for Lambda audit operations"""
    
    def __init__(self, region: str, access_key: str, secret_key: str):
        """
        Initialize AWS client
        
        Args:
            region: AWS region
            access_key: AWS access key ID
            secret_key: AWS secret access key
        """
        try:
            self.lambda_client = boto3.client(
                'lambda',
                region_name=region,
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key
            )
            
            self.iam_client = boto3.client(
                'iam',
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key
            )
            
            self.s3_client = boto3.client(
                's3',
                region_name=region,
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key
            )
            
            self.region = region
        except Exception as e:
            raise AWSClientError(f"Failed to initialize AWS client: {e}")
    
    def list_lambda_functions(self) -> List[Dict[str, Any]]:
        """
        List all Lambda functions in the region
        
        Returns:
            List of Lambda function metadata
        """
        try:
            functions = []
            paginator = self.lambda_client.get_paginator('list_functions')
            
            for page in paginator.paginate():
                functions.extend(page.get('Functions', []))
            
            logger.info(f"Found {len(functions)} Lambda functions")
            return functions
        except ClientError as e:
            raise AWSClientError(f"Failed to list Lambda functions: {e}")
    
    def get_lambda_function(self, function_name: str) -> Dict[str, Any]:
        """
        Get Lambda function details
        
        Args:
            function_name: Name of the Lambda function
            
        Returns:
            Function metadata and configuration
        """
        try:
            response = self.lambda_client.get_function(
                FunctionName=function_name
            )
            return response
        except ClientError as e:
            raise AWSClientError(
                f"Failed to get Lambda function {function_name}: {e}"
            )
    
    def get_lambda_function_code(self, function_name: str) -> bytes:
        """
        Download Lambda function code
        
        Args:
            function_name: Name of the Lambda function
            
        Returns:
            ZIP file bytes
        """
        try:
            response = self.lambda_client.get_function(
                FunctionName=function_name
            )
            
            code_location = response['Code']['Location']
            
            # Download from S3
            import requests
            response = requests.get(code_location)
            response.raise_for_status()
            
            return response.content
        except Exception as e:
            raise AWSClientError(
                f"Failed to download Lambda code for {function_name}: {e}"
            )
    
    def get_lambda_policy(self, function_name: str) -> Optional[Dict[str, Any]]:
        """
        Get Lambda function policy
        
        Args:
            function_name: Name of the Lambda function
            
        Returns:
            Policy document or None if not found
        """
        try:
            response = self.lambda_client.get_policy(
                FunctionName=function_name
            )
            
            import json
            policy = json.loads(response.get('Policy', '{}'))
            return policy
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                return None
            raise AWSClientError(
                f"Failed to get Lambda policy for {function_name}: {e}"
            )
    
    def get_iam_role(self, role_name: str) -> Dict[str, Any]:
        """
        Get IAM role details
        
        Args:
            role_name: Name of the IAM role
            
        Returns:
            Role metadata
        """
        try:
            response = self.iam_client.get_role(RoleName=role_name)
            return response['Role']
        except ClientError as e:
            raise AWSClientError(f"Failed to get IAM role {role_name}: {e}")
    
    def get_role_policies(self, role_name: str) -> Dict[str, Any]:
        """
        Get all inline and attached policies for a role
        
        Args:
            role_name: Name of the IAM role
            
        Returns:
            Dictionary with inline and attached policies
        """
        try:
            # Inline policies
            inline_policies = {}
            paginator = self.iam_client.get_paginator('list_role_policies')
            
            for page in paginator.paginate(RoleName=role_name):
                for policy_name in page.get('PolicyNames', []):
                    response = self.iam_client.get_role_policy(
                        RoleName=role_name,
                        PolicyName=policy_name
                    )
                    inline_policies[policy_name] = response['RolePolicyDocument']
            
            # Attached policies
            attached_policies = {}
            attach_paginator = self.iam_client.get_paginator(
                'list_attached_role_policies'
            )
            
            for page in attach_paginator.paginate(RoleName=role_name):
                for policy in page.get('AttachedPolicies', []):
                    attached_policies[policy['PolicyName']] = policy
            
            return {
                'inline': inline_policies,
                'attached': attached_policies
            }
        except ClientError as e:
            raise AWSClientError(
                f"Failed to get policies for role {role_name}: {e}"
            )
    
    def check_public_access(self, function_name: str) -> bool:
        """
        Check if Lambda function has public access
        
        Args:
            function_name: Name of the Lambda function
            
        Returns:
            True if publicly accessible
        """
        try:
            policy = self.get_lambda_policy(function_name)
            
            if not policy or 'Statement' not in policy:
                return False
            
            for statement in policy['Statement']:
                if statement.get('Effect') == 'Allow':
                    principal = statement.get('Principal', {})
                    
                    # Check for wildcard principal
                    if principal == '*' or principal.get('Service') == '*':
                        return True
                    
                    if isinstance(principal, dict):
                        if principal.get('AWS') == '*':
                            return True
            
            return False
        except Exception as e:
            logger.error(f"Error checking public access: {e}")
            return False
