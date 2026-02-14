"""
IAM Policy Analyzer for Lambda Security Audit
Analyzes IAM roles and policies for overprivileged permissions
"""
from typing import Dict, List, Any, Set
import json
import logging

logger = logging.getLogger(__name__)


class IAMAnalyzerError(Exception):
    """IAM Analyzer error"""
    pass


class IAMAnalyzer:
    """Analyzes IAM policies for security issues"""
    
    # Dangerous permissions that should rarely be used
    DANGEROUS_PERMISSIONS = {
        "iam:*",
        "iam:CreateAccessKey",
        "iam:CreateUser",
        "iam:AttachUserPolicy",
        "iam:PutUserPolicy",
        "iam:CreateRole",
        "iam:AssumeRole",
        "s3:*",
        "ec2:*",
        "rds:*",
        "kms:Decrypt",
        "kms:GenerateDataKey",
        "secretsmanager:GetSecretValue",
        "dynamodb:*",
    }
    
    # Star permissions
    STAR_PERMISSIONS = {"*"}
    
    def __init__(self):
        """Initialize IAM Analyzer"""
        self.findings = []
    
    def analyze_lambda_role(self, function_name: str, role_arn: str,
                           policies: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Analyze Lambda execution role for overprivileged permissions
        
        Args:
            function_name: Lambda function name
            role_arn: IAM role ARN
            policies: Dictionary with inline and attached policies
            
        Returns:
            List of findings
        """
        self.findings = []
        
        # Extract role name from ARN
        role_name = role_arn.split('/')[-1]
        
        logger.info(f"Analyzing IAM role: {role_name} for {function_name}")
        
        # Analyze inline policies
        if 'inline' in policies:
            for policy_name, policy_doc in policies['inline'].items():
                self._analyze_policy_document(
                    policy_doc, role_name, policy_name, 'inline'
                )
        
        # Analyze attached policies
        if 'attached' in policies:
            for policy_name in policies['attached']:
                self.findings.append({
                    'type': 'IAM_POLICY',
                    'severity': 'MEDIUM',
                    'message': f"Attached managed policy: {policy_name}",
                    'role': role_name,
                    'function': function_name,
                    'policy_type': 'attached',
                    'policy_name': policy_name
                })
        
        return self.findings
    
    def _analyze_policy_document(self, policy_doc: Dict[str, Any], 
                                role_name: str, policy_name: str,
                                policy_type: str):
        """Analyze individual policy document"""
        
        if 'Statement' not in policy_doc:
            return
        
        for statement in policy_doc['Statement']:
            if statement.get('Effect') != 'Allow':
                continue
            
            # Analyze actions
            actions = self._get_actions(statement)
            resources = self._get_resources(statement)
            
            for action in actions:
                # Check for wildcard action
                if action == '*':
                    self.findings.append({
                        'type': 'OVERPRIVILEGED',
                        'severity': 'CRITICAL',
                        'message': 'Wildcard action (*) - Lambda has access to all AWS services',
                        'role': role_name,
                        'action': action,
                        'resources': resources,
                        'policy_name': policy_name,
                        'policy_type': policy_type
                    })
                
                # Check for dangerous permissions
                elif action in self.DANGEROUS_PERMISSIONS:
                    self.findings.append({
                        'type': 'DANGEROUS_PERMISSION',
                        'severity': 'HIGH',
                        'message': f'High-risk permission: {action}',
                        'role': role_name,
                        'action': action,
                        'resources': resources,
                        'policy_name': policy_name,
                        'policy_type': policy_type
                    })
                
                # Check for broad wildcards (e.g., s3:*, iam:*)
                elif action.endswith('*'):
                    service = action.split(':')[0]
                    if f"{service}:*" in self.DANGEROUS_PERMISSIONS:
                        self.findings.append({
                            'type': 'BROAD_PERMISSION',
                            'severity': 'HIGH',
                            'message': f'Broad permission for {service}: {action}',
                            'role': role_name,
                            'action': action,
                            'resources': resources,
                            'policy_name': policy_name,
                            'policy_type': policy_type
                        })
            
            # Check for wildcard resources
            if '*' in resources:
                self.findings.append({
                    'type': 'WILDCARD_RESOURCE',
                    'severity': 'MEDIUM',
                    'message': 'Wildcard resource (*) - allows access to all resources',
                    'role': role_name,
                    'resources': resources,
                    'actions': list(actions),
                    'policy_name': policy_name,
                    'policy_type': policy_type
                })
    
    @staticmethod
    def _get_actions(statement: Dict[str, Any]) -> Set[str]:
        """Extract actions from statement"""
        actions = set()
        
        action_field = statement.get('Action', [])
        
        if isinstance(action_field, str):
            actions.add(action_field)
        elif isinstance(action_field, list):
            actions.update(action_field)
        
        not_action_field = statement.get('NotAction', [])
        if not_action_field:
            if isinstance(not_action_field, str):
                actions.add(f"NotAction:{not_action_field}")
            elif isinstance(not_action_field, list):
                actions.update([f"NotAction:{a}" for a in not_action_field])
        
        return actions
    
    @staticmethod
    def _get_resources(statement: Dict[str, Any]) -> List[str]:
        """Extract resources from statement"""
        resources = []
        
        resource_field = statement.get('Resource', [])
        
        if isinstance(resource_field, str):
            resources.append(resource_field)
        elif isinstance(resource_field, list):
            resources.extend(resource_field)
        
        return resources
    
    def check_public_access_risk(self, function_name: str, 
                                is_public: bool, role_policies: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Check if public Lambda has excessive permissions
        
        Args:
            function_name: Lambda function name
            is_public: Whether Lambda is publicly accessible
            role_policies: Role policies
            
        Returns:
            List of findings
        """
        findings = []
        
        if is_public:
            dangerous_count = sum(
                1 for f in self.findings 
                if f['severity'] in ['CRITICAL', 'HIGH']
            )
            
            findings.append({
                'type': 'PUBLIC_ACCESS_RISK',
                'severity': 'CRITICAL',
                'message': f'Lambda function {function_name} is publicly accessible with dangerous permissions',
                'function': function_name,
                'issues_found': dangerous_count
            })
        
        return findings
