"""
Environment Variables Scanner for Lambda Security Audit
Extracts and analyzes Lambda environment variables for exposed secrets
"""
from typing import Dict, List, Any
import re
import logging

logger = logging.getLogger(__name__)


class EnvironmentVariableScanner:
    """Scans Lambda environment variables for exposed secrets"""
    
    # Common secret patterns in env var names
    SECRET_VAR_PATTERNS = [
        r".*password.*",
        r".*secret.*",
        r".*key.*",
        r".*token.*",
        r".*api[_-]?key.*",
        r".*access[_-]?key.*",
        r".*private[_-]?key.*",
        r".*encryption.*",
        r".*credential.*",
        r".*auth.*",
    ]
    
    # Dangerous values
    DANGEROUS_VALUES = [
        r"AKIA[0-9A-Z]{16}",  # AWS Access Key
        r"[A-Za-z0-9/+=]{40}",  # AWS Secret Key pattern
        r"(?i)(admin|password|123|password123)",  # Weak passwords
    ]
    
    def __init__(self):
        """Initialize environment variable scanner"""
        self.findings = []
    
    def scan_environment_variables(self, function_name: str, 
                                   env_vars: Dict[str, str]) -> List[Dict[str, Any]]:
        """
        Scan Lambda environment variables for secrets
        
        Args:
            function_name: Lambda function name
            env_vars: Dictionary of environment variables
            
        Returns:
            List of findings
        """
        self.findings = []
        
        if not env_vars or not isinstance(env_vars, dict):
            return self.findings
        
        logger.info(f"Scanning {len(env_vars)} environment variables for {function_name}")
        
        for var_name, var_value in env_vars.items():
            if not var_value:
                continue
            
            # Check if variable name looks like a secret
            if self._is_secret_variable(var_name):
                self.findings.append({
                    'type': 'EXPOSED_SECRET_VAR',
                    'severity': 'CRITICAL',
                    'message': f'Potentially sensitive environment variable exposed: {var_name}',
                    'variable_name': var_name,
                    'variable_value': var_value[:50],  # Show first 50 chars
                    'function': function_name
                })
            
            # Check if value looks like a secret
            if self._contains_secret_value(var_value):
                self.findings.append({
                    'type': 'EXPOSED_SECRET_VALUE',
                    'severity': 'CRITICAL',
                    'message': f'Exposed secret in {var_name}',
                    'variable_name': var_name,
                    'variable_value': var_value[:50],
                    'function': function_name
                })
            
            # Check for AWS credentials
            if self._contains_aws_credentials(var_value):
                self.findings.append({
                    'type': 'AWS_CREDENTIALS',
                    'severity': 'CRITICAL',
                    'message': f'AWS credentials found in environment variable: {var_name}',
                    'variable_name': var_name,
                    'variable_value': var_value[:50],
                    'function': function_name
                })
            
            # Check for debug mode enabled
            if var_name.upper() == 'DEBUG_MODE' and var_value.lower() in ['true', '1', 'yes']:
                self.findings.append({
                    'type': 'DEBUG_MODE',
                    'severity': 'HIGH',
                    'message': 'Debug mode is enabled - may leak sensitive information',
                    'variable_name': var_name,
                    'variable_value': var_value,
                    'function': function_name
                })
        
        return self.findings
    
    @staticmethod
    def _is_secret_variable(var_name: str) -> bool:
        """Check if variable name indicates a secret"""
        var_upper = var_name.upper()
        secret_keywords = [
            'PASSWORD', 'SECRET', 'KEY', 'TOKEN', 'API_KEY',
            'ACCESS_KEY', 'PRIVATE_KEY', 'ENCRYPTION', 'CREDENTIAL',
            'AUTH', 'JWT', 'SESSION', 'APIKEY'
        ]
        
        return any(keyword in var_upper for keyword in secret_keywords)
    
    @staticmethod
    def _contains_secret_value(value: str) -> bool:
        """Check if value looks like a secret"""
        if not isinstance(value, str):
            return False
        
        # Check length (secrets are usually long)
        if len(value) > 15:
            # Check for common secret patterns
            if any(char_type in value for char_type in ['/', '+', '=', '_', '-']):
                return True
        
        return False
    
    @staticmethod
    def _contains_aws_credentials(value: str) -> bool:
        """Check if value contains AWS credentials"""
        if not isinstance(value, str):
            return False
        
        # AWS Access Key pattern
        if re.match(r"AKIA[0-9A-Z]{16}", value):
            return True
        
        # AWS Secret Key pattern (40 char base64-like)
        if re.match(r"[A-Za-z0-9/+=]{40}", value):
            return True
        
        return False
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary of environment variable findings"""
        summary = {
            'total': len(self.findings),
            'critical_secrets': len([f for f in self.findings if f['severity'] == 'CRITICAL']),
            'by_type': {}
        }
        
        for finding in self.findings:
            finding_type = finding.get('type', 'UNKNOWN')
            summary['by_type'][finding_type] = summary['by_type'].get(finding_type, 0) + 1
        
        return summary
