"""
Main orchestrator for Lambda Security Audit Automation
Coordinates the entire audit workflow
"""
import os
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Dict, List, Any
import logging

from modules.aws_client import AWSClient, AWSClientError
from modules.scanner import SecurityScanner, ScannerError
from modules.iam_analyzer import IAMAnalyzer
from modules.env_scanner import EnvironmentVariableScanner
from modules.findings import FindingsManager
from config.config import ConfigManager, ConfigError

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class AuditOrchestrator:
    """Orchestrates the complete Lambda security audit workflow"""
    
    def __init__(self, config_path: str = None):
        """
        Initialize audit orchestrator
        
        Args:
            config_path: Path to credentials.json file
        """
        try:
            self.config_manager = ConfigManager(config_path)
            aws_config = self.config_manager.get_aws_config()
            
            self.aws_client = AWSClient(
                region=aws_config['region'],
                access_key=aws_config['access_key_id'],
                secret_key=aws_config['secret_access_key']
            )
            
            tool_config = self.config_manager.get_tool_config()
            self.scanner = SecurityScanner(
                max_file_size_mb=tool_config.get('max_file_size_mb', 10),
                timeout_seconds=tool_config.get('timeout_seconds', 300)
            )
            
            self.iam_analyzer = IAMAnalyzer()
            self.env_scanner = EnvironmentVariableScanner()
            self.findings_manager = FindingsManager()
            self.audit_config = self.config_manager.get_audit_config()
            
            logger.info("Audit Orchestrator initialized successfully")
            
        except (ConfigError, AWSClientError) as e:
            logger.error(f"Failed to initialize orchestrator: {e}")
            raise
    
    def run_full_audit(self, function_name: str = None) -> Dict[str, Any]:
        """
        Run complete security audit on Lambda function(s)
        
        Args:
            function_name: Optional specific function name. 
                          If None, audits all functions.
            
        Returns:
            Audit results
        """
        logger.info("Starting Lambda Security Audit...")
        print("\n" + "="*60)
        print("LAMBDA SECURITY AUDIT")
        print("="*60)
        
        results = {
            'functions_audited': 0,
            'total_findings': 0,
            'errors': []
        }
        
        try:
            # Step 1: List Lambda functions
            logger.info("Step 1: Discovering Lambda functions...")
            functions = self.aws_client.list_lambda_functions()
            
            if function_name:
                functions = [f for f in functions 
                           if f['FunctionName'] == function_name]
            
            logger.info(f"Found {len(functions)} function(s) to audit")
            
            # Step 2: Audit each function
            for function in functions:
                try:
                    self._audit_function(function)
                    results['functions_audited'] += 1
                except Exception as e:
                    error_msg = f"Error auditing {function['FunctionName']}: {e}"
                    logger.error(error_msg)
                    results['errors'].append(error_msg)
            
            # Step 3: Generate reports
            logger.info("Step 3: Generating reports...")
            self._generate_reports()
            
            results['total_findings'] = len(self.findings_manager.all_findings)
            
            logger.info("Audit completed successfully")
            
        except Exception as e:
            logger.error(f"Audit failed: {e}")
            results['errors'].append(str(e))
        
        return results
    
    def _audit_function(self, function: Dict[str, Any]):
        """
        Audit a single Lambda function
        
        Args:
            function: Lambda function metadata
        """
        function_name = function['FunctionName']
        logger.info(f"\n{'='*40}")
        logger.info(f"Auditing: {function_name}")
        logger.info(f"{'='*40}")
        
        # Get function details
        logger.info("Fetching function configuration...")
        func_details = self.aws_client.get_lambda_function(function_name)
        
        # Step 1: Download and scan code
        if self.audit_config.get('scan_for_secrets', True):
            self._scan_function_code(function_name, func_details)
        
        # Step 1.5: Scan environment variables
        self._scan_environment_variables(function_name, func_details)
        
        # Step 2: Analyze IAM role
        if self.audit_config.get('check_iam_permissions', True):
            self._analyze_iam_role(function_name, func_details)
        
        # Step 3: Check public access
        if self.audit_config.get('check_public_access', True):
            self._check_public_access(function_name)
    
    def _scan_function_code(self, function_name: str, 
                           func_details: Dict[str, Any]):
        """Scan Lambda function code for secrets"""
        logger.info("STEP 1: Scanning code for secrets...")
        
        try:
            # Download code
            logger.info("Downloading Lambda function code...")
            code_bytes = self.aws_client.get_lambda_function_code(function_name)
            
            # Extract to temp directory
            with tempfile.TemporaryDirectory() as temp_dir:
                zip_path = os.path.join(temp_dir, 'lambda.zip')
                extract_path = os.path.join(temp_dir, 'extracted')
                
                # Save zip file
                with open(zip_path, 'wb') as f:
                    f.write(code_bytes)
                
                # Extract
                os.makedirs(extract_path, exist_ok=True)
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    zip_ref.extractall(extract_path)
                
                # Scan
                logger.info("Scanning for secrets...")
                findings = self.scanner.scan_code_directory(extract_path)
                
                if findings:
                    logger.warning(f"Found {len(findings)} potential security issues")
                    self.findings_manager.add_findings(findings, 'code_scan', 
                                                      function_name)
                else:
                    logger.info("No secrets detected in code")
        
        except Exception as e:
            logger.error(f"Error scanning code: {e}")
            self.findings_manager.add_findings([{
                'type': 'SCAN_ERROR',
                'severity': 'LOW',
                'message': f'Failed to scan code: {str(e)}'
            }], 'code_scan_error', function_name)
    
    def _scan_environment_variables(self, function_name: str,
                                   func_details: Dict[str, Any]):
        """Scan environment variables for exposed secrets"""
        logger.info("STEP 1.5: Scanning environment variables...")
        
        try:
            config = func_details.get('Configuration', {})
            env_vars = config.get('Environment', {}).get('Variables', {})
            
            if not env_vars:
                logger.info("No environment variables found")
                return
            
            logger.info(f"Found {len(env_vars)} environment variable(s)")
            
            # Scan
            findings = self.env_scanner.scan_environment_variables(
                function_name, env_vars
            )
            
            if findings:
                logger.warning(f"Found {len(findings)} environment variable issues")
                self.findings_manager.add_findings(findings, 'env_scan',
                                                  function_name)
                
                # Also log summary
                summary = self.env_scanner.get_summary()
                if summary['critical_secrets'] > 0:
                    logger.error(f"⚠️  CRITICAL: {summary['critical_secrets']} exposed secrets found!")
            else:
                logger.info("No exposed secrets in environment variables")
        
        except Exception as e:
            logger.error(f"Error scanning environment variables: {e}")
    
    def _analyze_iam_role(self, function_name: str, 
                         func_details: Dict[str, Any]):
        """Analyze IAM role and permissions"""
        logger.info("STEP 2: Analyzing IAM role and permissions...")
        
        try:
            config = func_details.get('Configuration', {})
            role_arn = config.get('Role')
            
            if not role_arn:
                logger.warning("No IAM role found for function")
                return
            
            # Extract role name from ARN
            role_name = role_arn.split('/')[-1]
            
            # Get role and policies
            logger.info(f"Fetching policies for role: {role_name}")
            policies = self.aws_client.get_role_policies(role_name)
            
            # Analyze
            findings = self.iam_analyzer.analyze_lambda_role(
                function_name, role_arn, policies
            )
            
            if findings:
                logger.warning(f"Found {len(findings)} IAM permission issues")
                self.findings_manager.add_findings(findings, 'iam_analysis', 
                                                  function_name)
            else:
                logger.info("No critical IAM permission issues detected")
        
        except Exception as e:
            logger.error(f"Error analyzing IAM role: {e}")
            self.findings_manager.add_findings([{
                'type': 'IAM_ERROR',
                'severity': 'LOW',
                'message': f'Failed to analyze IAM: {str(e)}'
            }], 'iam_error', function_name)
    
    def _check_public_access(self, function_name: str):
        """Check if Lambda is publicly accessible"""
        logger.info("STEP 3: Checking public access...")
        
        try:
            is_public = self.aws_client.check_public_access(function_name)
            
            if is_public:
                logger.warning(f"⚠️  {function_name} is PUBLICLY ACCESSIBLE")
                self.findings_manager.add_findings([{
                    'type': 'PUBLIC_ACCESS',
                    'severity': 'CRITICAL',
                    'message': f'Lambda function {function_name} is publicly accessible',
                    'function': function_name
                }], 'public_access', function_name)
            else:
                logger.info("Function is not publicly accessible")
        
        except Exception as e:
            logger.error(f"Error checking public access: {e}")
    
    def _generate_reports(self):
        """Generate audit reports"""
        logger.info("Generating reports...")
        
        # Print summary to console
        self.findings_manager.print_summary()
        
        # Save files
        json_report = self.findings_manager.save_json_report()
        csv_report = self.findings_manager.save_csv_report()
        html_report = self.findings_manager.export_html_report()
        
        logger.info(f"Reports saved to findings/ directory:")
        logger.info(f"  - JSON: {Path(json_report).name}")
        logger.info(f"  - CSV:  {Path(csv_report).name}")
        logger.info(f"  - HTML: {Path(html_report).name}")
        
        print(f"\n📊 Reports saved to: findings/")
        print(f"   - {Path(json_report).name}")
        print(f"   - {Path(csv_report).name}")
        print(f"   - {Path(html_report).name}")


def main():
    """Main entry point"""
    # Check command line arguments
    config_path = None
    function_name = None
    
    if len(sys.argv) > 1:
        config_path = sys.argv[1]
    
    if len(sys.argv) > 2:
        function_name = sys.argv[2]
    
    try:
        orchestrator = AuditOrchestrator(config_path)
        results = orchestrator.run_full_audit(function_name)
        
        if results['errors']:
            print(f"\n⚠️  Audit completed with {len(results['errors'])} error(s)")
            sys.exit(1)
        else:
            print(f"\n✅ Audit completed successfully")
            print(f"   Functions audited: {results['functions_audited']}")
            print(f"   Total findings: {results['total_findings']}")
            sys.exit(0)
    
    except Exception as e:
        logger.error(f"Failed to run audit: {e}")
        print(f"\n❌ Audit failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
