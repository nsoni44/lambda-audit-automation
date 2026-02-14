"""
Security scanner module for Lambda code
Detects secrets, hardcoded credentials, and common vulnerabilities
"""
import re
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Any, Optional
import json
import logging

logger = logging.getLogger(__name__)


class ScannerError(Exception):
    """Scanner error"""
    pass


class SecretsPattern:
    """Common patterns for detecting secrets"""
    
    # AWS
    AWS_KEY = r"AKIA[0-9A-Z]{16}"
    AWS_SECRET = r"aws_secret_access_key\s*=\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?"
    
    # API Keys
    API_KEY = r"api[_-]?key\s*[:=]\s*['\"]?[A-Za-z0-9\-_]{20,}['\"]?"
    
    # Database
    DB_PASSWORD = r"(password|passwd|pwd)\s*[:=]\s*['\"]?[^\s'\"]+"
    
    # OAuth tokens
    OAUTH_TOKEN = r"oauth[_-]?token\s*[:=]\s*['\"]?[A-Za-z0-9\-_]{30,}['\"]?"
    
    # Private keys
    PRIVATE_KEY = r"-----BEGIN (RSA|OPENSSH|DSA|EC|PGP) PRIVATE KEY"
    
    # Tokens
    TOKEN = r"(token|secret)\s*[:=]\s*['\"]?[A-Za-z0-9\-_\.]{20,}['\"]?"


class SecurityScanner:
    """Scans Lambda code for security issues"""
    
    def __init__(self, max_file_size_mb: int = 10, timeout_seconds: int = 300):
        """
        Initialize scanner
        
        Args:
            max_file_size_mb: Maximum file size to scan in MB
            timeout_seconds: Timeout for scanning operations
        """
        self.max_file_size = max_file_size_mb * 1024 * 1024
        self.timeout = timeout_seconds
        self.findings = []
    
    def scan_code_directory(self, code_path: str) -> List[Dict[str, Any]]:
        """
        Scan extracted Lambda code directory
        
        Args:
            code_path: Path to extracted Lambda code
            
        Returns:
            List of findings
        """
        self.findings = []
        
        if not os.path.exists(code_path):
            raise ScannerError(f"Code path does not exist: {code_path}")
        
        # Scan for secrets
        self._scan_for_secrets(code_path)
        
        # Scan for common vulnerabilities
        self._scan_vulnerabilities(code_path)
        
        # Scan for hardcoded configs
        self._scan_hardcoded_config(code_path)
        
        return self.findings
    
    def _scan_for_secrets(self, code_path: str):
        """Scan for hardcoded secrets"""
        logger.info("Scanning for secrets...")
        
        patterns = [
            ("AWS Key", SecretsPattern.AWS_KEY),
            ("AWS Secret", SecretsPattern.AWS_SECRET),
            ("API Key", SecretsPattern.API_KEY),
            ("Database Password", SecretsPattern.DB_PASSWORD),
            ("OAuth Token", SecretsPattern.OAUTH_TOKEN),
            ("Private Key", SecretsPattern.PRIVATE_KEY),
            ("Generic Token", SecretsPattern.TOKEN),
        ]
        
        for root, dirs, files in os.walk(code_path):
            # Skip common directories
            dirs[:] = [d for d in dirs if d not in 
                      ['.git', '__pycache__', 'node_modules', '.venv']]
            
            for file in files:
                file_path = os.path.join(root, file)
                
                # Skip binary files
                if self._is_binary_file(file_path):
                    continue
                
                # Check file size
                if os.path.getsize(file_path) > self.max_file_size:
                    continue
                
                try:
                    with open(file_path, 'r', encoding='utf-8', 
                             errors='ignore') as f:
                        content = f.read()
                        
                        for secret_type, pattern in patterns:
                            matches = re.finditer(pattern, content, re.IGNORECASE)
                            
                            for match in matches:
                                line_num = content[:match.start()].count('\n') + 1
                                
                                rel_path = os.path.relpath(file_path, code_path)
                                
                                self.findings.append({
                                    'type': 'SECRET',
                                    'severity': 'CRITICAL',
                                    'secret_type': secret_type,
                                    'file': rel_path,
                                    'line': line_num,
                                    'message': f"Potential {secret_type} found",
                                    'match': match.group()[:50]  # First 50 chars
                                })
                except Exception as e:
                    logger.warning(f"Error scanning {file_path}: {e}")
    
    def _scan_vulnerabilities(self, code_path: str):
        """Scan for common vulnerabilities"""
        logger.info("Scanning for vulnerabilities...")
        
        vulnerability_patterns = [
            ("SQL Injection", r"(SELECT|INSERT|UPDATE|DELETE).*format\(|f\""),
            ("Command Injection", r"(os\.system|subprocess|exec|eval)\("),
            ("Insecure Deserialization", r"(pickle|yaml)\.load\("),
            ("Weak Cryptography", r"(MD5|SHA1|DES)\("),
            ("Hardcoded URL", r"https?://[a-zA-Z0-9\-\.]+"),
        ]
        
        for root, dirs, files in os.walk(code_path):
            dirs[:] = [d for d in dirs if d not in 
                      ['node_modules', '.venv', '__pycache__']]
            
            for file in files:
                if file.endswith(('.py', '.js', '.java', '.go')):
                    file_path = os.path.join(root, file)
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8', 
                                 errors='ignore') as f:
                            content = f.read()
                            
                            for vuln_type, pattern in vulnerability_patterns:
                                matches = re.finditer(pattern, content)
                                
                                for match in matches:
                                    line_num = content[:match.start()].count('\n') + 1
                                    rel_path = os.path.relpath(file_path, code_path)
                                    
                                    self.findings.append({
                                        'type': 'VULNERABILITY',
                                        'severity': 'HIGH',
                                        'vuln_type': vuln_type,
                                        'file': rel_path,
                                        'line': line_num,
                                        'message': f"Potential {vuln_type} vulnerability"
                                    })
                    except Exception as e:
                        logger.warning(f"Error scanning {file_path}: {e}")
    
    def _scan_hardcoded_config(self, code_path: str):
        """Scan for hardcoded configurations"""
        logger.info("Scanning for hardcoded configurations...")
        
        config_patterns = [
            ("Database Host", r"host\s*[:=]\s*['\"]?(localhost|127\.0\.0\.1|db\.example\.com)"),
            ("Debug Mode", r"(DEBUG|debug)\s*[:=]\s*(true|True)"),
            ("Insecure Protocol", r"http://(?!localhost)"),
        ]
        
        for root, dirs, files in os.walk(code_path):
            dirs[:] = [d for d in dirs if d not in ['node_modules', '.venv']]
            
            for file in files:
                if file.endswith(('.py', '.js', '.json', '.yaml')):
                    file_path = os.path.join(root, file)
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8', 
                                 errors='ignore') as f:
                            content = f.read()
                            
                            for config_type, pattern in config_patterns:
                                matches = re.finditer(pattern, content, re.IGNORECASE)
                                
                                for match in matches:
                                    line_num = content[:match.start()].count('\n') + 1
                                    rel_path = os.path.relpath(file_path, code_path)
                                    
                                    self.findings.append({
                                        'type': 'CONFIGURATION',
                                        'severity': 'MEDIUM',
                                        'config_type': config_type,
                                        'file': rel_path,
                                        'line': line_num,
                                        'message': f"Potential hardcoded {config_type}"
                                    })
                    except Exception as e:
                        logger.warning(f"Error scanning {file_path}: {e}")
    
    def scan_with_trufflehog(self, code_path: str, 
                            entropy_threshold: float = 3.0) -> List[Dict[str, Any]]:
        """
        Scan with truffleHog for secrets (requires installation)
        
        Args:
            code_path: Path to scan
            entropy_threshold: Entropy threshold for truffleHog
            
        Returns:
            List of findings from truffleHog
        """
        findings = []
        
        try:
            result = subprocess.run(
                ['trufflehog', 'filesystem', code_path, 
                 '--json', '--entropy'],
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            if result.returncode == 0 and result.stdout:
                for line in result.stdout.split('\n'):
                    if line.strip():
                        try:
                            finding = json.loads(line)
                            findings.append({
                                'type': 'SECRET',
                                'severity': 'CRITICAL',
                                'tool': 'truffleHog',
                                'finding': finding
                            })
                        except json.JSONDecodeError:
                            pass
        except FileNotFoundError:
            logger.warning("truffleHog not installed. Skipping truffleHog scan.")
        except subprocess.TimeoutExpired:
            logger.error("truffleHog scan timed out")
        except Exception as e:
            logger.warning(f"Error running truffleHog: {e}")
        
        return findings
    
    @staticmethod
    def _is_binary_file(file_path: str) -> bool:
        """Check if file is binary"""
        binary_extensions = {'.pyc', '.so', '.o', '.bin', '.exe', '.dll',
                           '.jpg', '.png', '.gif', '.zip', '.tar', '.gz'}
        
        return any(file_path.endswith(ext) for ext in binary_extensions)
