"""
Configuration handler for Lambda Security Audit Automation
Loads AWS credentials and audit settings from JSON file
"""
import json
import os
from typing import Dict, Any
from pathlib import Path


class ConfigError(Exception):
    """Configuration error"""
    pass


class ConfigManager:
    """Manages configuration from JSON file"""
    
    def __init__(self, config_path: str = None):
        """
        Initialize config manager
        
        Args:
            config_path: Path to credentials.json file. 
                        Defaults to ./config/credentials.json
        """
        if config_path is None:
            config_path = os.path.join(
                os.path.dirname(__file__), 
                "credentials.json"
            )
        
        self.config_path = config_path
        self.config = None
        self._load_config()
    
    def _load_config(self):
        """Load configuration from JSON file"""
        if not os.path.exists(self.config_path):
            raise ConfigError(
                f"Configuration file not found: {self.config_path}\n"
                f"Please copy credentials.json.example to credentials.json "
                f"and fill in your AWS credentials"
            )
        
        try:
            with open(self.config_path, 'r') as f:
                self.config = json.load(f)
        except json.JSONDecodeError as e:
            raise ConfigError(f"Invalid JSON in config file: {e}")
        except Exception as e:
            raise ConfigError(f"Error reading config file: {e}")
        
        self._validate_config()
    
    def _validate_config(self):
        """Validate required configuration fields"""
        required_aws_fields = ["region", "access_key_id", "secret_access_key"]
        
        if "aws" not in self.config:
            raise ConfigError("Missing 'aws' section in credentials.json")
        
        aws_config = self.config["aws"]
        for field in required_aws_fields:
            if field not in aws_config or not aws_config[field]:
                raise ConfigError(
                    f"Missing or empty AWS field: {field}"
                )
        
        # Check if using example values
        if aws_config["access_key_id"].startswith("AKIA"):
            if aws_config["access_key_id"] == "AKIAIOSFODNN7EXAMPLE":
                raise ConfigError(
                    "You are using example AWS credentials. "
                    "Please update credentials.json with real credentials."
                )
    
    def get_aws_config(self) -> Dict[str, str]:
        """Get AWS configuration"""
        return self.config.get("aws", {})
    
    def get_audit_config(self) -> Dict[str, bool]:
        """Get audit settings"""
        return self.config.get("audit", {
            "scan_for_secrets": True,
            "static_analysis": True,
            "check_iam_permissions": True,
            "check_public_access": True,
            "include_dependencies": False
        })
    
    def get_tool_config(self) -> Dict[str, Any]:
        """Get tool-specific settings"""
        return self.config.get("tools", {
            "trufflehog_entropy_threshold": 3.0,
            "max_file_size_mb": 10,
            "timeout_seconds": 300
        })
    
    def get_config(self) -> Dict[str, Any]:
        """Get entire configuration"""
        return self.config
