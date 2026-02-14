"""
Findings storage module for Lambda Security Audit
Stores and manages audit findings
"""
import json
import csv
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import logging

logger = logging.getLogger(__name__)


class FindingsManager:
    """Manages audit findings storage and retrieval"""
    
    def __init__(self, findings_dir: str = "findings"):
        """
        Initialize findings manager
        
        Args:
            findings_dir: Directory to store findings
        """
        self.findings_dir = Path(findings_dir)
        self.findings_dir.mkdir(parents=True, exist_ok=True)
        self.all_findings = []
    
    def add_findings(self, findings: List[Dict[str, Any]], 
                    source: str, function_name: str = ""):
        """
        Add findings from a source
        
        Args:
            findings: List of finding dictionaries
            source: Source of findings (e.g., 'secrets', 'iam', 'public_access')
            function_name: Related Lambda function name
        """
        for finding in findings:
            finding['source'] = source
            finding['timestamp'] = datetime.now().isoformat()
            if function_name:
                finding['function'] = function_name
            self.all_findings.append(finding)
    
    def save_json_report(self, function_name: str = None) -> str:
        """
        Save findings as JSON
        
        Args:
            function_name: Optional specific function name
            
        Returns:
            Path to saved file
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"audit_findings_{timestamp}.json"
        
        findings_to_save = self.all_findings
        if function_name:
            findings_to_save = [f for f in self.all_findings 
                               if f.get('function') == function_name]
            filename = f"audit_{function_name}_{timestamp}.json"
        
        filepath = self.findings_dir / filename
        
        with open(filepath, 'w') as f:
            json.dump(findings_to_save, f, indent=2, default=str)
        
        logger.info(f"Saved JSON findings to {filepath}")
        return str(filepath)
    
    def save_csv_report(self, function_name: str = None) -> str:
        """
        Save findings as CSV
        
        Args:
            function_name: Optional specific function name
            
        Returns:
            Path to saved file
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"audit_findings_{timestamp}.csv"
        
        findings_to_save = self.all_findings
        if function_name:
            findings_to_save = [f for f in self.all_findings 
                               if f.get('function') == function_name]
            filename = f"audit_{function_name}_{timestamp}.csv"
        
        filepath = self.findings_dir / filename
        
        if not findings_to_save:
            logger.warning("No findings to save")
            return ""
        
        # Get all unique keys from findings
        fieldnames = set()
        for finding in findings_to_save:
            fieldnames.update(finding.keys())
        fieldnames = sorted(list(fieldnames))
        
        with open(filepath, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for finding in findings_to_save:
                writer.writerow(finding)
        
        logger.info(f"Saved CSV findings to {filepath}")
        return str(filepath)
    
    def get_summary(self) -> Dict[str, Any]:
        """
        Get summary of findings
        
        Returns:
            Summary statistics
        """
        summary = {
            'total_findings': len(self.all_findings),
            'by_severity': {},
            'by_type': {},
            'by_source': {}
        }
        
        for finding in self.all_findings:
            # Count by severity
            severity = finding.get('severity', 'UNKNOWN')
            summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1
            
            # Count by type
            finding_type = finding.get('type', 'UNKNOWN')
            summary['by_type'][finding_type] = summary['by_type'].get(finding_type, 0) + 1
            
            # Count by source
            source = finding.get('source', 'UNKNOWN')
            summary['by_source'][source] = summary['by_source'].get(source, 0) + 1
        
        return summary
    
    def get_critical_findings(self) -> List[Dict[str, Any]]:
        """Get only critical findings"""
        return [f for f in self.all_findings 
                if f.get('severity') in ['CRITICAL', 'HIGH']]
    
    def print_summary(self):
        """Print findings summary to console"""
        summary = self.get_summary()
        
        print("\n" + "="*50)
        print("AUDIT FINDINGS SUMMARY")
        print("="*50)
        print(f"Total Findings: {summary['total_findings']}")
        
        print("\nBy Severity:")
        for severity, count in sorted(summary['by_severity'].items(), 
                                     key=lambda x: x[1], reverse=True):
            print(f"  {severity}: {count}")
        
        print("\nBy Type:")
        for type_, count in sorted(summary['by_type'].items(), 
                                  key=lambda x: x[1], reverse=True):
            print(f"  {type_}: {count}")
        
        print("\nBy Source:")
        for source, count in sorted(summary['by_source'].items(), 
                                   key=lambda x: x[1], reverse=True):
            print(f"  {source}: {count}")
        
        critical = self.get_critical_findings()
        print(f"\n⚠️  CRITICAL FINDINGS: {len(critical)}")
        for finding in critical[:10]:  # Show first 10
            print(f"  - {finding.get('type')}: {finding.get('message')}")
        
        print("="*50 + "\n")
    
    def export_html_report(self, function_name: str = None) -> str:
        """
        Export findings as HTML report
        
        Args:
            function_name: Optional specific function name
            
        Returns:
            Path to saved file
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"audit_report_{timestamp}.html"
        
        findings_to_save = self.all_findings
        if function_name:
            findings_to_save = [f for f in self.all_findings 
                               if f.get('function') == function_name]
            filename = f"audit_{function_name}_{timestamp}.html"
        
        filepath = self.findings_dir / filename
        
        summary = self.get_summary()
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Lambda Security Audit Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #333; }}
                .summary {{ background: #f0f0f0; padding: 15px; border-radius: 5px; margin: 20px 0; }}
                .finding {{ 
                    border-left: 4px solid #ccc;
                    padding: 10px;
                    margin: 10px 0;
                    background: #fafafa;
                }}
                .finding.CRITICAL {{ border-left-color: #d32f2f; }}
                .finding.HIGH {{ border-left-color: #f57c00; }}
                .finding.MEDIUM {{ border-left-color: #fbc02d; }}
                .finding.LOW {{ border-left-color: #388e3c; }}
                .severity {{ 
                    display: inline-block;
                    padding: 3px 8px;
                    border-radius: 3px;
                    font-weight: bold;
                    color: white;
                    margin-right: 10px;
                }}
                .CRITICAL {{ background: #d32f2f; }}
                .HIGH {{ background: #f57c00; }}
                .MEDIUM {{ background: #fbc02d; color: #333; }}
                .LOW {{ background: #388e3c; }}
                table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
                th, td {{ border: 1px solid #ddd; padding: 10px; text-align: left; }}
                th {{ background-color: #333; color: white; }}
                tr:nth-child(even) {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <h1>Lambda Security Audit Report</h1>
            <p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
            
            <div class="summary">
                <h2>Summary</h2>
                <p><strong>Total Findings:</strong> {summary['total_findings']}</p>
                <p><strong>Critical/High:</strong> {len(self.get_critical_findings())}</p>
            </div>
            
            <h2>Findings Details</h2>
            <table>
                <tr>
                    <th>Type</th>
                    <th>Severity</th>
                    <th>Message</th>
                    <th>Source</th>
                    <th>Function</th>
                </tr>
        """
        
        for finding in findings_to_save:
            severity = finding.get('severity', 'UNKNOWN')
            html_content += f"""
                <tr>
                    <td>{finding.get('type', '')}</td>
                    <td><span class="severity {severity}">{severity}</span></td>
                    <td>{finding.get('message', '')}</td>
                    <td>{finding.get('source', '')}</td>
                    <td>{finding.get('function', '')}</td>
                </tr>
            """
        
        html_content += """
            </table>
        </body>
        </html>
        """
        
        with open(filepath, 'w') as f:
            f.write(html_content)
        
        logger.info(f"Saved HTML report to {filepath}")
        return str(filepath)
