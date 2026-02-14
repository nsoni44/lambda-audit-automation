# Lambda Security Audit Automation

Comprehensive security audit tool for AWS Lambda functions. Automatically scans all Lambda functions in your account for secrets, vulnerabilities, IAM misconfigurations, and dangerous permissions.

**Similar to CloudFox but specifically built for Lambda security audits.**

## ✅ What It Audits

| Category | Detection |
|----------|-----------|
| **🔐 Secrets** | Hardcoded AWS keys, API keys, passwords, tokens in code & environment variables |
| **⚠️ Vulnerabilities** | SQL injection, command injection, hardcoded configs, debug mode enabled |
| **🚨 IAM Issues** | Overprivileged roles, s3:*, iam:*, wildcard permissions, wildcard resources |
| **🌐 Public Access** | Publicly accessible Lambda functions, unauthenticated endpoints |
| **📊 Environment Variables** | Exposed secrets in Lambda environment variables (NEW!) |

## 📊 Reporting

- **JSON**: Full technical details for integration & automation
- **CSV**: Spreadsheet format for analysis & tracking
- **HTML**: Visual report for presentations & compliance

## 📁 Project Structure

```
lambda_audit_automation/
├── config/
│   ├── credentials.json.example    # Template (COPY THIS)
│   ├── credentials.json            # Your AWS credentials (ignored by git)
│   └── config.py                   # Configuration loader
│
├── modules/
│   ├── aws_client.py              # AWS boto3 wrapper
│   ├── scanner.py                 # Code vulnerability scanner
│   ├── iam_analyzer.py            # IAM policy analyzer
│   ├── env_scanner.py             # Environment variable scanner (NEW!)
│   ├── findings.py                # Findings storage & reporting
│   └── __init__.py
│
├── findings/                       # Generated reports
│   └── archive/                    # Old reports
│
├── main.py                        # Main audit orchestrator
├── requirements.txt               # Python dependencies
├── .gitignore                     # Prevents credential leakage
├── README.md                      # This file
└── QUICKSTART.md                  # Setup guide
```

## 🚀 Quick Start (5 minutes)

### Step 1: Setup
```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate            # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Copy credentials template
cp config/credentials.json.example config/credentials.json
```

### Step 2: Configure AWS Credentials
```bash
# Edit with your AWS credentials
nano config/credentials.json
```

**Minimal IAM permissions required:**
```json
{
  "Effect": "Allow",
  "Action": [
    "lambda:GetFunction",
    "lambda:ListFunctions",
    "lambda:GetPolicy",
    "iam:GetRole",
    "iam:ListRolePolicies",
    "iam:GetRolePolicy",
    "iam:ListAttachedRolePolicies"
  ],
  "Resource": "*"
}
```

### Step 3: Run Audit
```bash
# Audit all Lambda functions
python3 main.py

# Or audit specific function
python3 main.py config/credentials.json my-function-name
```

## 📊 Reports

Reports are automatically generated in `findings/` directory:

1. **audit_findings_*.json** - Full technical details
2. **audit_findings_*.csv** - Spreadsheet format
3. **audit_report_*.html** - Visual HTML report

Old reports are automatically archived in `findings/archive/`

### Sample Output

```
============================================================
LAMBDA SECURITY AUDIT
============================================================

========================================
Auditing: my-lambda-function
========================================

STEP 1: Scanning code for secrets...
Downloading Lambda function code...
Scanning for secrets...
⚠️  Found 2 potential security issues in code

STEP 2: Analyzing IAM role and permissions...
Fetching policies for role: lambda-execution-role
⚠️  Found 3 IAM permission issues

STEP 3: Checking public access...

==================================================
AUDIT FINDINGS SUMMARY
==================================================
Total Findings: 5

By Severity:
  HIGH: 3
  MEDIUM: 2

By Type:
  OVERPRIVILEGED: 2
  SECRET: 2
  WILDCARD_RESOURCE: 1

⚠️  CRITICAL FINDINGS: 3
  - SECRET: Potential AWS Key found
  - OVERPRIVILEGED: High-risk permission: s3:*
  - WILDCARD_RESOURCE: Wildcard resource (*)
==================================================

📊 Reports saved to: findings/
   - audit_findings_20240214_120530.json
   - audit_findings_20240214_120530.csv
   - audit_report_20240214_120530.html
```

## Reports

Audit generates three types of reports in the `findings/` directory:

### 1. JSON Report (`audit_findings_*.json`)
Complete findings with all details. Suitable for programmatic processing.

### 2. CSV Report (`audit_findings_*.csv`)
Tabular format for Excel/spreadsheet analysis.

### 3. HTML Report (`audit_report_*.html`)
Formatted visual report for presentations.

## AWS Credentials Security

⚠️ **Important Security Notes:**

1. **Never** commit `config/credentials.json` to version control
2. Add `config/credentials.json` to `.gitignore`:
   ```
   config/credentials.json
   ```

3. Use IAM credentials with **minimum required permissions**:
   ```json
   {
       "Version": "2012-10-17",
       "Statement": [
           {
               "Effect": "Allow",
               "Action": [
                   "lambda:GetFunction",
                   "lambda:ListFunctions",
                   "lambda:GetPolicy",
                   "iam:GetRole",
                   "iam:ListRolePolicies",
                   "iam:GetRolePolicy",
                   "iam:ListAttachedRolePolicies"
               ],
               "Resource": "*"
           }
       ]
   }
   ```

4. Consider using AWS temporary credentials (STS)

## Optional Tools

### Install truffleHog for Enhanced Secret Detection
```bash
pip install truffleHog

# or
brew install truffleHog  # macOS
```

Then enable in `credentials.json`:
```json
{
  "audit": {
    "scan_for_secrets": true
  }
}
```

## Troubleshooting

### `Configuration file not found`
- Copy `config/credentials.json.example` to `config/credentials.json`
- Fill in your AWS credentials

### `Failed to initialize AWS client`
- Check AWS credentials in `config/credentials.json`
- Verify IAM permissions
- Verify AWS region is correct

### `Failed to download Lambda code`
- Check Lambda execution IAM role has S3 access
- Verify Lambda code exists and is not too large (>50MB)

### `No Lambda functions found`
- Verify AWS region in config matches where functions exist
- Check IAM credentials have `lambda:ListFunctions` permission

## Audit Workflow

The audit follows this attack path flowchart:

```
1. Configure AWS Credentials (from JSON)
   ↓
2. List Lambda Functions (aws lambda list-functions)
   ↓
3. For each function:
   ├─ Download Code (GetFunction/S3)
   ├─ Extract & Scan for Secrets
   ├─ Analyze IAM Role & Policies
   └─ Check Public Access
   ↓
4. Document Findings
   ├─ JSON Report
   ├─ CSV Report
   └─ HTML Report
   ↓
5. Recommend Remediation
```

## Remediation Examples

### Issue: Hardcoded Secrets
```python
# ❌ BAD
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
db_password = "password123"

# ✅ GOOD
import os
AWS_KEY = os.getenv('AWS_KEY')
db_password = os.getenv('DB_PASSWORD')
```

### Issue: Overprivileged IAM Role
```json
// ❌ BAD - Too permissive
{
  "Effect": "Allow",
  "Action": "s3:*",
  "Resource": "*"
}

// ✅ GOOD - Least privilege
{
  "Effect": "Allow",
  "Action": [
    "s3:GetObject",
    "s3:PutObject"
  ],
  "Resource": "arn:aws:s3:::my-bucket/lambda-data/*"
}
```

### Issue: Public Access
```python
# Remove public access from Lambda policy
# Use API Gateway with IAM authentication instead
# Or restrict Principal to specific AWS accounts
```

## Contributing

Feel free to extend this tool with:
- Additional secret patterns
- More vulnerability detections
- DynamoDB findings storage
- Slack/email notifications
- CloudWatch integration

## License

MIT License - See LICENSE file

## Support

For issues, suggestions, or improvements:
1. Check the Troubleshooting section
2. Review AWS IAM permissions
3. Check application logs for detailed error messages

---

**Happy auditing! 🔐**
