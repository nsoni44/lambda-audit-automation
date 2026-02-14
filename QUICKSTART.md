# Quick Start Guide

## Installation (5 minutes)

### Step 1: Copy Credentials Template
```bash
cp config/credentials.json.example config/credentials.json
```

### Step 2: Edit Credentials
Edit `config/credentials.json` and add your AWS credentials:
```json
{
  "aws": {
    "region": "us-east-1",
    "access_key_id": "YOUR_AWS_ACCESS_KEY",
    "secret_access_key": "YOUR_AWS_SECRET_KEY",
    "account_id": "123456789012"
  },
  ...
}
```

### Step 3: Create Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
```

### Step 4: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 5: Run Audit
```bash
python main.py
```

---

## Usage

### Audit All Functions
```bash
python main.py
```

### Audit Specific Function
```bash
python main.py config/credentials.json my-function-name
```

### Using the Setup Script (macOS/Linux)
```bash
chmod +x run_audit.sh
./run_audit.sh
```

---

## What Gets Audited

✅ **Code Scanning**
- AWS credentials and API keys
- Passwords and tokens
- Private keys
- SQL injection vulnerabilities
- Command injection vulnerabilities

✅ **IAM Analysis**
- Overprivileged permissions
- Dangerous actions (s3:*, iam:*, etc.)
- Wildcard resources
- Managed policy review

✅ **Public Access**
- Resource policy review
- Wildcard principals
- Public Lambda detection

---

## Output Files

Reports are saved in the `findings/` directory:

1. **audit_findings_*.json** - Full details in JSON format
2. **audit_findings_*.csv** - Spreadsheet-friendly format
3. **audit_report_*.html** - Visual HTML report

---

## Audit Workflow

```
START: Configure AWS Credentials (from JSON)
  ↓
DISCOVERY: List all Lambda functions
  ↓
FOR EACH FUNCTION:
  ├─ Download Lambda code (GetFunction)
  ├─ Extract & Scan for secrets
  ├─ Analyze IAM role permissions
  └─ Check public access
  ↓
FINDINGS: Collect all issues by severity
  ├─ CRITICAL: Immediate action needed
  ├─ HIGH: Should fix soon
  ├─ MEDIUM: Address opportunistically
  └─ LOW: Monitor
  ↓
REPORTING: Generate JSON/CSV/HTML reports
  ↓
END: Summary with recommended remediations
```

---

## Security Best Practices

⚠️ **Important:**

1. **Never commit credentials** - Add to .gitignore:
   ```
   config/credentials.json
   ```

2. **Use minimal IAM permissions** - Create a dedicated audit user with only:
   - lambda:GetFunction
   - lambda:ListFunctions
   - lambda:GetPolicy
   - iam:GetRole
   - iam:ListRolePolicies
   - iam:GetRolePolicy
   - iam:ListAttachedRolePolicies

3. **Use temporary credentials** - Consider using AWS STS tokens instead

4. **Rotate credentials regularly** - Change AWS keys periodically

---

## Troubleshooting

### Error: "Configuration file not found"
```
Solution: Copy config/credentials.json.example to config/credentials.json
```

### Error: "Invalid AWS credentials"
```
Solution: Verify credentials in config/credentials.json
         Check your AWS access key and secret key
         Verify IAM user has required permissions
```

### Error: "No Lambda functions found"
```
Solution: Verify the AWS region in config/credentials.json
         Check IAM permissions include lambda:ListFunctions
         Verify Lambda functions exist in that region
```

### Code download fails
```
Solution: Check Lambda execution role has S3 access
         Verify Lambda code size is under 50MB
         Check network access to S3
```

---

## Configuration Options

Edit `config/credentials.json` to control audit behavior:

```json
{
  "audit": {
    "scan_for_secrets": true,           // Scan code for credentials
    "static_analysis": true,             // Check for vulnerabilities
    "check_iam_permissions": true,       // Analyze IAM policies
    "check_public_access": true,         // Check public access
    "include_dependencies": false        // Include node_modules, etc
  },
  "tools": {
    "trufflehog_entropy_threshold": 3.0, // Secret entropy threshold
    "max_file_size_mb": 10,              // Max file size to scan
    "timeout_seconds": 300               // Timeout for operations
  }
}
```

---

## Example Findings

### Finding: Hardcoded AWS Credentials
**Severity:** CRITICAL
**Action:** Move to environment variables or AWS Secrets Manager

### Finding: Overprivileged IAM Role
**Severity:** HIGH
**Action:** Restrict permissions to minimum required (least privilege)

### Finding: Publicly Accessible Lambda
**Severity:** CRITICAL
**Action:** Remove public access or add authentication

---

## Next Steps

1. ✅ Review the generated reports
2. ✅ Prioritize findings by severity
3. ✅ Create remediation plan
4. ✅ Fix critical/high issues
5. ✅ Re-run audit to verify fixes
6. ✅ Schedule regular audits (weekly/monthly)

---

## Need Help?

- Check README.md for detailed documentation
- Review AWS IAM permissions requirements
- Check application logs for error details

---

**Happy auditing! 🔐**
