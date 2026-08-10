# GitHub Security Auditor - Quick Start Guide

## 30-Second Setup

### 1. Get GitHub Token
1. Go to https://github.com/settings/tokens
2. Click "Generate new token (classic)"
3. Set scopes: `repo`, `admin:org_hook`, `read:org`
4. Copy the token

### 2. Clone and Setup
```bash
git clone <repo-url> github-auditor
cd github-auditor
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Run Audit (Choose One)

**CLI Mode - Generate Report:**
```bash
python github_auditor.py -t YOUR_TOKEN -o YOUR_ORG
# Reports saved to current directory
```

**Web Dashboard Mode - Interactive:**
```bash
python github_auditor.py -t YOUR_TOKEN -o YOUR_ORG --web
# Visit http://localhost:5000
```

## What You'll Get

✅ **HTML Report** - Beautiful visual dashboard with:
- Compliance score (0-100%)
- Risk assessment (LOW/MEDIUM/HIGH/CRITICAL)
- Per-repository findings
- Actionable recommendations
- Download-ready report

✅ **JSON Export** - Machine-readable results for:
- CI/CD integration
- Custom dashboards
- Automation workflows
- Historical tracking

## Example Output

```
🔍 Starting GitHub security audit for organization: my-company
📋 Running organization-level checks...
✅ Organization Settings: 4/5
📦 Scanning repositories...
   [1/24] Checking api-service... ✅ (18/18)
   [2/24] Checking web-app... ⚠️ (16/18)

======================================================================
📊 AUDIT SUMMARY
======================================================================
Compliance Score: 82.5%
Risk Level: 🟡 MEDIUM RISK
Passed: 412/500
======================================================================
📄 JSON Report: github_audit_20240115_103045.json
📊 HTML Report: github_audit_20240115_103045.html
```

## Environment Variables (Optional)

Create `.env` file for easy reuse:
```
GITHUB_TOKEN=ghp_your_token_here
GITHUB_ORG=your-organization
```

Then run without arguments:
```bash
python github_auditor.py
```

## Troubleshooting

**"Bad credentials"** - Token is invalid or expired
- Regenerate token at https://github.com/settings/tokens
- Verify scopes include `repo` and `admin:org_hook`

**"Rate limit exceeded"** - Too many API calls
- Authenticated requests: 5,000/hour
- Wait 1 hour or use different token

**"Permission denied"** - Token lacks access
- Ensure token has `admin:org_hook` scope
- Verify you're owner of the organization

## Next Steps

1. **Review the HTML report** - Check compliance score and findings
2. **Prioritize fixes** - Address CRITICAL and HIGH risk items first
3. **Share results** - Email HTML report to team leads
4. **Track progress** - Re-run audits monthly to track improvements

## Help & Support

```bash
# View all options
python github_auditor.py --help

# Verbose output for debugging
python github_auditor.py -t TOKEN -o ORG -v

# Custom output directory
python github_auditor.py -t TOKEN -o ORG -d ./reports
```

## What Gets Checked? (21 Checks)

**Organization Level:**
- ✅ 2FA enforcement
- ✅ SSO configuration
- ✅ Access control
- ✅ Audit logging
- ✅ Member privileges

**Per Repository:**
- ✅ Repository visibility (public/private)
- ✅ Branch protection
- ✅ PR review requirements
- ✅ Status checks
- ✅ Commit signing
- ✅ Secrets scanning
- ✅ Dependency alerts
- ✅ Stale review dismissal
- ✅ Admin enforcement
- ✅ Forking control
- ✅ SECURITY.md file
- ✅ CODEOWNERS file
- ✅ .gitignore configuration
- ✅ Wiki/Pages settings
- ✅ Issues enabled
- ✅ Collaborator audit

## Scoring Guide

| Score | Risk Level | Action |
|-------|-----------|--------|
| 90-100% | 🟢 LOW | Maintain current practices |
| 70-89% | 🟡 MEDIUM | Address gaps progressively |
| 50-69% | 🟠 HIGH | Implement critical fixes |
| 0-49% | 🔴 CRITICAL | Immediate action required |

---

**Need more help?** See README.md for detailed documentation.
