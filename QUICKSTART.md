# GitHub Security Auditor - Quick Start Guide

## 30-Second Setup

### 1. Get a GitHub Token

Use a **fine-grained personal access token** with **read-only** access to:
Metadata, Administration, Contents, Dependabot alerts, Secret scanning alerts.

1. Go to https://github.com/settings/tokens?type=beta
2. Generate a fine-grained token scoped to the organization or repositories
   you want to audit
3. Copy the token

The tool never writes anything. Do not grant `repo` on a classic token — it
confers full write access to every repository, which a read-only auditor has
no use for.

### 2. Clone and Setup

```bash
git clone <repo-url> github-auditor
cd github-auditor
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Run an Audit

**CLI Mode - Generate a Report:**
```bash
export GITHUB_TOKEN=ghp_your_token_here
python3 github_auditor.py --org YOUR_ORG
# Reports saved to audit_results/
```

**Web Dashboard Mode - Interactive:**
```bash
python3 app.py
# Visit http://127.0.0.1:5000 and paste the token into the form
```

There is no `--token` flag on the CLI: a token accepted as a command-line
argument lands in shell history and in `ps aux` for any other user on the
machine. Use `GITHUB_TOKEN`, or `--token-stdin` to pipe one in.

## What You'll Get

✅ **HTML Report** with:
- Compliance score and coverage (how much of the control set was actually scored)
- Risk assessment (LOW / MEDIUM / HIGH / CRITICAL)
- Per-repository findings, each mapped to SOC 2, NIST, ISO/IEC 27001 and CIS Controls
- An access inventory: every principal with repository access and what their
  permission actually permits
- Specific recommendations, not just pass/fail

Sample console output:
```
GitHub Security Auditor v1.19.0

[START] Starting GitHub security audit for: YOUR_ORG
[TIME] Timestamp (UTC): 2026-08-10T21:00:00+00:00
----------------------------------------------------------------------

[INFO] Running organization-level checks...
[OK] Organization Settings: 7/9

[SCANNING] Scanning repositories...
   Found 12 repositories
   [1/12] Checking api... [PASSED] (24/31)
   ...

======================================================================
AUDIT SUMMARY
======================================================================
Compliance Score: 82.5%
Coverage: 71.0% of checks were scored
Risk Level: MEDIUM RISK
======================================================================
JSON Report: audit_results/audit_YOUR_ORG_<session>.json
HTML Report: audit_results/audit_YOUR_ORG_<session>.html
```

Coverage below 100% is normal: several checks require organization owner or
repository admin access, or a paid plan, and are reported `not_applicable` or
`unknown` rather than counted as failures. See APPLICABILITY.md.

## Environment Variables (Optional)

```bash
export GITHUB_TOKEN=ghp_your_token_here
export GITHUB_ORG=your-organization
```

Then run without `--org`:
```bash
python3 github_auditor.py
```

## More CLI Options

```bash
# Restrict the audit to specific repositories
python3 github_auditor.py --org YOUR_ORG --repos api,web,infra

# Report against one compliance framework only
python3 github_auditor.py --org YOUR_ORG --standard soc2

# Skip account-type auto-detection
python3 github_auditor.py --org YOUR_ORG --account-type organization

# Verbose output, custom output directory
python3 github_auditor.py --org YOUR_ORG -v -d ./reports

# All options
python3 github_auditor.py --help

# Print the tool version and exit
python3 github_auditor.py --version
```

## Troubleshooting

**"Bad credentials"** - Token is invalid or expired. Regenerate it at
https://github.com/settings/tokens?type=beta.

**"Rate limit exceeded"** - Authenticated requests are limited to 5,000/hour.
Wait for the window to reset, or scope the audit to fewer repositories with
`--repos`.

**Many checks show "Not Checked"** - The token likely lacks organization owner
or repository admin access. See APPLICABILITY.md for exactly which checks
need which access level, and the coverage table for what to expect at each
permission tier.

**Many checks show "N/A"** - These are checks that do not apply to this
account or plan (for example, organization-only checks on a personal
account, or branch protection controls on a private repository under a
free plan). They are excluded from the score, not failures.

## Next Steps

1. **Read the coverage line before the score** - a score computed over a
   minority of checks is a weaker statement than the same number over all of
   them.
2. **Review the access inventory** - it is unscored on purpose, and is the
   evidence an access review is actually conducted against.
3. **Prioritize fixes** using the Compliance Gaps table - each failing
   control lists what was observed and the specific remediation.
4. **Re-run on a schedule** to track progress over time.

## What Gets Checked?

The exact count and the applicability of every check by account type and plan
is documented in **APPLICABILITY.md** rather than restated here, so this file
cannot drift out of sync with the engine the way an inline checklist would.

At a glance: organization-level checks cover 2FA enforcement, default
repository permission, member repository creation, Actions policy, and
organization owner count. Repository-level checks cover branch protection,
secret scanning, dependency alerts, GitHub Actions supply-chain settings
(action pinning, workflow permissions, untrusted triggers, self-hosted
runners, build provenance), repository hygiene (SECURITY.md, CODEOWNERS,
.gitignore, activity), and access review (direct grants, outside
collaborators, admin concentration).

---

**Need more help?** See README.md for detailed documentation, or
APPLICABILITY.md for exactly what applies to your account.
