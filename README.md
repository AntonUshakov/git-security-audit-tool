# GitHub Security Auditor 🔒

[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Security Audit Passed](https://img.shields.io/badge/security-verified-brightgreen.svg)](SECURITY_AUDIT.md)
[![Privacy First](https://img.shields.io/badge/privacy-first-green.svg)](PRIVACY.md)
[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)]()

A comprehensive, privacy-first GitHub organization security auditor with compliance mapping to SOC2, NIST, ISO27001, and CIS standards.

**⚠️ Important**: This tool respects your privacy. [No tokens are stored, no data is sent external.](SECURITY_AUDIT.md)

---

## ✨ Features

### Severity-weighted scoring

Every report shows two scores: an **unweighted** one (every check counted
equally) and a **weighted** one (critical findings count four times as much as
low ones). Risk level is derived from the weighted score - a single missing
2FA policy moves it more than a missing SECURITY.md file does, which a flat
average cannot represent. See APPLICABILITY.md for the full severity table.

## Reports for one standard

```bash
python3 github_auditor.py --org acme --standard soc2
```

Produces a report containing SOC 2 and nothing else — mappings, gap analysis and
score all describe that control set. `soc2`, `nist`, `iso27001`, `cis`, or `all`
(default). Also selectable on the web start screen.

Every report includes the **access inventory** regardless of standard: each
repository, everyone with access, the permission held, what that permission
permits, and where an access reviewer will push back.

## Does this apply to my account?

Not every check runs against every account. Nine of the 40 are organization
settings that do not exist on a personal account, eleven depend on branch
protection that a free plan does not enforce on private repositories, and
several need repository admin on the token.

Checks that cannot apply are reported **Not Applicable** and excluded from the
score. The report shows a **coverage** figure next to the score so you can see
how much of the control set the number actually describes.

**[Read the full applicability matrix &rarr;](APPLICABILITY.md)**

| Target | Scored | Coverage |
|---|---|---|
| Personal account, free | 25 of 64 | 39% |
| Personal account, paid | 26 of 64 | 41% |
| Organization, free | 28 of 64 | 44% |
| Organization, Team | 29 of 64 | 45% |

Select your account type on the start screen. Choosing "Organization" for a
personal account produces eight findings that cannot apply to you; choosing
"Personal account" for an organization silently drops eight real ones.

## 🛡️ Security Auditing
- **40 security checks (9 organization-level, 31 repository-level)** across organization and repository levels
- **Real-time audit** of GitHub organizations
- **Detailed reporting** in HTML and JSON formats
- **Compliance scoring** with risk assessment

### 📋 Compliance Standards
- **SOC 2 Trust Services Criteria** - Service organization controls
- **NIST SP 800-53** - Federal information security
- **ISO/IEC 27001** - International information security
- **CIS Controls v8** - Cybersecurity best practices

### 🌐 Web Interface
- **Beautiful dashboard** with audit results
- **Interactive documentation** with built-in wiki
- **Audit history** tracking
- **One-click report download** (HTML + JSON)

### 🔐 Privacy & Security
- **No token storage** - Tokens destroyed after use
- **Local-only execution** - Everything runs on your machine
- **No telemetry** - No external data transmission
- **Open source** - Audit the code yourself

---

## Quick Start

### 1. Installation

**macOS/Linux:**
```bash
git clone https://github.com/AntonUshakov/github-auditor.git
cd github-auditor
./run.sh
```

**Windows:**
```bash
git clone https://github.com/AntonUshakov/github-auditor.git
cd github-auditor
python3 -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python3 app.py
```

### 2. Get a GitHub Token

1. Go to https://github.com/settings/tokens?type=beta
2. Generate a fine-grained token scoped to the organization or repositories
   you want to audit
3. Grant **read-only** access to: Metadata, Administration, Contents,
   Dependabot alerts, Secret scanning alerts
4. Copy the token

Do not grant `repo` on a classic token — it is full write access to every
repository, and this tool never writes anything.

### 3. Run Audit

1. Open http://localhost:5000
2. Click "Start New Audit"
3. Paste GitHub token & enter org name
4. Wait 2-15 minutes (depends on org size)
5. Review results in dashboard
6. Download HTML or JSON report

---

## System Requirements

- **Python**: 3.7 or higher
- **RAM**: 2GB minimum
- **Internet**: For GitHub API calls
- **OS**: macOS, Linux, Windows, or Docker

---

## What Gets Audited

### Organization Level (5 checks)
- 2FA enforcement for members
- SSO/SAML configuration
- Access control policies
- Audit logging setup
- Member privilege management

### Repository Level (16 checks)
- Repository visibility settings
- Branch protection rules
- Pull request requirements
- Status checks enforcement
- Commit signing policies
- Secrets scanning
- Dependency scanning
- And 9 more...

**Total: 40 Security Controls**

---

## Architecture

### Local-Only Design
```
Your Machine
├── Web Browser (localhost:5000)
├── Python Flask App
├── audit_results/ (local storage)
└── → GitHub API (direct HTTPS)
```

### Zero External Dependencies
- ❌ No cloud servers
- ❌ No data collection
- ❌ No analytics
- ❌ No storage external
- ✅ Direct GitHub API only

---

## Security & Privacy

### Data Handling
- ✅ Tokens never stored
- ✅ Results stored locally only
- ✅ No external transmission
- ✅ Direct GitHub API calls
- ✅ No logging of credentials

### Compliance
- ✅ No data collection: the tool sends nothing anywhere, so there is no processing to regulate
- ✅ CCPA compliant (no tracking)
- ✅ OWASP best practices
- ✅ CWE/SANS Top 25 prevention
- ✅ GitHub's security guidelines

**See [SECURITY_AUDIT.md](SECURITY_AUDIT.md) and [PRIVACY.md](PRIVACY.md) for full details.**

---

## Usage

### Web Interface
```
Home Page
  ↓
Start New Audit → Enter Token + Org
  ↓
(Optional) Find Repositories → Select which to audit
  ↓
Start Audit
  ↓
Running... (audit in progress)
  ↓
Dashboard → View Results
  ↓
Download Report (HTML or JSON)
```

### Audit Results (shape)

The real structure - see `checks.py` and `github_auditor.py` for the exact
fields, since this is a summary, not the schema:

```json
{
  "organization": "my-org",
  "account_type": "Organization",
  "timestamp": "2026-08-10T21:00:00+00:00",
  "repository_scope": ["api", "web"],
  "checks": {
    "organization": { "total": 9, "passed": 7, "failed": 1,
                       "unknown": 1, "not_applicable": 0, "details": { "...": "..." } },
    "repositories": { "api": { "...": "per-repository results, same shape" } }
  },
  "summary": {
    "compliance_score": 65.5,
    "coverage_percent": 71.0,
    "risk_level": "MEDIUM RISK"
  }
}
```

---

## API Endpoints

### Web Interface Routes
- `GET /` - Homepage
- `GET /start` - Audit form
- `POST /api/list-repositories` - List repositories for the "Find Repositories" picker
- `POST /api/start-audit` - Begin audit
- `GET /api/audit-status/{session_id}` - Poll for completion
- `GET /dashboard/{session_id}` - View results
- `GET /api/report/{session_id}/html` - Download HTML
- `GET /api/report/{session_id}/json` - Download JSON
- `GET /wiki` - Documentation home
- `GET /wiki/{page}` - Wiki pages
- `GET /history` - Audit history

---

## Configuration

This tool has one required input - a GitHub token, via `GITHUB_TOKEN` or
`--token-stdin` - and no optional third-party API keys. `config.py` reads
`GITHUB_TOKEN` and `GITHUB_ORG` and nothing else.

---

## Troubleshooting

### Port 5000 Already in Use
```bash
python3 app.py  # Will find available port
```

### GitHub Token Invalid
- Regenerate at https://github.com/settings/tokens
- Verify scopes are correct
- Token may have expired

### Audit Very Slow
- Normal for 100+ repositories
- GitHub API rate limits may apply
- Try during off-peak hours

### Reports Won't Download
- Clear browser cache
- Try JSON format if HTML fails
- Check `audit_results/` directory

**For more help, see [SECURITY.md](SECURITY.md) and documentation.**

---

## Project Structure

```
github-auditor/
├── app.py                    # Flask web application
├── github_auditor.py         # CLI audit engine
├── checks.py                 # 40 security check implementations
├── report_generator.py       # HTML/JSON report generation
├── compliance_mapping.py     # Compliance standard mappings
├── config.py                 # Configuration management
├── wiki_content.py           # Built-in documentation
├── run.sh                    # One-command launcher
├── requirements.txt          # Python dependencies
├── Dockerfile                # Docker support
├── LICENSE                   # MIT License
├── SECURITY.md              # Security policy
├── PRIVACY.md               # Privacy policy
├── CODE_OF_CONDUCT.md       # Community guidelines
├── CONTRIBUTING.md          # Contribution guidelines
├── SECURITY_AUDIT.md        # Security audit report
└── README.md                # This file
```

---

## CLI Usage (Advanced)

```bash
# GITHUB_TOKEN env var, or --token-stdin to pipe a token in.
# There is no --token flag: a token accepted as an argument lands in shell
# history and `ps aux`.
export GITHUB_TOKEN=ghp_your_token_here
python3 github_auditor.py --org organization_name

# Restrict to specific repositories
python3 github_auditor.py --org organization_name --repos api,web,infra

# One framework only
python3 github_auditor.py --org organization_name --standard soc2

# Explicit account type (skip auto-detection)
python3 github_auditor.py --org a-username --account-type user

# Sample output
GitHub Security Auditor v1.19.0

[START] Starting GitHub security audit for: organization_name
[TIME] Timestamp (UTC): 2026-08-10T21:00:00+00:00
----------------------------------------------------------------------

[INFO] Running organization-level checks...

[OK] Organization Settings: 7/9

[SCANNING] Scanning repositories...
   Found 12 repositories
   [1/12] Checking api... [PASSED] (24/31)
```

Run `python3 github_auditor.py --help` for the full flag list, or `--version`
to print the tool version and exit.

---

## Development

### Setting Up Development Environment
```bash
git clone https://github.com/your-fork/github-auditor.git
cd github-auditor

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt
pip install pytest flake8  # Optional dev tools

# Make changes, test, commit
./run.sh  # Test locally
```

### Contributing
See [CONTRIBUTING.md](CONTRIBUTING.md) for:
- How to report issues
- How to submit pull requests
- Code style guidelines
- Security considerations
- Development roadmap

---

## Performance

### Typical Audit Times
| Organization Size | Time |
|------------------|------|
| < 5 repos | 2-3 min |
| 5-50 repos | 3-5 min |
| 50-100 repos | 5-10 min |
| 100+ repos | 10-15 min |

*Times vary based on GitHub API rate limits and network speed*

---

## Browser Support

| Browser | Status |
|---------|--------|
| Chrome | ✅ Full support |
| Firefox | ✅ Full support |
| Safari | ✅ Full support |
| Edge | ✅ Full support |
| IE 11 | ⚠️ Limited |

---

## Reporting Issues

### Bug Reports
1. Check [existing issues](https://github.com/AntonUshakov/github-auditor/issues)
2. Create new issue with details
3. Include: OS, Python version, org size, error message

### Security Issues
**DO NOT** create public issue. See [SECURITY.md](SECURITY.md) for responsible disclosure.

### Feature Requests
Describe feature, explain use case, suggest implementation

---

## Roadmap

### Completed ✅
- Web interface with audit dashboard
- 40 security checks
- 4 compliance standard mappings
- HTML and JSON reports
- Audit history tracking
- Built-in documentation wiki
- Full privacy & security verification

### Planned 🔄
- More security checks
- Additional compliance standards
- Advanced filtering & searching
- Scheduled audits
- Email reports
- API for programmatic access

---

## License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

### What This Means
✅ **You can:**
- Use commercially
- Modify the code
- Distribute copies
- Use in private projects

✅ **You must:**
- Include license text
- Include copyright notice

✅ **You cannot:**
- Hold authors liable
- Remove license/copyright

---

## Acknowledgments

### Built With
- [PyGithub](https://github.com/PyGithub/PyGithub) - GitHub API library
- [Flask](https://flask.palletsprojects.com/) - Web framework
- [Python](https://www.python.org/) - Programming language

### Security Inspired By
- OWASP Top 10
- CWE/SANS Top 25
- GitHub security best practices
- Privacy by design principles

---

## Code of Conduct

This project and everyone participating in it is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

---

## Support

| Question | Resource |
|----------|----------|
| How do I use it? | [README.md](README.md) & built-in wiki |
| Is it secure? | [SECURITY_AUDIT.md](SECURITY_AUDIT.md) |
| Is my data safe? | [PRIVACY.md](PRIVACY.md) |
| Found a bug? | [Create issue](https://github.com/AntonUshakov/github-auditor/issues) |
| Want to help? | [CONTRIBUTING.md](CONTRIBUTING.md) |
| Security concern? | [SECURITY.md](SECURITY.md) |

---

## Author

**GitHub Security Auditor** developed by the security community.

Maintained and contributed to by [@AntonUshakov](https://github.com/AntonUshakov)

---

## Similar Projects

- [Gitleaks](https://github.com/gitleaks/gitleaks) - Secret scanning
- [GitHub Security](https://github.com/features/security) - Native GitHub features
- [Dependabot](https://github.com/dependabot) - Dependency management

---

## Final Notes

### Data Privacy
This tool is designed for **maximum privacy**. Read [PRIVACY.md](PRIVACY.md) to verify.

### Security First
Every line of code reviewed for security. See [SECURITY_AUDIT.md](SECURITY_AUDIT.md).

### Open Source
Review the code. Audit it yourself. Trust through transparency.

---

## Get Started Now! 🚀

```bash
git clone https://github.com/AntonUshakov/github-auditor.git
cd github-auditor
./run.sh
```

Open http://localhost:5000 and start auditing!

---

**Questions?** Check the [built-in wiki](http://localhost:5000/wiki) or [create an issue](https://github.com/AntonUshakov/github-auditor/issues).

**Found a security issue?** See [SECURITY.md](SECURITY.md) for responsible disclosure.

---

Made with ❤️ for GitHub security

**Last Updated**: August 8, 2026  
**Version**: 1.2.2  
**Status**: Production Ready ✅
