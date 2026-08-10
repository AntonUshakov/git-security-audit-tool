# GitHub Security Auditor 🔒

[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Security Audit Passed](https://img.shields.io/badge/security-verified-brightgreen.svg)](SECURITY_AUDIT.md)
[![Privacy First](https://img.shields.io/badge/privacy-first-green.svg)](PRIVACY.md)
[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)]()

A comprehensive, privacy-first GitHub organization security auditor with compliance mapping to SOC2, NIST, ISO27001, and CIS standards.

**⚠️ Important**: This tool respects your privacy. [No tokens are stored, no data is sent external.](SECURITY_AUDIT.md)

---

## ✨ Features

### Reports for one standard

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

### 2. Get GitHub Token

1. Go to https://github.com/settings/tokens
2. Click "Generate new token"
3. Grant scopes:
   - `repo` (read repositories)
   - `admin:org_hook` (read webhooks)
   - `read:org` (read org info)
4. Copy the token (won't be shown again)

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
Running... (audit in progress)
  ↓
Dashboard → View Results
  ↓
Download Report (HTML or JSON)
```

### Audit Results
```json
{
  "organization": "my-org",
  "timestamp": "2026-08-08T21:28:27",
  "compliance_score": 65.5,
  "risk_level": "MEDIUM RISK",
  "checks": [
    {
      "name": "2FA Enforcement",
      "status": "PASSED",
      "details": "..."
    }
  ],
  "compliance_mapping": {
    "SOC2": { "score": 70, "status": "MEDIUM" },
    "NIST": { "score": 65, "status": "HIGH" },
    "ISO27001": { "score": 68, "status": "HIGH" },
    "CIS": { "score": 62, "status": "CRITICAL" }
  }
}
```

---

## API Endpoints

### Web Interface Routes
- `GET /` - Homepage
- `GET /start` - Audit form
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

### Optional Features

**VirusTotal & AbuseIPDB** (optional, for IP checking):
```bash
# Set environment variables (optional)
export VIRUSTOTAL_API_KEY=your_key
export ABUSEIPDB_API_KEY=your_key

# Or use config.py to configure
```

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
├── checks.py                 # 32 security check implementations
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
# Run from command line (no web UI)
python3 github_auditor.py -t YOUR_TOKEN -o organization_name

# Output
Starting GitHub organization audit...
Organization: organization_name
Checking 5 organization-level controls...
Checking 16 repository-level controls...
Results: 65% compliance (MEDIUM RISK)
```

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
