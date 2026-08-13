GitHub Security Auditor 

A local, privacy-first GitHub organization security auditor. Maps 40 security controls to SOC 2, NIST SP 800-53, ISO/IEC 27001, and CIS Controls, with severity-weighted scoring, an access-review inventory, and run-to-run history — all computed from data your token can already see, sent nowhere but your own machine.

No token is ever stored. See SECURITY_AUDIT.md and PRIVACY.md for exactly what the code does, not a marketing claim.

Features
40 security controls (9 organization-level, 31 repository-level) — see the full list and what applies to your account in APPLICABILITY.md.
Severity-weighted scoring. A missing 2FA policy moves the risk classification more than a missing SECURITY.md file — a flat average can't represent that. Every report shows both the weighted score and the unweighted one.
Three scoring metrics, not one: compliance_score (of what could be evaluated), weighted_score (severity-adjusted, drives risk level), and pass_rate_of_total_scope (the conservative figure — of the full 40-control scope).
Token visibility gaps are detected, not assumed away. If your token can only see some of an organization's repositories, the report says so explicitly instead of claiming full coverage.
Access review: every repository's principals (users and teams), how they got access (direct grant, team, outside collaborator), and what their permission actually allows — plus four scored findings (direct grants, outside collaborators, admin concentration, org owner count).
GitHub Actions supply-chain checks: action pinning to a commit SHA, untrusted workflow triggers, self-hosted runner exposure on public repos, build provenance, and the platform-level SHA-pinning policy.
Branch protection via classic rules and rulesets, plan-aware: a free plan's private repos can't enforce branch protection at all, and the tool says so as plan_restricted, not as a failure.
Every Not Applicable finding states why — structural (never applies), plan_restricted (a plan/billing decision would fix it, with its own report section), or prerequisite_failed (a sibling finding already covers it).
Single-standard reports. --standard soc2 produces a report containing SOC 2 and nothing else — mappings, gaps, and score all describe that one control set.
Audit history with per-repository trends. Every run is compared against the previous audit of the same organization: which checks regressed, which were fixed, per repository.
Repository picker. Find your repositories through the web UI, then choose which to audit, instead of typing exact names.
Owner category on every finding (Organization owner / Repository admin / Engineering team), and both work-list tables sorted by severity.
Quick Start
1. Installation
bash
git clone https://github.com/AntonUshakov/github-auditor.git
cd github-auditor
python3 -m venv venv
source venv/bin/activate       # Windows: venv\Scripts\activate
pip install -r requirements.txt
2. Get a GitHub Token
Go to https://github.com/settings/tokens?type=beta
Generate a fine-grained token scoped to the organization or repositories you want to audit.
Grant read-only access to: Metadata, Administration, Contents, Dependabot alerts, Secret scanning alerts.
Copy the token.

Do not grant repo on a classic token — it is full write access to every repository, and this tool never writes anything. Every API call it makes is a GET.

3. Run an Audit

Web interface:

bash
python3 app.py

Open http://127.0.0.1:5000, paste the token, enter the organization, and optionally click Find Repositories to pick a subset before starting.

CLI:

bash
export GITHUB_TOKEN=ghp_your_token_here
python3 github_auditor.py --org organization_name

See QUICKSTART.md for sample output, environment variables, and troubleshooting.

System Requirements
Python 3.9 or higher
Internet access to api.github.com
macOS, Linux, Windows, or Docker
Does This Apply to My Account?

Not every check runs against every account. Nine of the 40 are organization settings that don't exist on a personal account; eleven depend on branch protection that a free plan doesn't enforce on private repositories; several need repository admin on the token.

Checks that can't apply are reported Not Applicable and excluded from the score. The report shows a coverage figure next to the score, so you can see how much of the control set the number actually describes — read coverage before the score.

Read the full applicability matrix →

Select your account type on the start screen. Choosing "Organization" for a personal account produces findings that can't apply to you; choosing "Personal account" for an organization silently drops nine real ones.

Compliance Standards
Standard	Reference
SOC 2 Trust Services Criteria	AICPA TSC 2017, with 2022 points of focus
NIST SP 800-53	Revision 5
ISO/IEC 27001	2022 (Annex A, clauses 5–8)
CIS Controls	v8.1

Every check maps to at least one criterion per standard — see the "Security Checks & Compliance Mapping" table in any generated report, or compliance_mapping.py directly. A mapping is evidence for an auditor's review, not a certification.

Architecture
Your machine
├── Web browser (127.0.0.1:5000) or CLI
├── Python (Flask for the web UI)
├── audit_results/  — reports and history, local only
└── → api.github.com (direct HTTPS, your token)

No cloud service, no analytics, no third-party integration beyond the GitHub API itself. See PRIVACY.md for what changed once the access inventory started recording usernames (v1.9.0) — it's still local-only, but it is personal data, and that document says so plainly.

Usage
Web Interface
Home
  → Start New Audit (token, organization, account type, standard)
  → (optional) Find Repositories → select which to audit
  → Running... (background thread, poll for status)
  → Dashboard (live results, comparison to the previous audit)
  → Download report (HTML or JSON)
Audit Results (shape)

This is a summary, not the schema — see checks.py and github_auditor.py for the exact fields:

json
{
  "organization": "my-org",
  "account_type": "Organization",
  "timestamp": "2026-08-13T21:00:00+00:00",
  "repository_scope": ["api", "web"],
  "repository_visibility": {"confidence": "confirmed", "visible_count": 12, "expected_total": 12, "gap": 0},
  "checks": {
    "organization": {"total": 9, "passed": 7, "failed": 1, "unknown": 1, "not_applicable": 0, "details": {"...": "..."}},
    "repositories": {"api": {"...": "per-repository results, same shape, plus access_inventory"}}
  },
  "summary": {
    "compliance_score": 65.5,
    "weighted_score": 58.2,
    "pass_rate_of_total_scope": 47.5,
    "coverage_percent": 71.0,
    "risk_level": "MEDIUM RISK",
    "severity_breakdown": {"critical": 1, "high": 2, "medium": 3, "low": 1}
  }
}
API Endpoints (Web Interface)
Method & Path	Purpose
GET /	Homepage
GET /start	Audit form
POST /api/list-repositories	List repositories for the picker
POST /api/start-audit	Begin an audit
GET /api/audit-status/{session_id}	Poll for completion
GET /dashboard/{session_id}	View results
GET /api/report/{session_id}/html	Download HTML
GET /api/report/{session_id}/json	Download JSON
GET /wiki, GET /wiki/{page}	Built-in documentation
GET /history	Audit history, grouped by organization
Configuration

One required input — a GitHub token, via GITHUB_TOKEN or --token-stdin — and no optional third-party API keys. config.py reads GITHUB_TOKEN and GITHUB_ORG and nothing else.

CLI Reference
bash
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

# Full flag list, or print the version and exit
python3 github_auditor.py --help
python3 github_auditor.py --version
Troubleshooting

Bad credentials — token is invalid or expired; regenerate it at https://github.com/settings/tokens?type=beta.

Rate limit exceeded — authenticated requests are capped at 5,000/hour. The tool retries and backs off automatically (logged as [RATE LIMIT] ...); for a large organization, scope the audit with --repos to reduce the call volume.

Many checks show "Not Checked" — the token likely lacks organization owner or repository admin access; see APPLICABILITY.md for exactly which checks need which access level.

Many checks show "N/A" — either the control doesn't apply to this account/plan, or a sibling finding already covers it. Not a failure.

Report won't download — check the audit_results/ directory directly, or try the other format (HTML vs. JSON).

Project Structure
github-auditor/
├── app.py                    # Flask web application
├── github_auditor.py         # CLI entry point + audit orchestration
├── checks.py                 # 40 security check implementations
├── access_review.py          # Access inventory and access-review findings
├── history.py                # Compact per-run records and run-to-run diffing
├── report_generator.py       # HTML/JSON report generation
├── compliance_mapping.py     # Standard mappings, severity, owner category
├── config.py                 # Configuration management
├── wiki_content.py           # Built-in documentation (served at /wiki)
├── version.py                # Single source of truth for the version string
├── requirements.txt          # Runtime dependencies
├── requirements-dev.txt      # pytest, pip-audit
├── tests/                    # 236 tests, plus live-API fixture data
├── run.sh                    # One-command launcher
├── Dockerfile, .dockerignore
├── LICENSE, SECURITY.md, PRIVACY.md, SECURITY_AUDIT.md
├── CODE_OF_CONDUCT.md, CONTRIBUTING.md
├── APPLICABILITY.md          # What applies to your account, by type and plan
├── QUICKSTART.md
├── CHANGELOG.md
└── README.md                 # This file
Development
bash
git clone https://github.com/your-fork/github-auditor.git
cd github-auditor
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt

pytest tests/ -q          # 236 tests
pip-audit                 # dependency vulnerability check

See CONTRIBUTING.md for how to report issues, submit pull requests, and the code style this project follows.

Performance

Repository checks run sequentially today; a large organization takes longer. Scope with --repos to reduce the call volume, or watch for [RATE LIMIT] ... log lines if the audit pauses — that's the tool correctly backing off from GitHub's rate limit, not a hang.

Reporting Issues

Bugs: open an issue with your OS, Python version, organization size, and the exact error.

Security issues: do not open a public issue — see SECURITY.md for responsible disclosure.

Roadmap

Tracked candidly, including what's still open:

Not yet implemented: structured unknown_reason categorization (insufficient token scope vs. plan limitation vs. missing API field) — correctly scoped as a larger change (tagging dozens of call sites at the source), not started.
Not yet implemented: parallel repository scanning (currently sequential).
Not yet implemented: Fork Pull Request Workflows policy field names — the GitHub API field names for this setting have not matched any tried candidate against a live response yet; the check correctly reports unknown rather than guessing.
Not yet implemented: bypass-list reading for ruleset-based branch protection, and interpretation of newer ruleset rule types (copilot_code_review, merge_queue, code quality/coverage rules).
Not yet implemented: multi-criterion SOC 2 mappings (NIST/ISO already support several criteria per check; SOC 2 currently supports one).

See CHANGELOG.md for what has shipped.

License

MIT — see LICENSE. You can use, modify, and distribute this commercially or privately; you must keep the license and copyright notice; the authors are not liable for how you use it.

Built With

PyGithub · Flask · Python 3.9+

Code of Conduct

Governed by CODE_OF_CONDUCT.md.

Support
Question	Resource
How do I use it?	This README, QUICKSTART.md, and the built-in /wiki
Does this apply to my account?	APPLICABILITY.md
Is it secure?	SECURITY_AUDIT.md
Is my data safe?	PRIVACY.md
What changed recently?	CHANGELOG.md
Found a bug?	Open an issue
Security concern?	SECURITY.md
Changelog

Every change is recorded in CHANGELOG.md, including defects found and fixed, not just features added — that document is a more honest account of this project's history than a features list would be.

Recent highlights:

v1.19.1 — README rewritten, fixing the fossilized "Version: 1.2.2" footer and stale check counts.
v1.19.0 — Gap tables sorted by severity, with an owner category (Organization owner / Repository admin / Engineering team) per finding.
v1.18.0 — not_applicable findings state why (structural / plan- restricted / prerequisite-failed); a third, conservative scoring metric.
v1.17.0 — Token visibility gaps are detected and reported, instead of a full-account audit silently covering only what the token could see.
v1.16.0 — Audit history with per-repository tracking and comparison against the previous run of the same organization.
v1.15.0 — Rate-limit backoff made visible; duplicate API calls within one audit run eliminated.
v1.14.0 — Severity-weighted scoring; risk level now reflects what a finding actually enables, not an equally-weighted average.

Maintained by @AntonUshakov.
