# GitHub Security Auditor 🔒

[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)]()

> Local, severity-weighted GitHub security audit tool — 40 controls mapped to
> SOC 2 / NIST / ISO 27001 / CIS, honest about coverage and plan limits, your
> token never leaves your machine.

Audits an organization or personal account against 40 controls spanning 2FA,
branch protection (classic and rulesets), secret scanning, GitHub Actions
supply-chain risk, and access review (who has what access and why) — scored
by severity, not a flat pass/fail average, and reported per repository, per
standard, and against the previous audit's results. Runs entirely on your
machine; the only network call is to `api.github.com` with your own token.

**No token is ever stored.** See [SECURITY_AUDIT.md](SECURITY_AUDIT.md) and
[PRIVACY.md](PRIVACY.md) for exactly what the code does, not a marketing claim.

---

## Features

- **40 security controls** (9 organization-level, 31 repository-level) — see
  the full list and what applies to your account in
  [APPLICABILITY.md](APPLICABILITY.md).
- **Severity-weighted scoring.** A missing 2FA policy moves the risk
  classification more than a missing `SECURITY.md` file — a flat average
  can't represent that. Every report shows both the weighted score and the
  unweighted one.
- **Three scoring metrics, not one**: `compliance_score` (of what could be
  evaluated), `weighted_score` (severity-adjusted, drives risk level), and
  `pass_rate_of_total_scope` (the conservative figure — of the *full*
  40-control scope).
- **Token visibility gaps are detected**, not assumed away. If your token
  can only see some of an organization's repositories, the report says so
  explicitly instead of claiming full coverage.
- **Access review**: every repository's principals (users and teams), how
  they got access (direct grant, team, outside collaborator), and what their
  permission actually allows — plus four scored findings (direct grants,
  outside collaborators, admin concentration, org owner count).
- **GitHub Actions supply-chain checks**: action pinning to a commit SHA,
  untrusted workflow triggers, self-hosted runner exposure on public repos,
  build provenance, and the platform-level SHA-pinning policy.
- **Branch protection via classic rules *and* rulesets**, plan-aware: a free
  plan's private repos can't enforce branch protection at all, and the tool
  says so as `plan_restricted`, not as a failure.
- **Every Not Applicable finding states why** — `structural` (never
  applies), `plan_restricted` (a plan/billing decision would fix it, with
  its own report section), or `prerequisite_failed` (a sibling finding
  already covers it).
- **Single-standard reports.** `--standard soc2` produces a report
  containing SOC 2 and nothing else — mappings, gaps, and score all describe
  that one control set.
- **Audit history with per-repository trends.** Every run is compared
  against the previous audit of the same organization: which checks
  regressed, which were fixed, per repository.
- **Repository picker.** Find your repositories through the web UI, then
  choose which to audit, instead of typing exact names.
- **Owner category on every finding** (Organization owner / Repository
  admin / Engineering team), and both work-list tables sorted by severity.

---

## Quick Start

### 1. Installation

```bash
git clone https://github.com/AntonUshakov/github-auditor.git
cd github-auditor
python3 -m venv venv
source venv/bin/activate       # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Get a GitHub Token

1. Go to https://github.com/settings/tokens?type=beta
2. Generate a fine-grained token scoped to the organization or repositories
   you want to audit.
3. Grant **read-only** access to: Metadata, Administration, Contents,
   Dependabot alerts, Secret scanning alerts.
4. Copy the token.

Do not grant `repo` on a classic token — it is full write access to every
repository, and this tool never writes anything. Every API call it makes is
a GET.

### 3. Run an Audit

**Web interface:**
```bash
python3 app.py
```
Open http://127.0.0.1:5000, paste the token, enter the organization, and
optionally click **Find Repositories** to pick a subset before starting.

**CLI:**
```bash
export GITHUB_TOKEN=ghp_your_token_here
python3 github_auditor.py --org organization_name
```

See [QUICKSTART.md](QUICKSTART.md) for sample output, environment variables,
and troubleshooting.

---

## System Requirements

- Python 3.9 or higher
- Internet access to `api.github.com`
- macOS, Linux, Windows, or Docker

---

## Does This Apply to My Account?

Not every check runs against every account. Nine of the 40 are organization
settings that don't exist on a personal account; eleven depend on branch
protection that a free plan doesn't enforce on private repositories; several
need repository admin on the token.

Checks that can't apply are reported **Not Applicable** and excluded from
the score. The report shows a **coverage** figure next to the score, so you
can see how much of the control set the number actually describes — read
coverage before the score.

**[Read the full applicability matrix →](APPLICABILITY.md)**

Select your account type on the start screen. Choosing "Organization" for a
personal account produces findings that can't apply to you; choosing
"Personal account" for an organization silently drops nine real ones.

---

## Compliance Standards

| Standard | Reference |
|---|---|
| SOC 2 Trust Services Criteria | AICPA TSC 2017, with 2022 points of focus |
| NIST SP 800-53 | Revision 5 |
| ISO/IEC 27001 | 2022 (Annex A, clauses 5–8) |
| CIS Controls | v8.1 |

Every check maps to at least one criterion per standard — see the
"Security Checks & Compliance Mapping" table in any generated report, or
`compliance_mapping.py` directly. A mapping is evidence for an auditor's
review, not a certification.

---

## Architecture

```
Your machine
├── Web browser (127.0.0.1:5000) or CLI
├── Python (Flask for the web UI)
├── audit_results/  — reports and history, local only
└── → api.github.com (direct HTTPS, your token)
```

No cloud service, no analytics, no third-party integration beyond the GitHub
API itself. See [PRIVACY.md](PRIVACY.md) for what changed once the access
inventory started recording usernames (v1.9.0) — it's still local-only, but
it is personal data, and that document says so plainly.

---

## Usage

### Web Interface

```
Home
  → Start New Audit (token, organization, account type, standard)
  → (optional) Find Repositories → select which to audit
  → Running... (background thread, poll for status)
  → Dashboard (live results, comparison to the previous audit)
  → Download report (HTML or JSON)
```

### Audit Results (shape)

This is a summary, not the schema — see `checks.py` and `github_auditor.py`
for the exact fields:

```json
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
```

---

## API Endpoints (Web Interface)

| Method & Path | Purpose |
|---|---|
| `GET /` | Homepage |
| `GET /start` | Audit form |
| `POST /api/list-repositories` | List repositories for the picker |
| `POST /api/start-audit` | Begin an audit |
| `GET /api/audit-status/{session_id}` | Poll for completion |
| `GET /dashboard/{session_id}` | View results |
| `GET /api/report/{session_id}/html` | Download HTML |
| `GET /api/report/{session_id}/json` | Download JSON |
| `GET /wiki`, `GET /wiki/{page}` | Built-in documentation |
| `GET /history` | Audit history, grouped by organization |

---

## Configuration

One required input — a GitHub token, via `GITHUB_TOKEN` or `--token-stdin` —
and no optional third-party API keys. `config.py` reads `GITHUB_TOKEN` and
`GITHUB_ORG` and nothing else.

---

## CLI Reference

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

# Full flag list, or print the version and exit
python3 github_auditor.py --help
python3 github_auditor.py --version
```

---

## Troubleshooting

**Bad credentials** — token is invalid or expired; regenerate it at
https://github.com/settings/tokens?type=beta.

**Rate limit exceeded** — authenticated requests are capped at 5,000/hour.
The tool retries and backs off automatically (logged as `[RATE LIMIT] ...`);
for a large organization, scope the audit with `--repos` to reduce the call
volume.

**Many checks show "Not Checked"** — the token likely lacks organization
owner or repository admin access; see [APPLICABILITY.md](APPLICABILITY.md)
for exactly which checks need which access level.

**Many checks show "N/A"** — either the control doesn't apply to this
account/plan, or a sibling finding already covers it. Not a failure.

**Report won't download** — check the `audit_results/` directory directly,
or try the other format (HTML vs. JSON).

---

## Project Structure

```
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
```

---

## Development

```bash
git clone https://github.com/your-fork/github-auditor.git
cd github-auditor
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt

pytest tests/ -q          # 236 tests
pip-audit                 # dependency vulnerability check
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to report issues, submit pull
requests, and the code style this project follows.

---

## Performance

Repository checks run sequentially today; a large organization takes longer.
Scope with `--repos` to reduce the call volume, or watch for
`[RATE LIMIT] ...` log lines if the audit pauses — that's the tool correctly
backing off from GitHub's rate limit, not a hang.

---

## Reporting Issues

**Bugs**: [open an issue](https://github.com/AntonUshakov/github-auditor/issues)
with your OS, Python version, organization size, and the exact error.

**Security issues**: do not open a public issue — see
[SECURITY.md](SECURITY.md) for responsible disclosure.

---

## Roadmap

Tracked candidly, including what's still open:

- **Not yet implemented**: structured `unknown_reason` categorization
  (insufficient token scope vs. plan limitation vs. missing API field) —
  correctly scoped as a larger change (tagging dozens of call sites at the
  source), not started.
- **Not yet implemented**: parallel repository scanning (currently
  sequential).
- **Not yet implemented**: Fork Pull Request Workflows policy field names —
  the GitHub API field names for this setting have not matched any tried
  candidate against a live response yet; the check correctly reports
  `unknown` rather than guessing.
- **Not yet implemented**: bypass-list reading for ruleset-based branch
  protection, and interpretation of newer ruleset rule types
  (`copilot_code_review`, `merge_queue`, code quality/coverage rules).
- **Not yet implemented**: multi-criterion SOC 2 mappings (NIST/ISO already
  support several criteria per check; SOC 2 currently supports one).

See [CHANGELOG.md](CHANGELOG.md) for what has shipped.

---

## License

MIT — see [LICENSE](LICENSE). You can use, modify, and distribute this
commercially or privately; you must keep the license and copyright notice;
the authors are not liable for how you use it.

---

## Built With

[PyGithub](https://github.com/PyGithub/PyGithub) ·
[Flask](https://flask.palletsprojects.com/) · Python 3.9+

---

## Code of Conduct

Governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

---

## Support

| Question | Resource |
|---|---|
| How do I use it? | This README, [QUICKSTART.md](QUICKSTART.md), and the built-in `/wiki` |
| Does this apply to my account? | [APPLICABILITY.md](APPLICABILITY.md) |
| Is it secure? | [SECURITY_AUDIT.md](SECURITY_AUDIT.md) |
| Is my data safe? | [PRIVACY.md](PRIVACY.md) |
| What changed recently? | [CHANGELOG.md](CHANGELOG.md) |
| Found a bug? | [Open an issue](https://github.com/AntonUshakov/github-auditor/issues) |
| Security concern? | [SECURITY.md](SECURITY.md) |

---

## Version History

Every release below shipped a real, verifiable change - most were prompted by
a defect found in a live audit run, not a planned feature. Full detail,
including what was found and how it was verified, is in
**[CHANGELOG.md](CHANGELOG.md)**.

| Version | Date | Summary |
|---|---|---|
| 1.19.2 | 2026-08-13 | README: full version-history table and a tightened, information-dense description, replacing a six-item highlights list. |
| 1.19.1 | 2026-08-13 | README rewritten - fixed a fossilized "Version: 1.2.2 / Production Ready" footer and stale check counts left over from the original release. |
| 1.19.0 | 2026-08-13 | Gap tables sorted by severity; an owner category (Organization owner / Repository admin / Engineering team) on every finding. |
| 1.18.0 | 2026-08-13 | Not Applicable findings state *why* (structural / plan-restricted / prerequisite-failed); added `pass_rate_of_total_scope`, the conservative scoring metric. |
| 1.17.0 | 2026-08-13 | Token visibility gaps are detected and reported - a full-account audit no longer silently claims complete coverage if the token can only see part of the org. |
| 1.16.0 | 2026-08-13 | Audit history enriched with per-repository tracking and a diff against the previous run of the same organization. |
| 1.15.0 | 2026-08-11 | Rate-limit backoff made visible in the console; duplicate API calls within a single audit run eliminated. |
| 1.14.0 | 2026-08-11 | Severity-weighted scoring added. Every check previously counted equally toward the score regardless of what its failure enabled. |
| 1.13.0 | 2026-08-11 | Repository name added to every compliance-table finding - fixed a real accuracy defect where multi-repository results were silently collapsed into one. |
| 1.12.0 | 2026-08-11 | "Find repositories, then pick" flow added to the web UI, replacing free-text repository entry. |
| 1.11.1 | 2026-08-11 | Full re-audit across five areas (UTC time, token security, check logic, repo-scope selection, doc drift) found and fixed several real defects. |
| 1.11.0 | 2026-08-10 | Organization-Level Findings and Failed Checks Summary rebuilt as tables; version number surfaced across the whole interface; repository-scoped audits wired end to end. |
| 1.10.1 | 2026-08-10 | Fixed a rendering bug that made every downloadable report fail; both compliance sections rebuilt as actionable tables. |
| 1.10.0 | 2026-08-10 | Single-standard reports added (SOC 2 / NIST / ISO 27001 / CIS, isolated from each other); access inventory gained capability columns. |
| 1.9.0 | 2026-08-09 | Access review added: per-repository inventory of who has access and what they can do. 36 checks → 40. |
| 1.8.0 | 2026-08-09 | Account type is chosen before the audit runs, instead of guessed; applicability documented per account type and plan. |
| 1.7.0 | 2026-08-09 | Fixed account-type detection - the engine had assumed every target was an organization and misreported every organization-only control on personal accounts. |
| 1.6.2 | 2026-08-09 | Confirmed the last open assumption in the branch-protection enforcement model directly against the GitHub UI. |
| 1.6.1 | 2026-08-09 | Second live validation run; found and fixed three defects in the actual output that mock-based testing had missed. |
| 1.6.0 | 2026-08-09 | Ruleset and Actions logic modelled directly from a live free-organization account. 35 checks → 36. |
| 1.5.0 | 2026-08-09 | GitHub Actions coverage extended from the live repository settings UI; a second XSS site found by a test added the previous release. 32 checks → 35. |
| 1.4.2 | 2026-08-09 | Modelled plan-based enforcement directly from the GitHub UI, adding a state the engine had previously misreported as passing. |
| 1.4.1 | 2026-08-09 | Ruleset handling verified against live GitHub API responses instead of assumptions; one real defect found and fixed by that verification. |
| 1.4.0 | 2026-08-09 | Added GitHub Actions supply-chain coverage (SHA pinning, untrusted triggers, self-hosted runners, build provenance). 23 checks → 32. |
| 1.3.1 | 2026-08-09 | First release validated against a live GitHub account rather than mocked data only. |
| 1.3.0 | 2026-08-09 | Post-review rewrite. The original v1.2.2 scoring engine could not produce an accurate result under any configuration and should not be used. |

---

Maintained by [@AntonUshakov](https://github.com/AntonUshakov).
