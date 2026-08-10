# Privacy Policy

**Last Updated**: August 8, 2026

## Overview

GitHub Security Auditor ("this tool") respects your privacy. **This document explains that we collect no data, store no credentials, and use no external tracking.**

---

## What We Don't Do

❌ **We DO NOT:**
- Collect personal information
- Store GitHub tokens or credentials
- Send data to external servers
- Use analytics or telemetry
- Track your usage
- Log your audit activities
- Require registration or accounts
- Use cookies (except browser session)

---

## What Information Exists

### On Your Machine (Stored Locally)
This tool stores **only**:
- Audit results (HTML/JSON reports)
- Audit metadata (timestamp, organization name, score)
- Audit history (no token or credentials)

**Location**: `audit_results/` directory on your machine

**Lifetime**: Until you delete them

### In Memory (During Execution)
Temporarily while running:
- GitHub token (only while audit runs, destroyed after)
- Audit results (until sent to browser)
- Session ID (temporary, cleared on restart)

**Lifetime**: Only during active audit session

### NOT Stored Anywhere
- ❌ GitHub tokens
- ❌ GitHub usernames or emails
- ❌ Personal authentication data
- ❌ API responses with sensitive data
- ❌ User identification information

---

## GitHub API Communication

### Direct Connection
- You provide your own GitHub token
- Tool connects directly to `api.github.com`
- We have NO intermediary servers
- We do NOT proxy your requests
- We do NOT see your API key

### What GitHub Sees
- Your token (you control this)
- Normal API requests (org info, repo settings)
- Read-only operations

### What We See
- Nothing (direct connection, no proxy)

### GitHub's Privacy
- GitHub's own [privacy policy](https://docs.github.com/en/site-policy/privacy-policies/github-privacy-statement) applies
- They may log API requests (standard practice)
- We do not receive or store logs from GitHub

---

## Third-Party Integrations (Optional)

### VirusTotal & AbuseIPDB
If you enable these optional features:
- You provide your own API keys
- Direct connection to their services
- We do NOT store your keys
- Their privacy policies apply

### No Required Third Parties
- All core features work offline (after initial GitHub auth)
- No tracking pixels
- No external CDNs
- No analytics services

---

## Data You Control

### Report Files
Generated HTML/JSON reports:
- ✅ You own completely
- ✅ Stored on your machine
- ✅ You decide when to share
- ✅ You control deletion

### Audit History
Historical metadata:
- ✅ Your machine only
- ✅ You can delete `audit_results/history.json`
- ✅ No backup copies
- ✅ No sync to cloud

---

## Security & Encryption

### In Transit
- GitHub API: HTTPS/TLS encrypted
- Browser to App: Local only (no external network)

### At Rest
- Files: Plain text (same directory)
- No encryption by default (local machine, your responsibility)

### Token Safety
- Never logged
- Never cached beyond current session
- Never written to disk
- Python garbage collection after use

---

## Your Rights

### Access
- ✅ You have all access to files on your machine
- ✅ View `audit_results/` directory anytime

### Deletion
- ✅ Delete reports: Remove files
- ✅ Delete history: Edit `history.json`
- ✅ Delete everything: Remove `audit_results/` folder

### No Transfer
- ✅ Data never leaves your machine
- ✅ No backup providers
- ✅ No cloud sync

---

## The report contains personal data

As of v1.9.0 the report includes an **access inventory**: the GitHub username of
every person with access to each repository, and the permission each holds.

This changes what the output is. Earlier versions produced configuration facts
about repositories; the report now identifies individuals and describes their
privileges. That is personal data in the ordinary sense and in the regulatory
one.

Nothing about the tool's transmission behaviour has changed — the inventory is
built on your machine from the GitHub API and is written only to
`audit_results/`. But:

- **Store the report accordingly.** It belongs with HR and access-review
  material, not in a shared drive or a ticket attachment.
- **If you run this for an organisation**, you are the controller of that file.
  Retention, access and disclosure are your policies to apply.
- **Share findings, not the roster**, unless the recipient has a reason to see
  who holds what.

The access inventory cannot currently be disabled separately. If you need the
configuration findings without the names, delete the "Access Inventory" section
from the generated HTML before circulating it.

## Data Protection Position

This project makes no compliance claim, because there is nothing to be compliant
about. GDPR and CCPA regulate organisations that **collect and process** personal
data. This tool runs entirely on your machine and transmits nothing to the author
or to any third party, so no controller, processor or data flow exists.

**What that means in practice:**

- Nothing is collected, so there is no lawful basis to establish, no consent to
  obtain and no subject access request to service.
- The only data at rest is `audit_results/` on your own disk. You own it, you
  delete it, and the author of this tool cannot reach it.
- The only network traffic is between your machine and `api.github.com`, which is
  governed by your existing agreement with GitHub, not by this tool.

**If you deploy this for an organisation**, you become the controller of whatever
`audit_results/` contains — repository names, member counts, configuration state —
and your own retention and access policies apply to that directory. This tool does
not and cannot make that determination for you.

### Other Jurisdictions
- ✅ Local-first approach compliant
- ✅ No cross-border data flow
- ✅ Standard open-source license

---

## Open Source Implications

This project is open source:
- ✅ Source code publicly available
- ✅ Anyone can audit security practices
- ✅ Anyone can verify no tracking
- ✅ Forks maintain privacy standards

---

## Changes to This Policy

If this privacy policy changes:
- ✅ New version posted here
- ✅ Release notes mention changes
- ✅ Substantial changes trigger major version bump

**Current Status**: Stable, no known changes planned

---

## Contact & Questions

### Privacy Questions
1. Check this document
2. Review [SECURITY_AUDIT.md](SECURITY_AUDIT.md) for technical details
3. Review source code: Open and auditable
4. Create GitHub issue with "privacy" tag

### Not Collecting Feedback
- We don't track feature requests from usage
- No telemetry on what you audit
- You must manually create issues/PRs

---

## Third-Party Privacy Notices

### PyGithub Library
- [PyGithub on GitHub](https://github.com/PyGithub/PyGithub)
- Official library, no telemetry

### Flask Framework
- [Flask Documentation](https://flask.palletsprojects.com/)
- Standard web framework, no tracking

### GitHub.com
- [GitHub Privacy Statement](https://docs.github.com/en/site-policy/privacy-policies/github-privacy-statement)
- You interact with GitHub directly

---

## Summary

**In One Sentence**: 
This tool respects your privacy because it stores nothing about you and sends no data external.

**Verification**: 
Open the source code. Read it. You'll see no external API calls (except GitHub), no database, no logging.

---

## Acknowledgments

Privacy-first design inspired by:
- OWASP security principles
- Privacy by design philosophy
- Open source best practices
- European data protection standards

---

**Status**: ✅ Privacy Verified  
**Last Audit**: August 8, 2026  
**Data protection**: no collection, no transmission, no third-party access

---

If you have privacy concerns, they should be addressed in [SECURITY.md](SECURITY.md) using private disclosure methods.
