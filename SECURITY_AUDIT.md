# Security Notes - Token Handling & Data Privacy

This document describes what the code actually does, verified against the
source at the version below. It replaces an earlier version of this file that
described features this project does not have (VirusTotal/AbuseIPDB
integration, which belongs to a different project), wrong dependency
versions, and a false claim that no usernames are ever stored - the Access
Inventory feature (v1.9.0+) stores GitHub usernames by design.

This is not a third-party audit or a certification. It is a description of
the current implementation, written by the people who wrote it, with a list
of what is not yet verified rather than a claim of completeness.

**Reflects**: v1.19.0
**Last reviewed**: 2026-08-10

---

## 1. Token handling

### Where the token flows

**Web (`app.py`):**
1. Submitted via the start-audit form, received as `data['token']` in
   `POST /api/start-audit`.
2. `data['token']` is set to `None` immediately after validation, before the
   background thread starts - the raw parsed request body no longer carries
   the credential.
3. The token is passed explicitly into the worker thread as a positional
   argument (`Thread(target=run_audit, args=(github_token,))`), not captured
   from an enclosing scope, so no closure keeps a second live reference.
4. The outer `github_token` local in the request handler is set to `None`
   after the thread starts.
5. Inside the worker, the token is dropped (`token = None`) in a `finally`
   block once the audit completes or raises.

**CLI (`github_auditor.py`):** the token comes from `GITHUB_TOKEN` or
`--token-stdin`. There is no `--token` flag - a token accepted as a command
argument is visible in shell history and in `ps aux` to any other user on the
machine.

### What is never true regardless of path

- The token is never written to `audit_results/` - not in `history.json`, not
  in the generated HTML/JSON reports, not anywhere in `audit_sessions`.
- The token is never included in an exception message. `_from_exception()` in
  `checks.py` builds error text from the HTTP status code and exception type
  only, never from `str(exc)`, which can carry request context in some HTTP
  client libraries.
- `Config.__repr__` prints the organization name and account type, not the
  token.
- No file in this project sets a logging level that would emit PyGithub's
  request/response cycle, which is the path by which an `Authorization`
  header could otherwise reach a log.

### What was fixed and why it mattered

- `app.secret_key` was a hardcoded string committed to the repository;
  replaced with `secrets.token_bytes(32)` generated at process start.
- Session IDs were client-supplied timestamps with no authentication on the
  endpoints that read them; replaced with `secrets.token_urlsafe(32)`
  generated server-side.
- The Werkzeug debug console (`debug=True`) rendered the local variables of
  any failing request frame, including the token local in the audit-start
  path. Debug is now off by default and opt-in via `AUDITOR_DEBUG=1`.
- The report-download filename was built from a user-controlled organization
  name with no sanitisation, allowing path traversal. It now passes through
  `secure_filename()` and the resolved path is confined to `audit_results/`.

---

## 2. What gets stored, and where

**In `audit_results/` on the machine that ran the audit:**

- `history.json` - session id, organization name, timestamp, compliance
  score. No token.
- `audit_*.html`, `audit_*.json` - the full report, including the **access
  inventory**: every collaborator's GitHub username, whether their access is
  direct or team-derived, and their permission level. See "Personal data" below.

**Never stored:**

- The GitHub token, in any form.
- Email addresses. The access inventory intentionally uses usernames only;
  collecting email was considered and rejected (see CHANGELOG 1.10.0) because
  it raises the sensitivity of the report for no auditing benefit over the
  username, which is already sufficient to identify the principal on GitHub.
- Raw API response bodies beyond what a given check's result message quotes.

---

## 3. Personal data

As of v1.9.0, the access inventory means the report is no longer purely a
configuration artifact - it names individuals and describes their privileges.
PRIVACY.md covers this in detail; the summary:

- Nothing about the tool's network behaviour changed. The inventory is built
  locally from data the GitHub API already returns and is written only to
  `audit_results/`, same as every other report section.
- If you run this for an organisation, you are the controller of that file.
  Retention, access and disclosure of it are your policies to apply, not this
  tool's.
- The report should be treated and stored like access-review material, not
  circulated as a general status update.

---

## 4. Network and process posture

- **GitHub API calls**: direct to `api.github.com` over HTTPS, using the
  provided token. No intermediary service, no request logging by this tool.
- **The web interface itself is plain HTTP by default**, not HTTPS - this is
  the Flask development server (`app.run(...)`), appropriate for local use
  bound to `127.0.0.1`. It is not hardened for exposure beyond localhost.
  There is no authentication in front of the web UI beyond the unguessable
  session id; do not bind it to `0.0.0.0` on a network you do not control.
  The Dockerfile's `HEALTHCHECK` note repeats this: publish the container
  port to `127.0.0.1` only.
- **No outbound telemetry, analytics, or crash reporting** of any kind.
  Nothing in this codebase calls a service other than `api.github.com`.

---

## 5. Dependencies

`requirements.txt`, current pins:

```
PyGithub==2.5.0
Flask==3.1.0
requests==2.32.3
```

`requirements-dev.txt` adds `pytest` and `pip-audit` for local testing and
dependency vulnerability scanning; neither ships in the runtime image.

No dependency in this project performs network calls other than to GitHub
(via PyGithub/requests) and to the Flask development server's own bindings.
Re-run `pip-audit` before release rather than trusting a pinned list to stay
current - CVEs get disclosed against already-released versions.

---

## 6. Container

The Dockerfile (current version):

- Runs as a non-root user (`auditor`, uid 10001) rather than root.
- Ships a `HEALTHCHECK`.
- `.dockerignore` excludes `audit_results/`, `.git/`, and `.env`.
- Documents that the port should be published to `127.0.0.1` only, since
  there is no authentication in front of the application.

---

## 7. Token scope recommendation

Use a **fine-grained personal access token** with **read-only** access to:
Metadata, Administration, Contents, Dependabot alerts, Secret scanning
alerts. The tool never writes to GitHub - every API call it makes is a GET.

Do not grant `repo` on a classic token. `repo` is full read/write access to
every repository the token can see, and a tool that only ever reads has no
use for it. If you must use a classic token, `read:org` covers the
organization-level checks; nothing in this tool requires `admin:org_hook`,
`workflow`, or any write scope, despite what earlier drafts of this document
and other project files (now corrected) recommended.

---

## 8. What is not yet verified

Documented here rather than implied to be covered:

- This document describes the code, not an independent penetration test.
  Nothing here should be read as a third-party certification.
- Rate limiting and brute-force protection on the web endpoints beyond the
  unguessable session id have not been load-tested.
- The organization-level Actions endpoints and the `security_and_analysis`
  block require authentication to confirm against live GitHub, and remain
  partially unconfirmed - see APPLICABILITY.md and CHANGELOG.md for the
  current state of each.
- No formal secret-scanning pass has been run against this repository's own
  git history (as opposed to the repositories it audits).

See CHANGELOG.md for the version-by-version record of what was found and
fixed, including several defects (a hardcoded secret key, `debug=True`,
client-supplied session ids, an XSS in the generated report, a path traversal
in the download endpoint) that existed in earlier versions of this project
and are not present as of the version at the top of this document.
