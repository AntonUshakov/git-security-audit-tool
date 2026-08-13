# What applies to your account

Not every check can run against every GitHub account. Some controls exist only
on organizations, some only on paid plans, and some need repository admin on the
token. A check that cannot apply is reported `not_applicable` and **excluded
from the score** — it is not counted as a failure.

This is why the report shows a **coverage** figure next to the score. A 60%
score over 29 scored checks is a different statement from 60% over all 36, and
you should read the coverage line before the score.

**Select your account type on the start screen.** Choosing "Organization" for a
personal account produces eight findings that cannot apply to you; choosing
"Personal account" for an organization silently drops eight real ones.

---

## Result states

| State | Meaning | In the score |
|---|---|---|
| `pass` | Control is configured | yes |
| `fail` | Control is missing or misconfigured | yes |
| `unknown` | Could not determine — token permission, plan add-on, or an API field this version does not recognise | **no** |
| `not_applicable` | Cannot apply here — wrong account type, plan restriction, or a prerequisite already reported | **no** |

`unknown` and `not_applicable` are deliberately distinct. The first means *we
could not find out*; the second means *there is nothing to find out*. Collapsing
them would hide real gaps in what the tool can see.

---

## Organization-level checks (9)

None of these exist on a personal account. There is no membership policy, no
default repository permission, and no organization Actions policy to read.

| Check | Personal | Organization (Free) | Team | Enterprise Cloud |
|---|---|---|---|---|
| 2FA Enforcement | n/a | ✅ | ✅ | ✅ |
| SSO Configuration | n/a | n/a (free plan) | ⚠️ not implemented | ⚠️ not implemented |
| Default Repository Permission | n/a | ✅ | ✅ | ✅ |
| Member Repository Creation | n/a | ✅ | ✅ | ✅ |
| Audit Logging | n/a | n/a (Enterprise only) | n/a | ⚠️ not implemented |
| Actions Allowed Actions Policy | n/a | ✅ | ✅ | ✅ |
| Actions Default Token Permissions | n/a | ✅ | ✅ | ✅ |
| Actions Pull Request Approval | n/a | ✅ | ✅ | ✅ |
| Organization Owner Count | n/a | ✅ | ✅ | ✅ |

All nine require **organization owner** access on the token. With read-only
member access they return `unknown`.

⚠️ **SSO and Audit Logging are honest placeholders.** SAML status is not exposed
by the REST API, and the audit log endpoint is absent from PyGithub. Both always
return `unknown` with an explanation. An Enterprise Cloud customer gains nothing
from these two today.

---

## History and progress tracking

Every completed audit is recorded in `audit_results/history.json`: organization,
timestamp, account type, standard used, repository scope, the overall summary
(both scores, risk level, coverage, severity breakdown), and a **compact
per-repository breakdown** - pass/fail counts, weighted score, and a
check-name-to-status map for every repository audited.

Full check messages, remediation guidance, and the access inventory
(usernames) are deliberately excluded from history - every field added there
is multiplied by every run ever stored, and history exists to track trends
across many runs, not to reproduce a full report.

**The History page** (`/history`) groups runs by organization, newest first,
with a trend arrow showing the weighted-score change versus the previous run
for that organization.

**Every report compares against the previous audit of the same organization**,
when one exists in history. The comparison shows:

- The weighted score delta since last time.
- Per-repository: which specific checks newly failed (regression) or newly
  passed (fixed), and which changed coverage (moved to/from Not Checked or
  N/A - a permission or plan change, not a security finding).
- Which repositories are new to the audited set, and which are no longer
  present (archived, renamed, or removed from scope - not by itself a
  regression).

This is what makes "did the repository I fixed last time actually stay
fixed" answerable, which a bare score cannot show on its own - a repository
that regressed and one that improved can cancel out in the aggregate number
while both facts matter individually.

Comparison requires a previous entry in `history.json` for the same
organization name (case-insensitive match); the very first audit of an
organization has nothing to compare against, and legacy history entries
written before this feature (org/timestamp/score only) cannot be diffed and
are skipped when looking for a comparison baseline.

---

## Reliability: rate limits and duplicate requests

**Rate-limit backoff** is handled by PyGithub's own `GithubRetry`, constructed
explicitly in `github_auditor.GITHUB_RETRY_POLICY` rather than left to the
library's default (so a future PyGithub upgrade cannot silently change audit
behaviour). It already does the correct thing: on a primary rate limit it
waits until the `X-RateLimit-Reset` time; on a secondary (abuse-detection)
limit it waits a fixed 60 seconds; then retries automatically. This project
does not reimplement that logic - it would only be worse than GitHub's own
documented behaviour, already correctly followed by the library.

What this project adds: those backoff decisions are logged by PyGithub at
INFO level, but nothing configured logging by default, so a multi-minute
pause waiting for a rate-limit reset looked identical to a hang.
`configure_rate_limit_logging()` attaches a console handler
(`[RATE LIMIT] ...`) so the wait is explained instead of silent.

**Duplicate API calls within one audit are cached.** Several checks read the
same settings endpoint independently - four repository-level checks each read
`/actions/permissions` for a repository, two organization-level checks both
read `/actions/permissions/workflow`. Since the setting cannot change mid-audit,
`SecurityChecker._api_get()` caches by exact URL for the lifetime of one audit
run. The cache is per-instance and keyed by a URL that already includes the
repository or organization name, so it cannot mix up results between two
different repositories or leak across separate audit runs.

---

## Why a control is Not Applicable: three distinct reasons

`not_applicable` results carry a `reason_category`, because "cannot apply" has
three different causes with three different owners:

| Category | Meaning | Who can act on it |
|---|---|---|
| `structural` | Genuinely never applies here - no workflows to pin, an organization-only setting on a personal account, no rulesets defined | Nobody; nothing to do under any plan |
| `plan_restricted` | Blocked by the current GitHub plan - branch protection unenforceable on a private repo under Free | Whoever makes plan/billing decisions |
| `prerequisite_failed` | Contingent on a sibling control that already failed and reported the finding - nine checks depend on Branch Protection Rules and are not repeated nine times | Whoever fixes the named prerequisite |

The report shows a dedicated **"N controls blocked by the current GitHub
plan"** section listing only `plan_restricted` findings, separate from every
other Not Applicable reason - these are the only N/A findings with a concrete,
actionable fix, and burying them among findings nobody can act on defeats the
point of surfacing them at all.

## Three scoring metrics, not one

- **`compliance_score`** (unweighted): passed / evaluated. Every check
  counted equally.
- **`weighted_score`**: the same ratio, weighted by severity (see above).
  Drives `risk_level`.
- **`pass_rate_of_total_scope`**: passed / total (every control in the full
  40-control scope, not just what could be evaluated). The conservative
  figure - on a low-coverage audit, `compliance_score` can read as a
  near-passing grade while `pass_rate_of_total_scope` states plainly that
  only a fraction of the full control set is actually confirmed. The report
  header shows this figure prominently whenever coverage is below 60%.

---

## Owner category on every failing control

Every failing check is tagged with who can act on it - a category of access,
not a named person this tool has no way to know:

| Category | Meaning |
|---|---|
| Organization owner | An organization-level setting; requires org owner access |
| Repository admin | A repository Settings page, branch protection rule, or collaborator/team change; requires admin on that repository |
| Engineering team | A normal pull request - add a file, edit a workflow YAML - fixable by anyone with ordinary write access |

Plan-restricted findings are not in this scheme at all: their actual owner is
a billing/plan decision, and they have their own dedicated report section
(see above) rather than an owner-category tag.

**Both work-list tables are sorted by severity.** "Compliance Gaps Analysis"
sorts every finding critical-first across the whole report. "Failed Checks
Summary" keeps its repository grouping (that table's distinct purpose - see
everything wrong with one specific repository together) but sorts by
severity *within* each repository's block, so a repository's most urgent
finding is never below its housekeeping failures.

---

## Token visibility gaps

A token can successfully enumerate repositories with no error while seeing
only a subset of an account - a fine-grained token scoped to 3 of 40
repositories audits those 3 and reports nothing wrong, because nothing *is*
wrong from the API's point of view. The report cannot tell "audited
everything" from "audited everything this token could see" unless it checks.

Every audit compares what the token enumerated against the account's own
reported repository count (`public_repos + total_private_repos`). Three
outcomes:

| Confidence | Meaning | Shown as |
|---|---|---|
| `confirmed` | Enumerated count matches the account's total | "Full account: all repositories were audited (token visibility confirmed)" |
| `gap` | The token can see fewer repositories than the account has | "Partial coverage: N of M repositories..." - a prominent warning, not a footnote |
| `unconfirmed` | The account's own repository count is not visible to this token | Neither "full account" nor a gap is claimed - the report states what was audited and that completeness cannot be confirmed |

`unconfirmed` is common and not itself a problem: a plain organization member,
or anyone auditing an account other than the token's own, often cannot see
that account's total repository count at all (GitHub does not expose it to
every requester). The point is that the report never claims "Full account"
in that case - it says exactly what was and was not confirmed.

A `--repos` scope (auditing a deliberately chosen subset) is reported
separately from a visibility gap: one is a choice, the other is a limitation
the person running the audit may not know about. Grant the token
organization owner or broader repository access to close a real gap.

---

## Severity-weighted scoring

Two scores appear in every report:

- **Unweighted (`compliance_score`)**: passed / evaluated, every check counted
  equally. A missing `SECURITY.md` counts exactly as much as 2FA being disabled.
- **Weighted (`weighted_score`)**: each check contributes proportional to its
  severity - critical &times;4, high &times;3, medium &times;2, low &times;1.
  **Risk level is derived from this score**, not the flat one.

Severity is assigned per check, once, by what a failure of that specific
control enables - not by how many compliance frameworks map to it. See
`compliance_mapping.SEVERITY` for the full assignment and the reasoning
recorded next to it.

| Severity | Weight | Examples |
|---|---|---|
| Critical | 4 | 2FA Enforcement, Branch Protection Rules, Secrets Scanning, Action Version Pinning |
| High | 3 | Pull Request Reviews, Outside Collaborator Access, Organization Owner Count |
| Medium | 2 | Status Checks Before Merge, Commit Signing, Audit Logging |
| Low | 1 | SECURITY.md File, CODEOWNERS File, Repository Activity |

A single critical failure among many passing lower-severity checks moves the
weighted score and the risk level more than the same failure would move an
equally-weighted average - which is the point: a report where "no build
provenance" and "2FA is off" contribute identically to risk is not telling the
reader what actually matters.

The `severity_breakdown` field in the summary counts failures by level
directly (`{"critical": 1, "high": 0, "medium": 2, "low": 3}`), shown in the
report next to the pass/fail totals.

---

## Single-standard reports

Choose a framework on the start screen, or `--standard soc2|nist|iso27001|cis`.

A single-standard report contains **that framework and no other**. The
introduction, the control mappings, the gap analysis and the score all describe
one control set. A SOC 2 report that also scores NIST forces the reader to work
out which number applies to them, with the wrong one on the same page.

Scope is derived from the compliance mapping rather than a second hand-kept
list, so renaming a check cannot leave the two out of step. Today every check
maps to all four frameworks, so choosing one does not reduce the number of
checks run — it changes what the report says about them. If a future check maps
to only some frameworks, it will drop out of the others automatically.

`--standard all` (the default) keeps all four, as before.

The access inventory is included in every report regardless of the standard
selected. Access review is evidence for all four frameworks.

---

## Access review (4 checks + inventory)

An access review is the evidence auditors ask for first, and it is the one part
of this report that names people.

| Item | Personal | Organization | Requires |
|---|---|---|---|
| Access inventory (unscored) | partial | ✅ | repository read |
| Organization Owner Count | n/a | ✅ | organization owner |
| Direct Collaborator Grants | n/a | ✅ | repository admin |
| Outside Collaborator Access | n/a | ✅ | organization owner |
| Repository Admin Concentration | ✅ | ✅ | repository admin |

`Direct Collaborator Grants` compares direct user grants against team-derived
access, which has no meaning on a personal account — there are no teams to
review against. `Outside Collaborator Access` needs the organization-wide
outside collaborator list to classify a principal as external.

**The inventory is deliberately unscored.** A score gives an auditor a
conclusion; a roster lets them sample and reach their own. It lists every
principal per repository with the permission held, and flags the three patterns
that draw questions: a grant made directly to a user rather than through a team
(invisible to a team-based review), an external party holding standing access,
and admin permission (which permits disabling branch protection, rotating
secrets and deleting the repository).

⚠️ **The report now contains usernames.** It holds personal data and should be
stored and shared accordingly. See PRIVACY.md.

---

## Repository-level checks (31)

### Always available

Independent of account type and plan. Need only read access.

| Check | Notes |
|---|---|
| Repository Visibility | |
| SECURITY.md File | |
| CODEOWNERS File | |
| .gitignore Configuration | |
| Repository Activity | Flags no push in 365 days |
| Action Version Pinning | Reads workflow files |
| Workflow Permissions Declared | Reads workflow files |
| Untrusted Workflow Triggers | Reads workflow files |
| Self-Hosted Runner Exposure | Reads workflow files |
| Build Provenance Attestation | `not_applicable` if nothing is published |
| Dependency Scanning | |

The five workflow-file checks return `not_applicable` when a repository has no
`.github/workflows/`. Not using Actions is not a security failure.

### Branch protection — the plan matters most here

Eleven checks depend on branch protection or a ruleset:

- Branch Protection Rules
- Pull Request Reviews
- Status Checks Before Merge
- Commit Signing
- Dismiss Stale PR Reviews
- Code Owner Reviews
- Admin Bypass Prevention
- Linear History Required
- Force Push Protection
- Branch Deletion Protection
- Ruleset Enforcement Status

| Repository | Personal (any plan) | Organization Free | Team / Enterprise |
|---|---|---|---|
| Public | ✅ enforced | ✅ enforced | ✅ enforced |
| Private | ⚠️ not established | ❌ not enforced | ✅ enforced |

GitHub shows this directly when you open Settings → Rules on a private
repository under a free plan:

> Your rulesets won't be enforced on this private repository until you upgrade
> this organization account to GitHub Team.

When protection is not enforceable, the eleven checks report `not_applicable`
rather than failing — you cannot be marked down for a feature the plan does not
provide. The finding still names the remediation: upgrade to Team, or make the
repository public.

For a **personal** private repository the tool reports `unknown` rather than
assuming either way. GitHub's banner names a Team *organization* as the
requirement, so a paid personal plan is not established to lift the restriction.

**One missing setting produces one finding.** If the default branch has no
protection, only *Branch Protection Rules* fails; the other ten report
`not_applicable` and point back at it. Otherwise a single setting would account
for a third of the score.

### Secret scanning — needs a paid add-on on private repositories

| Check | Public repository | Private repository |
|---|---|---|
| Secrets Scanning | ✅ | needs GitHub Secret Protection |
| Push Protection | ✅ | needs GitHub Secret Protection |

Without the add-on the `security_and_analysis` block is absent from the API
response and both report `unknown`. This is indistinguishable from a token
without repository admin — if you see `unknown` here, check both.

### Actions settings — need repository admin

| Check | Requirement |
|---|---|
| Workflow Token Permissions | repository admin |
| Repository Actions Policy | repository admin |
| Action SHA Pinning Policy | repository admin |
| Fork Pull Request Workflows | repository admin |

`Fork Pull Request Workflows` grades a different control depending on
visibility. A private repository chooses whether fork workflows run at all; a
public one chooses which contributors need approval first.

⚠️ This check currently returns `unknown` in practice — the API field names for
the fork policy have not been confirmed and the candidate list has not matched a
live response. See `_FORK_WORKFLOW_KEYS` in `checks.py`.

---

## Measured coverage

Scored checks out of 64, for one public and one private repository:

| Target | Scored | Coverage |
|---|---|---|
| Personal account, free | 25 | 39% |
| Personal account, paid | 26 | 41% |
| Organization, free | 28 | 44% |
| Organization, Team | 29 | 45% |

Coverage below 100% is normal and expected. GitHub places a large share of these
controls behind paid tiers and admin permissions, and the tool reports what it
can actually see rather than guessing at the rest.

To raise your own coverage:

1. Grant the token **organization owner** access — unlocks all eight
   organization checks.
2. Grant **repository admin** — unlocks the four Actions settings checks, the
   secret scanning pair, and the rulesets listing.
3. Move private repositories to a **Team** organization — brings the eleven
   branch protection checks into scope.

---

## Token permissions

A fine-grained personal access token with **read-only** access to: Metadata,
Administration, Contents, Dependabot alerts, Secret scanning alerts. The tool
never writes anything and never needs write scopes.

If you use a classic token, `read:org` covers the organization checks. Do not
grant `repo` — it confers full write access to every repository, which a
read-only auditor has no use for.
