# Changelog

## [1.19.0] - 2026-08-13

Item 6 from the external review, the last item in this sequence: gap tables
sorted by severity, with an owner category per finding.

### Added - `OWNER_CATEGORY`: who can act on each of the 40 checks

Three categories, not a named person this tool has no way to know:

- **Organization owner** (9 checks) - all organization-level settings.
- **Repository admin** (23 checks) - a repository Settings page, branch
  protection rule, or collaborator/team change.
- **Engineering team** (8 checks) - a normal pull request: add a file, edit a
  workflow YAML. No elevated permission required.

Plan-restricted findings are deliberately excluded from this scheme - their
actual owner is a billing/plan decision, already routed to their own report
section in the previous release, not one of these three categories.

### Changed - "Compliance Gaps Analysis" sorted by severity

Critical findings first, across the whole report, instead of alphabetical by
check name. Verified against the reference audit: `Actions Allowed Actions
Policy` and `Repository Actions Policy` (both critical) now appear first,
ahead of five high-severity findings, ahead of medium, ahead of low - a
reader triaging a fourteen-row list no longer has to scan past low-severity
housekeeping to find what actually needs attention first.

### Changed - "Failed Checks Summary" sorted by severity within each
repository

This table's distinct purpose is seeing everything wrong with one specific
repository together, so the existing repository grouping was kept rather than
flattened into a single severity-only ordering that would have scattered a
repository's findings apart from each other. Severity ordering now applies
*within* each repository's block instead.

### Added - Owner column

Both tables gained an Owner column. Verified end to end against the same
reference audit: `Actions Allowed Actions Policy` (an organization-level
policy) reads "Organization owner"; `Repository Actions Policy` (the same
concern, but a repository setting) reads "Repository admin" - the owner
category tracks who holds the specific setting, not just which control family
it belongs to.

### Tests

236 total, including one confirming the Owner value on each row corresponds
to that row's own check rather than a value copied from elsewhere in the
table, and one confirming repository grouping in Failed Checks Summary
survives the addition of severity sorting rather than being flattened away.

### External review, concluded

This closes the sequence of changes evaluated from the external review of the
scoring model (items 1-4 and 6; item 5, structured `unknown_reason`
categorization, remains its own separately-scoped project, not started).
Summary of what was adopted, adapted, or declined:

- **Adopted as proposed**: token visibility gap detection (item 4) - the
  highest-value finding in the review, addressing a genuine blind spot this
  project had not previously considered.
- **Adopted with a refinement the review did not have**: splitting Not
  Applicable by cause (item 2) turned out to need three categories, not the
  two proposed, once the actual code paths were audited.
- **Adopted, generalized**: the review's remediation-table concept (item 6)
  already existed as "Compliance Gaps Analysis"; severity sorting and an
  owner category were the genuinely missing pieces.
- **Adopted, reframed**: control_coverage_pct and pass_rate_of_evaluated
  (item 1) already existed under different names; pass_rate_of_total_scope
  was the one genuinely new metric, now added (item 3).
- **Declined as proposed, own derivation preferred**: several suggested
  secondary SOC 2 criteria (item 3's table) were checked against the existing
  mappings and found less precise in multiple cases - adopting them wholesale
  would have been a regression, not an improvement.

## [1.18.0] - 2026-08-13

Items 2 and 3 from the external review: splitting Not Applicable by cause,
and a third, conservative scoring metric.

### Added - `reason_category` on every Not Applicable result

The review proposed two categories (plan-caused vs. structural). Auditing the
actual `not_applicable()` call sites found the code already has **three**
distinct rationales, not two - conflating the third into either of the first
two would misattribute findings:

| Category | Meaning |
|---|---|
| `structural` | Genuinely never applies - no workflows, an org-only setting on a personal account, no rulesets defined |
| `plan_restricted` | Blocked by the current GitHub plan - fixable by a plan/billing decision |
| `prerequisite_failed` | A sibling control already failed and reported the finding (nine controls depend on Branch Protection Rules) |

Verified the distinction actually holds at runtime, not just in the code
comments: a private repository on a free plan with no protection at all
correctly tags all ten dependent findings `plan_restricted` (the plan blocks
configuring protection to begin with), while the identical scenario on a paid
plan correctly tags them `prerequisite_failed` instead (nothing about the
plan is at fault - nobody turned branch protection on).

Tagged at the source in each check, not inferred from message text after the
fact - the same principle already applied to `unknown` vs `not_applicable` in
earlier releases: a second, derived fact about a result is a second source of
truth that drifts the moment the first one is edited.

### Added - "N controls blocked by the current GitHub plan" report section

Lists only `plan_restricted` findings, grouped by repository, separate from
every other Not Applicable reason. These are the only Not Applicable findings
with a concrete, actionable fix (upgrade the plan, or accept the gap) -
burying them among findings nobody can act on defeats the point of surfacing
them.

### Added - `pass_rate_of_total_scope`

A third scoring metric alongside `compliance_score` (unweighted) and
`weighted_score`: passed / total, where total includes every control in the
full scope, not just what could be evaluated. This is the conservative
figure the review specifically asked for - on a low-coverage audit,
`compliance_score` can read as a near-passing grade while this figure states
plainly what fraction of the complete control set is actually confirmed.
Shown in the report header whenever coverage is below 60%, and in the score
calculation breakdown always.

Computed identically in both places a summary is built
(`_calculate_summary()` and `scope_results_to_standard()`), keeping the
per-standard and full-audit summaries from drifting apart the way several
other duplicated calculations have in earlier releases.

### Not implemented from the same review, still pending

- Multi-criterion SOC 2 mappings and a re-derivation pass on secondary
  criteria.
- Structured `unknown_reason` categorization (insufficient token scope / plan
  limitation / API field missing) - correctly scoped as its own project in
  the previous release, still not started; would need tagging dozens of
  `unknown()` call sites at the source, matching the same source-of-truth
  discipline applied to `reason_category` in this release.
- Gap table sorted by severity with a generic owner category.

### Tests

228 total, including a runtime check that the same branch-protection
scenario produces `plan_restricted` on a free plan and `prerequisite_failed`
on a paid one - the distinction the whole feature depends on.

## [1.17.0] - 2026-08-13

Token visibility gap detection - the highest-priority item from an external
review of the scoring model. A token can enumerate repositories with no error
while seeing only a subset of an account, and nothing in the report
previously distinguished that from genuinely full coverage.

### The problem

A fine-grained token scoped to 3 of 40 repositories in an organization
audits those 3 successfully - no error, no warning, nothing wrong from the
API's point of view. The scope banner said "Full account: all accessible
repositories were audited," which is technically true and functionally
misleading: it reads as comprehensive coverage while auditing 7.5% of the
account. This is the same class of confident-wrongness this project has
repeatedly found and fixed elsewhere (the personal-account/organization
mismatch, an unenforced ruleset read as protection) - a report stating more
certainty than the data supports.

### Added - `GitHubAuditor._check_repo_visibility()`

Compares what the token enumerated via `get_repos()` against the account's
own reported total (`public_repos + total_private_repos`), immediately after
enumeration and before any `--repos` scoping is applied - so a deliberate
scope choice and an involuntary visibility limit are never conflated.

Three outcomes, all handled explicitly rather than assuming either extreme:

- **`confirmed`**: the counts match. "Full account" is now something the
  report can actually back up, not merely something no `--repos` flag was
  used to contradict.
- **`gap`**: the token sees fewer repositories than the account has. Logged
  as a `[WARN]` during the run and shown as a prominent, differently-colored
  banner in the report - not a footnote.
- **`unconfirmed`**: `public_repos`/`total_private_repos` are themselves
  permission-gated and not always visible to every token (a plain
  organization member, or anyone auditing an account they do not own, often
  cannot see its total repository count at all). In this case the report
  states what was audited and explicitly that completeness could not be
  confirmed - it never falls back to claiming "Full account" by default.

### Changed - scope banner

Rewritten to check `repository_visibility` before making any claim about
account-wide coverage. A `gap` renders in red with a remediation note (grant
broader access, or confirm the gap is intentional); an `unconfirmed` result
states the audited count without asserting completeness either way.

### Changed - `history.json` records visibility confidence

Cheap to store (a handful of scalar fields, not per-repository) and lets a
trend be tracked: visibility that degrades between runs (a token's access
was narrowed) or improves (access was granted) is now visible over time, the
same way score trends already are.

### Not implemented from the same review, and why

An external review proposed five further changes, evaluated on their merits
rather than adopted wholesale:

- **Splitting `not_applicable` into a plan-caused vs. structural reason.**
  Valid, and the code already has the two distinct code paths needed
  (`_get_protection`'s `not_enforceable` state vs. `_org_only`'s structural
  guard) - implementing this without inferring the reason from message text
  is the right next increment, not done in this release.
- **`pass_rate_of_total_scope`** as an explicit third metric alongside
  `compliance_score` and `coverage_percent`. Cheap, still pending.
- **Multi-criterion SOC 2 mappings** (currently one control per check, unlike
  NIST/ISO which already support several). The reviewer's proposed secondary
  criteria were not adopted as-is - spot-checking them against the existing
  mappings found several were less precise than what is already assigned
  (e.g. CC7.1 proposed for `Actions Allowed Actions Policy`, where CC6.8 -
  prevention of unauthorized software - is the closer fit for a control that
  prevents rather than detects). Worth doing, but needs its own re-derivation
  pass, not a copy of the proposal's table.
- **Structured `unknown_reason` categorization** (insufficient token scope /
  plan limitation / API field missing). Correct in principle, but properly
  implemented means tagging the reason at every `unknown()` call site across
  `checks.py` - dozens of locations - rather than inferring it from message
  text, which would be a second, driftable source of truth for the same fact.
  Sized as its own project, not a quick addition.
- **Remediation table sorted by severity with an owner category.** The gap
  table already exists (`Compliance Gaps Analysis`) with severity and repo
  columns; sorting by severity and adding a generic owner category (security
  admin / billing decision / engineering team, not a named person) is a
  reasonable next pass building on the reason-category work above.

### Tests

216 total, including one confirming a visibility gap is never reported as
negative if the token somehow enumerates more repositories than the
account's own reported total (a stale cached total, or a race between count
and listing).

## [1.16.0] - 2026-08-13

Phase 4 of the improvement roadmap, done out of sequence at request: audit
history enriched with per-repository tracking, and comparison against the
previous audit of the same organization.

### Added - `history.py`: compact per-run records and diffing

`history.json` previously stored four fields per run - org, timestamp, and a
single flat score. That answers "did the score change" but not "did *this*
repository get better", which is what a recurring audit is for.

Each run now records, per repository: pass/fail counts, weighted score, and a
check-name-to-status map. Full check messages, remediation guidance, and the
access inventory (usernames) are deliberately excluded - every field added
here is multiplied by every run ever stored.

`find_previous_run()` looks up the most recent prior run for the same
organization (case-insensitive), skipping legacy entries that predate this
feature and have nothing to diff against. `diff_runs()` compares two runs:
per-repository newly-failing/newly-passing/coverage-changed checks, a
per-repository score delta, and which repositories are new or no longer in
the audited set.

### Added - "Changes since the previous audit" section

Shown in both the live dashboard and the downloadable report, whenever a
previous run exists for the organization. States the weighted-score delta,
then per repository: which checks regressed (red), which were fixed (green),
and coverage changes (a check moving to/from Not Checked or N/A - a
permission or plan change, not a security finding, kept visually separate
from real regressions). New or removed repositories are noted without being
treated as a regression by default - usually a rename, archival, or scope
change.

### Changed - History page groups runs by organization with a trend

Previously a single flat table across every organization ever audited, sorted
however dict iteration happened to order it. Now grouped by organization,
newest run first, with a trend arrow showing the weighted-score change versus
the previous run for that same organization - so a repository's progress
across successive audits is visible together instead of scattered among
unrelated organizations.

### Fixed - a fourth independent copy of the risk-level thresholds

The History page's score-color logic re-derived LOW/MEDIUM/HIGH bands from a
raw score, a fourth copy of logic already found and fixed three times in
v1.14.0 (in `_calculate_summary`, `_get_risk_css_class`, and the dashboard
template). Now derives color from the stored `risk_level` text directly. A
raw-score fallback is kept, but only for legacy entries written before
`risk_level` was stored at all - every entry `build_history_entry()` writes
always includes it, so the fallback cannot apply to new data.

### Fixed - a corrupted `history.json` could prevent the app from starting

Loading history at startup used a bare `json.load()` with no error handling.
An interrupted write (crash mid-write, disk full) would leave a corrupted
file that raised on every subsequent startup, turning a recoverable data
problem into total unavailability. Now caught, the corrupted file is renamed
to `history.json.corrupted` for inspection, and the app starts with empty
history rather than failing to start at all.

### Fixed - trend arrow rendered as escaped text, not markup

`render_template_string`'s Jinja autoescaping turned the trend arrow helper's
`<span>` output into literal `&lt;span&gt;` text. Needed the same `|safe`
filter already used elsewhere in this file for wiki content - found by
actually rendering the page end-to-end and reading the output, not by
re-reading the template source, which looked correct on its own.

### Tests

208 total.

## [1.15.0] - 2026-08-11

Phase 2 of the improvement roadmap: rate-limit backoff visibility and
deduplication of repeated API calls within a single audit run.

### Added - rate-limit backoff made explicit and visible

PyGithub 2.5.0 already ships `GithubRetry`, which correctly retries a 403
that indicates a rate limit: waiting until `X-RateLimit-Reset` for the
primary (hourly) limit, or a fixed 60 seconds for the secondary
(abuse-detection) limit, then retrying automatically. This was already
active by default - `Github(token)` installs it without being asked - so
there was nothing to reimplement, and reimplementing it would only have been
worse than the library's own documented behaviour.

Two things were missing:

- The policy was implicit, relying on `Github()`'s own default. A future
  PyGithub upgrade changing that default would have silently changed audit
  behaviour with no signal anywhere in this codebase. `github_auditor.
  GITHUB_RETRY_POLICY` now constructs it explicitly, shared by both call
  sites (`GitHubAuditor` and the web app's repository-listing endpoint).
- PyGithub logs each backoff decision at INFO level, but nothing in this
  project configured logging, so those messages were silently dropped by
  Python's default (no handler, WARNING level). A multi-minute pause waiting
  for a rate-limit reset looked identical to a hang. `configure_rate_limit_
  logging()` attaches a console handler (`[RATE LIMIT] ...`) so the wait is
  explained.

### Fixed - four repeated API calls per repository, two per organization

`Repository Actions Policy`, `Action SHA Pinning Policy`, and `Fork Pull
Request Workflows` each independently called `/actions/permissions` for the
same repository - four identical requests per repository, every audit.
`Actions Default Token Permissions` and `Actions Pull Request Approval` did
the same for `/actions/permissions/workflow` at the organization level.

`SecurityChecker._api_get()` now caches by exact URL for the lifetime of one
`SecurityChecker` instance (one audit run). The setting cannot change
mid-audit, so a repeated request to the same URL wastes both time and
rate-limit budget for data already in hand. The cache cannot mix up results
between repositories: the URL already includes the repository name, which is
unique within one owner on GitHub.

Verified by counting actual requests through a call-tracking test double,
not just by checking that results were still correct - a check_repository()
pass against a repository with Actions data configured now makes exactly one
call to `/actions/permissions`, down from four.

### Fixed - seven tests that happened to rely on the old duplicate-request
behaviour

Several existing tests constructed multiple `FakeRepo()` instances without
distinct names, all defaulting to `name="app"` and therefore the same URL. In
production this can never happen - GitHub does not allow two repositories
with the same name under one owner - so the fix was to give each test
fixture a distinct name, matching real usage, rather than to weaken the
cache.

### Tests

195 total, including four that specifically prove deduplication by counting
real API calls rather than only inferring it from correct results.

## [1.14.0] - 2026-08-11

Phase 1 of a broader improvement plan: severity-weighted scoring. Every check
previously contributed an equal 1/40 to the score regardless of what its
failure actually enables.

### Added - severity classification for all 40 checks

`compliance_mapping.SEVERITY` assigns critical/high/medium/low to every
check, based on what a failure of that specific control enables - not on how
many frameworks map to it. Ten critical (2FA Enforcement, Branch Protection
Rules, Ruleset Enforcement Status, Secrets Scanning, Push Protection,
Dependency Scanning, Actions Allowed Actions Policy, Repository Actions
Policy, Action Version Pinning, Self-Hosted Runner Exposure), fourteen high,
twelve medium, four low. `test_every_mapped_check_has_a_severity` guards
against an unassigned or orphaned entry.

### Added - `weighted_score`, and risk level now derives from it

Each check contributes proportional to its severity (critical &times;4, high
&times;3, medium &times;2, low &times;1) rather than counting equally.
`risk_level` - previously derived from the flat percentage - now derives from
the weighted one. A single critical failure among otherwise-passing checks
now visibly moves risk classification instead of being one vote among forty.

Implemented in both places a summary is computed: `_calculate_summary()` in
`github_auditor.py` (the full-audit summary) and `scope_results_to_standard()`
in `compliance_mapping.py` (the per-standard summary), which previously
duplicated the aggregation logic and would otherwise have drifted out of sync
with each other exactly like the risk-threshold copies below.

`severity_breakdown` (failure counts by level) is also new in the summary.

### Fixed - three independent copies of the risk-level thresholds

Found while wiring the badge color to the new weighted score:

- `report_generator.py`'s `_get_risk_css_class(score)` re-derived LOW/MEDIUM/
  HIGH/CRITICAL bands from a raw score independently of `risk_level`'s own
  thresholds in `github_auditor.py`. Now derives the CSS class directly from
  the `risk_level` string instead of a second set of numeric bands that could
  disagree with the first.
- The dashboard template in `app.py` had a **third**, independent copy - and
  its own thresholds were backwards relative to its CSS class names
  (`risk-high` is styled green, `risk-low` red; the template applied
  `risk-high` at `score >= 90`, which happens to be correct only by the
  class-naming coincidence, not by the risk-level logic itself). It also
  read the flat score, so it could show a badge color contradicting the
  weighted-score-driven risk-level text right next to it. Now derives the
  class from `risk_level` directly, matching the fix above.

Three copies of the same threshold logic is the same failure mode this
project has fixed repeatedly in other forms (duplicate account-type
detection, duplicate compliance-scope aggregation) - independent copies of one
fact drift the moment one is updated and the others are not.

### Changed - report

- Score header shows both scores, weighted primary, with the unweighted one
  and a one-line explanation alongside it.
- Severity breakdown (failure counts by level) shown next to the pass/fail
  totals.
- "How Compliance Score is Calculated" section rewritten: corrected the
  formula (it previously divided by `total_checks`, which includes Not
  Checked/N/A, rather than `evaluated_checks` - a pre-existing inaccuracy
  found while updating this section), and explains both formulas.
- "Security Checks & Compliance Mapping" and "Compliance Gaps Analysis" both
  gained a **Severity** column.

### Documented

APPLICABILITY.md and README.md both explain the two scores and the severity
table.

### Tests

188 total.

### Next phases

Per the improvement roadmap: (2) deduplicating repeated API calls to the same
endpoint and adding rate-limit backoff, (3) parallel repository scanning,
(4) diffing between audit runs via an expanded `history.json`, (5) bypass-list
reading and unimplemented ruleset rule types (`copilot_code_review`,
`merge_queue`), (6) CI workflow for this project's own test suite, (7) exit-
code thresholds and SARIF export. Fork PR policy field names remain blocked
on a live API response that has not matched any candidate tried so far.

## [1.13.0] - 2026-08-11

Repository name added to every finding in the two compliance tables. Fixes an
accuracy defect discovered while making that change, not just a missing
column.

### Fixed - a real accuracy bug in multi-repository audits

`_collect_checks` collapsed every repository's result for a given check into
a single row, arbitrarily preferring whichever result was inserted first. On
an audit covering more than one repository, if a check passed in one
repository and failed in another, only one of those two facts was ever shown
- with no indication that the other repository disagreed. In "Compliance Gaps
Analysis" specifically, this could **under-count real failures**: a check
failing in three repositories was reported as at most one gap, not three.

Replaced with `_collect_check_rows`, which returns one row per (check,
repository) pair rather than one row per check name. Nothing is collapsed
or arbitrarily chosen anymore.

### Changed - "Security Checks & Compliance Mapping"

Added a **Repository** column, first in the row. Organization-level checks
are labelled "Organization" since they are not a property of any single
repository. A check run against N repositories now produces N rows instead
of one.

### Changed - "Compliance Gaps Analysis"

Same fix, same new column. The summary line changed from "N control(s) fail"
to "N finding(s) fail" to reflect that the count is now per (check,
repository) instance, not per distinct control name - a check failing in
three repositories is three findings, not one.

"Failed Checks Summary" already had a repository column (added in v1.11.0)
and was not affected by this defect, since it was never built on the
collapsing `_collect_checks`.

### Fixed - version.py had not been bumped since v1.11.0

`version.py`'s `__version__` was still `"1.11.0"` despite two releases having
shipped since. The CLI banner, web footers and report scope banner all read
from it and were all quietly wrong. Sample output in README, QUICKSTART and
SECURITY_AUDIT.md updated to match.

### Added - drift guard

`test_sample_outputs_in_docs_use_the_current_version` checks
"GitHub Security Auditor vX.Y.Z" and "Reflects: vX.Y.Z" patterns specifically
against `version.py`, distinguishing a stale version claim from a legitimate
historical reference (e.g. "the access inventory, added in v1.9.0"), which
must not be flagged.

### Tests

177 total, including a direct regression test reproducing the two-repository
disagreement case that motivated this fix.

## [1.12.0] - 2026-08-11

"Find repositories, then pick" flow for the web UI, replacing the free-text
repository field.

### Added - repository picker

The start form's "Repositories" field is now a button, not a text input:

1. Enter token and organization/username.
2. Click **Find Repositories** - calls the new `POST /api/list-repositories`
   endpoint, which resolves the account (same logic the audit itself uses)
   and lists every repository with its name, visibility, archived status and
   description.
3. A checkbox list appears, all selected by default, with a filter box and
   Select all / Select none. The count updates live.
4. Submitting the form sends exactly the checked names to `/api/start-audit`.

Leaving the picker unused (never clicking the button) still audits every
repository, preserving the previous default behaviour for anyone who just
wants to run a full audit.

### Added - `POST /api/list-repositories`

Read-only and synchronous - a single paginated GitHub API call, not a
background thread, since there is no per-repository work to do. Capped at
1000 repositories with a `truncated` flag; returns the same target-mismatch
warning the audit itself would raise (e.g. selecting "Personal account" for a
name that is actually an organization). Errors go through the existing
`_safe_error()` sanitiser - never a raw exception string, which can carry
request context in some HTTP client libraries.

### Changed - shared target resolution

`GitHubAuditor._resolve_target()`'s organization/personal-account detection
was extracted into a module-level `resolve_github_target(gh, name,
selection)`, used by both the audit itself and the new listing endpoint. Two
independent copies of "is this an organization or a personal account" is
exactly the kind of drift this project has spent several releases finding and
fixing elsewhere; this avoids creating a third instance of that pattern.

### Fixed - documentation

- README's "Audit Results" JSON example was entirely fabricated: `"checks":
  [...]` as a list (the real structure is `{"organization": {...},
  "repositories": {...}}`), and a `"compliance_mapping"` block with a
  `SOC2`/`NIST`/`ISO27001`/`CIS` shape that does not exist anywhere in the
  codebase. Replaced with a summary matching the fields
  `audit_organization()` actually writes, verified by a new test that reads
  the method's source rather than trusting the prose to stay in sync.
- Added `/api/list-repositories` to the endpoint list.
- Usage flow diagram now shows the repository-picker step.

### Tests

171 total, including an end-to-end test that lists repositories, selects a
subset, starts an audit scoped to it, and asserts only the selected
repositories were audited.

## [1.11.1] - 2026-08-11

Full re-read across five areas: UTC time, token security, check logic,
repository-scope selection, and documentation-to-code drift. Several real
defects found in each.

### Fixed - dates and times (UTC everywhere)

Every `datetime.now()` in the codebase was naive - no timezone, dependent on
the host's local clock. Fixed in `app.py`, `github_auditor.py` and
`report_generator.py`:

- All timestamps now use `datetime.now(timezone.utc)`.
- The CLI session-id timestamp changed from a local-time string to
  `%Y%m%dT%H%M%SZ` (UTC, ISO 8601 basic format).
- The HTML report's "Audited" line uses a new `_format_utc()` helper that
  renders any ISO timestamp as an explicit `... UTC` string, tolerating naive,
  aware, or malformed input rather than silently printing nothing (`%Z` on a
  naive datetime formats as an empty string with no error).

### Fixed - a real token-lifetime bug

`run_audit(token=github_token)` captured the token as a **default parameter**,
evaluated once when the function was defined. Setting `token = None` inside
the function cleared only that local name - the outer `github_token` in the
request handler, and the token still sitting in `data['token']` (the raw
parsed request body), were never cleared and remained reachable for as long as
the enclosing objects lived.

Fixed: the token is passed explicitly via `Thread(target=run_audit,
args=(github_token,))`, and `data['token']` plus the outer `github_token` are
both set to `None` immediately after the thread starts, not left to the
thread's own cleanup.

### Fixed - branch protection logic (a real false-negative)

`_enforcement()` suppressed **classic branch protection** under the same
free-plan restriction as rulesets. The non-enforcement banner, captured live
twice in this project's history, names rulesets specifically and never
mentions classic protection. The suppression had no evidence behind it and
hid a genuinely enforced setting on any repository using classic protection on
a free private repo. Classic protection is now trusted independently of
ruleset enforcement status.

### Fixed - ruleset enforcement checked the wrong rulesets

`Ruleset Enforcement Status` evaluated every ruleset in the repository,
including tag- and push-scoped ones. A disabled tag ruleset could fail this
check while `Branch Protection Rules` correctly passed from an unrelated,
active branch ruleset - two findings that looked contradictory for reasons the
report never explained. Non-branch targets (`tag`, `push`) are now excluded
by denylist, so an unrecognised or missing target stays in scope rather than
being silently dropped.

### Fixed - message accuracy

- The 2FA "fail" branch still carried the disproven "since 2024" completed-
  rollout claim that the "pass" branch had already been corrected to drop.
- `Repository Admin Concentration` appended a literal `...` to the admin list
  even when every name was already shown in full (4-5 admins, never
  truncated) - a false suggestion of hidden entries.
- "Auditors raise this as a availability finding" → "an availability finding".
- Removed dead code (`AccessReview._elevated`, never called).

### Fixed - repository-scope API bug (found via end-to-end testing)

`POST /api/start-audit` handled a `repos` value that was already a list (as
the browser's client-side JS sends, having split on commas first) but wrapped
any other value - including a raw comma-separated string, the same format the
CLI's `--repos` flag accepts - into a single-element list without splitting
it. A direct API call with `"repos": "a,b"` silently produced a scope of one
bogus repository name matching nothing, auditing zero repositories with no
error. Confirmed and fixed by an actual end-to-end run through the Flask test
client, not by re-reading the code.

The endpoint now splits a string payload on commas server-side (matching the
CLI), and normalises a list payload (trimming whitespace, dropping empty
entries) so both input shapes are held to the same standard.

### Fixed - documentation drift, five files

`README.md`, `QUICKSTART.md`, `TOOL_SUMMARY.md`, `SECURITY.md` and the in-app
wiki all still recommended the `-t TOKEN` CLI flag (removed in v1.3.0 for
shell-history/`ps aux` exposure) and the `repo, admin:org_hook, read:org`
scope set (replaced in v1.3.0 with a read-only fine-grained token) - several
of them self-contradicting in the same paragraph ("grant `repo`" followed by
"do NOT grant... write permissions"). QUICKSTART.md's sample output, check
counts and organization/repository split were all invented and matched no
shipped version.

**SECURITY_AUDIT.md was rewritten entirely.** The previous version: described
VirusTotal/AbuseIPDB integrations that do not exist in this project (they
belong to a different one); quoted `PyGithub==1.59`, `Flask==2.3.0` and a
`python-dotenv` dependency never in `requirements.txt`; claimed "GitHub
usernames ❌ NEVER STORED", directly false since the access inventory
(v1.9.0) stores them by design; and closed with a fabricated self-
certification ("Security Review Team", "APPROVED FOR PUBLIC RELEASE", a
fixed audit date) presenting an AI-written document as third-party sign-off.
The replacement describes the current, verified implementation, cross-
references PRIVACY.md for the access-inventory change, and lists what remains
unverified instead of certifying completeness.

The same phantom VirusTotal/AbuseIPDB content was also removed from
`PRIVACY.md` and `README.md`.

`APPLICABILITY.md`'s organization-level table was missing `Organization Owner
Count` and stated "(8)" where the engine has 9 organization-level checks.

The check-count drift guard (`test_check_count_claims_match_the_code`) only
matched the plural "security checks/controls" and missed the singular
"security check implementations" phrasing, under which "32" had survived in
two files after every other count moved to 40. The regex now matches both.

### Added - drift guards

Five new tests guard against every class of drift found in this pass:
stale token flag/scope advice, phantom third-party integrations, stale
dependency versions, fabricated certification language, and the false
no-usernames claim.

### Tests

164 total.

## [1.11.0] - 2026-08-10

Organization-Level Findings and Failed Checks Summary rebuilt as tables. Version
surfaced across the interface. Repository-scoped audits wired end to end.

### Changed - Organization-Level Findings is now a table

Same shape as the other two mapping tables: control, requirement per framework,
result, what was observed, and the remediation. Previously a stack of cards with
a message and no path to a fix.

### Changed - Failed Checks Summary is now one flat table

Every failure across every repository, one row each, with the **repository name
as its own column** rather than nested under a per-check heading. The previous
layout grouped by check first and repository second, which meant scanning a
2000-line report to find everything wrong in one specific repository. Sorted by
repository, so that is now one contiguous block.

### Fixed - `scope_warning` was always null in the output

`audit_results["scope_warning"]` was captured into the results dict at
construction time, before repository names were resolved against the account's
actual repositories - where the warning is actually set. Every scoped audit with
an unmatched name logged the warning to the console and then reported `null` in
the JSON and omitted it from the report. The field is now refreshed after
resolution, immediately before the summary is calculated.

### Added - scope banner in the report

Every report opens with a line stating what was actually audited: the full
account, or a named subset with the repository list and any unmatched names.
Carries the tool version. A restricted-scope audit that reads identically to a
full one invites the reader to assume more coverage than was run.

### Added - version on every page

`version.py` is the single source of truth; the CLI banner, all five web page
footers (previously only the landing page), and the report's scope banner all
read from it. `test_no_hardcoded_control_counts_in_report_prose` already exists
for control counts - this is the same fix for the version string, which had
drifted before by the same mechanism.

### Verified - repository scope was already wired

`--repos` on the CLI and the "Repositories (optional)" field on the web form
both restrict `audit_organization()` to a named subset; organization-level
checks still run against the whole account, since they are not a property of
any single repository. Confirmed end-to-end: a two-repository account scoped to
one name audits only that repository, the unmatched name surfaces as a warning
in both the console and the results, and the excluded repository does not appear
anywhere in the rendered report.

### Tests

147 total.

## [1.10.1] - 2026-08-10

Rendering bug in the published report, and both compliance sections rebuilt as
actionable tables.

### Fixed - a template call printed as literal text

The Audit Scope section read `{self._framework_blocks()}` in the published
report. When 1.10.0 replaced the hardcoded framework list, the call was inserted
into a plain string rather than an f-string, so it was never evaluated.

`test_no_unrendered_placeholders_in_the_report` now regex-scans the rendered
output of all five report variants for any surviving `{...}` placeholder. This
class of defect is invisible to every other test, because the report generates
without error and only a reader notices.

### Fixed - "Why These 21 Controls"

Stale in two more places, having survived 21 -> 23 -> 32 -> 36 -> 40. The count
guard added in 1.5.0 matched "N security checks/controls" and missed this
phrasing entirely. Counts in the report are now derived from the mapping at
render time, and a second guard fails on any hardcoded count in prose.

### Changed - Security Checks & Compliance Mapping is now a table

| Column | Contents |
|---|---|
| Security control | Check name, and what it verifies |
| Requirement | Control identifiers and titles, for the standard in scope |
| Result | Passed / Failed / Not Checked / N/A |
| Recommendation | The specific remediation |

Four columns for a single-standard report, seven when all frameworks are
included. A list of names with ticks tells a reader nothing they can act on; the
requirement and the fix belong on the same line as the finding.

### Changed - Compliance Gaps Analysis is now a work list

Failing controls only, each with the requirement it fails to evidence, **what
was actually observed** (the finding text from the check itself) and the
remediation. Not Checked and N/A are excluded and stated as excluded, so the
list is not mistaken for full coverage.

### Added - CONTROL_GUIDANCE

`verifies` and `remediation` for all 40 controls, held beside the framework
mapping. `test_every_mapped_check_has_guidance` fails on a missing or empty
entry, because a row with a blank recommendation column is a row nobody can act
on.

### Tests

124 total.

## [1.10.0] - 2026-08-10

Single-standard reports, and the access inventory extended with capability
columns.

### Added - one report, one standard

`--standard soc2|nist|iso27001|cis|all`, and a selector on the start screen.

A single-standard report contains that framework and no other. The introduction,
control mappings, gap analysis, standards table and score all describe one
control set, and the JSON export is scoped identically. A SOC 2 report that also
scores NIST forces the reader to work out which number applies to them, with the
wrong one on the same page.

Four parametrised tests assert the isolation directly: each report is searched
for the other three frameworks' names and control-identifier prefixes, and must
contain none of them. That check caught leaks in the static header, the
introduction and the framework description list, which are now generated from
the standard in scope rather than hardcoded.

Scope is derived from `COMPLIANCE_MAPPING` rather than a parallel hand-kept list
per standard. A second list is a second source of truth and drifts the moment a
check is renamed. Today every check maps to all four frameworks, so selecting
one does not reduce the checks run — it changes what the report says about them.

### Added - capability columns in the access inventory

Each principal now shows what the permission actually permits: push, merge,
change settings, delete, and a risk level. "Admin" means little to a reviewer
without knowing it can delete the repository.

### Fixed - GitHub's two permission vocabularies

The collaborators endpoint returns `push`/`pull`; `get_collaborator_permission`
returns `write`/`read`. Code that knows only one vocabulary silently buckets a
`read` user into the default. `normalise_permission()` maps both explicitly.

### Not adopted from the parallel branch

The uploaded archive builds these features on the v1.2.2 engine, which still
carries every defect from the original review — `repo.protected_branches`,
`secret_key = 'github-auditor-2026'`, `debug=True`, client-supplied session ids
and no three-state model. Its live output confirms it: every repository reports
`'Repository' object has no attribute 'protected_branches'`.

Ideas taken from it: capability columns and per-level risk. Ideas rejected:

- Collecting member **email addresses**. Usernames are already personal data;
  email escalates the report's sensitivity for no auditing benefit.
- `is_org_member` resolved by calling `get_members()` inside the per-collaborator
  loop — quadratic API calls against a rate-limited endpoint.
- `except: pass` around every collection step, which turns a permission error
  into a silently empty roster.
- A hand-maintained per-standard check list using ISO 27001:2013 numbering and
  "SOC 2 Type II", both already corrected here.

### Tests

112 total.

## [1.9.0] - 2026-08-09

Access review. 36 checks -> 40, plus an unscored inventory.

### Added - access inventory

A new report section listing every principal with access to each repository:
username or team, whether access is direct, team-derived or an outside
collaborator, and the permission held.

**It is deliberately unscored.** A score gives an auditor a conclusion; a roster
lets them sample it and reach their own. This is the artefact an access review is
actually conducted against, and no compliance score substitutes for it.

Rows are annotated where an auditor pushes back:

- a grant made **directly to a user** rather than through a team — it appears in
  no team roster, so a team-based review never surfaces it;
- an **outside collaborator** — an external party with standing access;
- **admin** — permits disabling branch protection, rotating secrets and deleting
  the repository. Most holders need Maintain instead.

### Added - four scored findings

| Check | What an auditor asks |
|---|---|
| Direct Collaborator Grants | Why is this permission outside the team model? |
| Outside Collaborator Access | Is this external party still engaged, and at this level? |
| Repository Admin Concentration | Why does each admin need settings control? |
| Organization Owner Count | Both extremes: one owner is a continuity risk, many is standing privilege |

Outside collaborators take precedence over the direct-grant classification, so an
external contractor is reported once by the check that describes them best rather
than twice.

### Privacy - the output changed category

Earlier versions produced configuration facts about repositories. The report now
**identifies individuals and describes their privileges**. That is personal data
in the ordinary sense and the regulatory one.

Nothing about transmission changed — the inventory is built locally and written
only to `audit_results/`. But PRIVACY.md now states plainly that the report
belongs with access-review material rather than a shared drive, that an
organisation running it is the controller of that file, and that findings can be
shared without circulating the roster.

### Tests

93 total, including one asserting a hostile username is escaped in the inventory
table — the third place escaping has had to be verified independently.

## [1.8.0] - 2026-08-09

Account type is now chosen before the audit runs, and applicability is
documented rather than left to be inferred from the results.

### Added - account type selection

The start screen asks "What are you auditing?" before anything else:
Organization, Personal account, or Detect automatically. The CLI gains
`--account-type {auto,organization,user}`.

The selection is not cosmetic. Eight checks exist only on organizations, so
choosing wrongly changes the result either way:

- Organization selected for a personal account: eight findings that cannot
  apply to that account.
- Personal account selected for an organization: eight real controls silently
  dropped. This case now emits a warning naming what was skipped, recorded in
  the results as `target_warning`.

Selecting "Organization" for a name that is not one produces a clear message
pointing at the personal account option, instead of a bare 404.

### Added - APPLICABILITY.md

A full matrix of which checks apply to which account type and plan, covering:

- The four result states and why `unknown` and `not_applicable` are kept apart.
- All eight organization checks by tier, including the two - SSO Configuration
  and Audit Logging - that are honest placeholders and return `unknown` on every
  plan including Enterprise.
- The eleven branch protection checks against the plan matrix, with GitHub's own
  non-enforcement wording quoted.
- Secret scanning requiring the Secret Protection add-on on private
  repositories, and why that is indistinguishable from a missing permission.
- Measured coverage by target, and three concrete steps to raise it.

Published in three places: `APPLICABILITY.md`, a "What Applies To You" wiki page
in the web interface, and a summary section in the README.

### Added - documentation drift guard

`test_applicability_doc_lists_every_check` fails when a check exists in the
engine but is absent from the published matrix. It caught two names on its first
run, broken across a line wrap in prose - the reason the branch protection list
is now a list rather than a paragraph.

### Tests

82 total.

## [1.7.0] - 2026-08-09

Account-type awareness. The engine previously assumed its target was an
organization and misreported every organization control on a personal account.

### Fixed - personal accounts were told the wrong thing

All eight organization-level checks returned `unknown` on a personal account,
with messages such as "only visible to organization owners" and "verify manually
at org/settings/security". Both claims are wrong: a personal account has no
membership policy, no default repository permission and no organization Actions
policy, so there is no setting to be denied access to and no page to visit.

`SecurityChecker` now detects the account type and returns `not_applicable` with
an accurate reason. The eight checks leave the score entirely rather than
sitting in it as unresolved unknowns.

### Fixed - paid personal plans were assumed to enforce rulesets

`_enforcement()` treated any non-free plan as enforcing. The non-enforcement
banner names a GitHub Team **organization** as the requirement, so a paid
personal plan is not established to lift it. A private repository on a personal
account now reports `unknown` enforcement with a caveat instead of a confident
pass. Organizations on a paid plan are unaffected.

### Added

- `account_type` is recorded in the audit results.

### Measured coverage by target

Scored checks out of 64 (one public and one private repository):

| Target | Scored | Coverage |
|---|---|---|
| Personal account, free | 25 | 39% |
| Personal account, paid | 26 | 41% |
| Organization, free | 28 | 44% |
| Organization, Team | 29 | 45% |

The tool is built around organization controls, and a personal account gives up
eight checks that cannot exist for it. Coverage on a private repository under a
free plan is low for a further reason already documented: ten branch controls
are unenforceable there.

### Known gaps by tier

- **Enterprise Cloud**: SAML SSO status and the audit log API are both reported
  `unknown`. Neither is implemented - SSO is not exposed by REST, and
  `get_audit_logs` is absent from PyGithub. An Enterprise customer gets no
  benefit from either check today.
- **Secret Protection / Code Security**: on private repositories these require
  a paid add-on. The engine reports `unknown` when the block is absent, which is
  correct but indistinguishable from a permission failure.
- Enterprise-only ruleset restrictions (commit metadata, branch names) are not
  checked at all.

### Tests

78 total.

## [1.6.2] - 2026-08-09

Confirmation release. The last open assumption in the enforcement model is now
verified from the UI.

### Verified - free organization, private repository

The suppression logic added in 1.4.2 was based on a banner seen on a *personal*
private repository. It is now confirmed for organizations as well, with the same
substance and different wording:

> Your rulesets won't be enforced on this private repository until you upgrade
> this organization account to GitHub Team.

The ten controls reported `not_applicable` on the reference private repository
are therefore correctly suppressed - the engine is not hiding real findings. Both
banner texts are recorded in `_enforcement()` so the basis for the decision stays
with the code.

### Changed

- Suppressed and unenforced findings now name the remediation explicitly:
  upgrade to GitHub Team, or make the repository public. A control removed from
  the score should still tell the reader what would bring it back into scope.
- **2FA message corrected.** It previously asserted that github.com "has
  required 2FA of all contributors since 2024". The platform requirement is a
  staged rollout with per-account deadlines - the reference account carries one
  of 23 September 2026 - and it does not govern organization membership at all.
  The message no longer leans on a completed-fact claim it cannot support, and
  states what the organization policy actually controls.

### Tests

73 total.

## [1.6.1] - 2026-08-09

Second live run against the reference organization. Ruleset detection confirmed
working end to end; three defects found in the output.

### Confirmed working on live data

- **Ruleset-only protection is detected.** `cherry-desk` reports "Default branch
  'main' is protected (repository ruleset)" with enforcement active. Under the
  pre-1.4.1 engine that repository would have read as completely unprotected,
  and under pre-1.3.0 every dependent control would have failed with an
  `AttributeError` message.
- **The SHA pinning probe hit a real key.** All four repositories returned a
  definite `fail`, matching the unchecked checkbox in the settings UI. One of
  the candidate key names in `_SHA_PINNING_KEYS` is correct.
- The three-state model is doing real work: 46 checks reported `not_applicable`
  and 11 `unknown`, none of them inflating the failure count.

### Fixed

- **API errors named the wrong settings page.** `_api_get` hardcoded "Actions
  settings" into every failure message, so a 403 from `/rulesets` read as
  "Actions settings: token lacks the required permission" and sent the reader
  to the wrong page. Each call site now passes its own label.
- **Subject-verb agreement** in dependent-check messages ("Pull request reviews
  is not enforceable"). Replaced with a colon form that reads correctly for both
  singular and plural control names.

### Added - coverage reporting

The reference run scored 57.14%, but only 63 of 120 checks could be scored at
all - 52.5% coverage. For the private repository it was 9 of 28. A score derived
from a third of the control set is a weaker claim than the same number derived
from all of it, and the summary previously left that division to the reader.

`coverage_percent` and `low_coverage` are now part of the summary, and the CLI
states plainly when fewer than 60% of checks were scored.

### Still unresolved

- **Fork pull request policy key names.** All four repositories returned
  `unknown`; none of the candidates in `_FORK_WORKFLOW_KEYS` or
  `_FORK_APPROVAL_KEYS` matched. The UI shows the setting exists, so the engine
  is asking for the wrong field.
- **Free organization, private repository.** `osint-reconnaissance-tool` has ten
  controls suppressed as `not_applicable` on the assumption that rulesets are
  not enforced there. That assumption comes from a banner observed on a
  *personal* private repository and has not been confirmed for a free
  organization. If it is wrong, the engine is hiding ten real findings.
- Secret scanning and rulesets both returned 403 on the private repository, so
  the audit token lacks admin on it.

### Tests

72 total.

## [1.6.0] - 2026-08-09

Modelled from the free-organization ruleset and Actions UI. 35 checks -> 36.

### Added - Ruleset Enforcement Status

The new-ruleset form defaults **Enforcement status to "Disabled"**. A ruleset
saved without changing that dropdown appears in the Rulesets list, reads as
configured, and enforces nothing.

This is the same false-confidence failure as the unenforced-plan case found in
1.4.2, reached by a different route, and it is invisible to
`/rules/branches/{branch}` because that endpoint returns only rules in effect.
The engine now reads `/repos/{o}/{r}/rulesets` and fails when any ruleset is
`disabled`, or reports separately when one is in `evaluate` mode - violations
logged, nothing blocked.

### Fixed - public repositories were skipped for fork approval

`Fork Pull Request Workflows` returned `not_applicable` for every public
repository. The control simply differs by visibility: a private repository
chooses whether fork workflows run at all, while a public one chooses which
contributors need approval first. The public case is the more consequential of
the two and was the one being skipped.

Grading now distinguishes the three policies. "Require approval for first-time
contributors who are new to GitHub" is reported as a failure: any account with
prior GitHub history runs workflows on the repository unreviewed, which is a
weak filter against a prepared attacker.

### Fixed - forward compatibility with new rule types

The branch-rule allowlist added in 1.4.1 silently ignored anything unfamiliar.
GitHub has since shipped rule types the list does not contain - code quality,
code coverage and Copilot code review appear in the ruleset form. A branch
covered only by unrecognised rules would have been reported as **unprotected**,
which is a false finding of the worst kind: confidently wrong.

Unrecognised types are now recorded and the branch reports `unknown`, naming the
types. Repository-scoped rules stay on an explicit denylist, so the
hashicorp/terraform case from 1.4.1 still reports correctly.

### Verified from the UI

- Free organization, public repository: no non-enforcement banner. Rulesets are
  enforced. The private repository case on a free organization is still open.
- "Restrict deletions" and "Block force pushes" are checked by default in the
  new-ruleset form, so their presence is weak evidence of a considered
  configuration.
- Organization policy can grey out repository workflow permissions. The
  repository-level check reads the effective value, so this needs no change.
- GitHub's own warning confirms the self-hosted runner check verbatim:
  "Using self-hosted runners in public repositories is not recommended."

### Observed, not implemented

Enterprise-only ruleset restrictions (commit metadata, branch names); merge
queue, required deployments, code scanning, code quality and code coverage
rules.

### Tests

69 total, including one asserting that an unfamiliar rule type can never be
read as an unprotected branch.

## [1.5.0] - 2026-08-09

Actions coverage extended from the repository settings UI. 32 checks -> 35.
A second XSS site was found by the escaping test added in 1.4.x.

### Security

- **Second unescaped interpolation in the HTML report.** The compliance-gap
  section rendered `repo_fail['repo']` and `repo_fail['message']` raw. The 1.4.x
  escaping pass covered the check and repository-card renderers but not this
  one. Found by `test_html_report_escapes_hostile_names`, which had been passing
  only because the hostile payload never reached that section before.
  A source-level guard now fails on any f-string field carrying repository,
  check or message data that does not go through `_esc()`.

### Added - three repository checks

- **Repository Actions Policy** - repository-level `allowed_actions`. Without
  it, a personal account received no Actions policy coverage at all, because the
  three existing policy checks are organization-scoped and personal accounts
  have no organization.
- **Action SHA Pinning Policy** - GitHub's native "Require actions to be pinned
  to a full-length commit SHA" setting. This is preventive where workflow
  scanning is only detective: the platform refuses to run an unpinned
  reference, rather than reporting one already committed.
- **Fork Pull Request Workflows** - on private repositories, running workflows
  from fork pull requests hands fork maintainers a token with read access to
  the source repository. `not_applicable` on public repositories.

The JSON key names for the last two are not confirmed. The engine probes a list
of candidate names and reports `unknown` with a manual-verification pointer when
none is present - it does not guess a pass or a failure. Replace the candidate
lists in `_SHA_PINNING_KEYS` / `_FORK_WORKFLOW_KEYS` once a real response is
available.

### Documented

- Actions policies (Settings > Actions > Policies, in preview) are implemented
  as rulesets and carry the same "won't be enforced on this private repository"
  banner. The plan restriction is systemic across ruleset-backed features rather
  than specific to branch protection.
- Remediation text for unpinned actions now points at the native setting as the
  stronger fix.

### Observed, not yet implemented

- Actions policies preview: restrict actors, restrict events, require lockfile.
- OIDC immutable subject claims, automatic for repositories created or renamed
  after 15 July 2026. Relevant to cloud trust policies bound to a repository
  identity.

### Tests

62 total. The count-drift guard caught the stale "32 security controls" claim
automatically before it could ship.

## [1.4.2] - 2026-08-09

Plan-based enforcement modelled from the GitHub UI. Adds a state the engine
previously would have reported as a pass.

### Added - configured-but-not-enforced detection

GitHub permits creating a ruleset on a private repository under a free plan and
then does not enforce it, showing only a banner:

> Your rulesets won't be enforced on this private repository until you move to
> GitHub Team organization account.

This creates a state where rules exist, the API returns them, and the branch is
not actually protected. The previous logic would have reported PASS. A false
"protected" is more dangerous than any false failure, because it manufactures
confidence rather than noise.

Branch protection now resolves to one of five states:

| State | Meaning | Scoring |
|---|---|---|
| `protected` | Rules exist and are enforced | pass |
| `unprotected` | No rules configured | fail |
| `configured_not_enforced` | Rules exist, plan does not honour them | **fail** |
| `not_enforceable` | No rules, and the plan could not enforce them anyway | not applicable |
| `unknown` | Not readable with this token | not applicable |

`configured_not_enforced` is a failure with an explicit message, because the
repository owner believes protection is in place and it is not.

### Changed

- Plan gating replaced: the previous check asked whether protection was
  *configurable*. Configurability was the wrong question - the UI allows the
  configuration and silently declines to apply it. The engine now asks whether
  it is *enforced*.
- The banner names a GitHub Team **organization**, not Pro, so the previous
  assumption that any paid plan lifts the restriction on personal private
  repositories was wrong and has been removed.
- When the plan cannot be determined and the repository is private, a passing
  branch protection result now carries an explicit caveat instead of silently
  assuming enforcement.

### Added - tests

4 new tests (52 total), including one asserting that an unenforced ruleset can
never be reported as a pass.

### Still unverified

- Whether classic branch protection (Settings -> Branches) behaves identically
  to rulesets on a free private repository, or shows a different restriction.
- Organization Actions endpoints and the `security_and_analysis` block, both of
  which require authentication.
- NIST SP 800-53 patch level; CIS, ISO and SOC 2 version positions.

## [1.4.1] - 2026-08-09

Ruleset handling verified against live GitHub API responses instead of
assumptions. One defect found and fixed by that verification.

### Fixed

- **Organization repository rules were counted as branch protection.**
  `GET /repos/{o}/{r}/rules/branches/{b}` also returns organization-scoped
  repository rules - `repository_visibility`, `repository_name`,
  `repository_create`, `repository_delete`, `repository_transfer` - which say
  nothing about the branch. Observed live on hashicorp/terraform. A repository
  governed only by those rules was marked "protected", after which all nine
  dependent controls were evaluated and failed. Rule types are now filtered
  against a branch-scoped allowlist.

### Verified against live responses

Captured from rust-lang/rust, github/docs, microsoft/vscode, actions/checkout,
cli/cli and vercel/next.js:

- All six rule type names used by the engine are correct: `pull_request`,
  `required_status_checks`, `required_linear_history`, `required_signatures`,
  `non_fast_forward`, `deletion`.
- Parameter names are correct: `required_approving_review_count`,
  `dismiss_stale_reviews_on_push`, `require_code_owner_review`, and the nested
  `required_status_checks[].context`.
- A ruleset alone does not set `branch.protected`. microsoft/vscode has four
  active rules while the branch reports `protected: null` with no classic
  protection URL. The engine already queried both endpoints unconditionally,
  so this case was handled - but it confirms that a classic-protection-only
  implementation would report such repositories as completely unprotected.

### Added

- `tests/fixtures/` - real API responses, replacing invented payloads. Six new
  tests run against them (48 total).
- `require_last_push_approval` is now parsed.
- Branch protection findings note when a ruleset is enforced at organization
  level (`ruleset_source_type: Organization`).

### Observed but not yet implemented

Rule types seen in production that the engine ignores: `copilot_code_review`
(present on 4 of 12 repositories sampled), `merge_queue`, `creation`, `update`,
`workflows`, `code_scanning`, `required_deployments`.

### Still unverified

- GitHub Free plan behaviour for private repositories - whether classic branch
  protection and rulesets differ. This drives the `not_applicable` logic and
  needs an authenticated check on a free private repository.
- Organization Actions endpoints (`/orgs/{org}/actions/permissions`) and the
  repository `security_and_analysis` block. Both require authentication, so the
  field names remain unconfirmed.
- NIST SP 800-53 patch level and the CIS/ISO/SOC 2 version positions.

## [1.4.0] - 2026-08-09

Adds GitHub Actions supply-chain coverage. 23 checks -> 32
(8 organization-level, 24 repository-level).

### Added - Actions supply chain

Every large-scale GitHub compromise since 2024 has arrived through the Actions
supply chain rather than through branch settings. The tool previously checked
none of it.

Organization level:
- **Actions Allowed Actions Policy** - `allowed_actions: all` means any
  Marketplace action can run in any repository.
- **Actions Default Token Permissions** - `GITHUB_TOKEN` defaulting to write
  hands push access to every action that runs.
- **Actions Pull Request Approval** - workflows able to approve pull requests
  defeat required reviews by supplying their own approval.

Repository level:
- **Workflow Token Permissions** - the repository-level override of the above.
- **Action Version Pinning** - third-party actions referenced by a mutable tag
  instead of a commit SHA. This is the exact path used in the
  tj-actions/changed-files compromise. GitHub-owned actions on tags are reported
  but not counted as findings.
- **Workflow Permissions Declared** - workflows with no top-level `permissions:`
  block inherit the repository default instead of stating least privilege.
- **Untrusted Workflow Triggers** - `pull_request_target` / `workflow_run`
  combined with a checkout of the pull request ref, which runs untrusted code
  with repository secrets in scope.
- **Self-Hosted Runner Exposure** - self-hosted runners on a public repository,
  where a fork pull request can execute code on your infrastructure.
- **Build Provenance Attestation** - publishing workflows that emit no
  provenance. Reported `not_applicable` when the repository publishes nothing.

Workflow files are matched with regular expressions rather than a YAML loader:
workflow templating routinely breaks strict parsers, and a YAML 1.1 loader turns
the `on:` key into the boolean `True`. No new dependency was added.

Repositories with no workflows return `not_applicable` for all six content
checks - not using Actions is not a security failure.

### Fixed - stale framework references

- **SOC 2**: "SOC 2 Type II: CC6.2" replaced with "SOC 2 Trust Services
  Criteria". Type I/II describes the report period, not the criteria set.
- **CIS Controls** relabelled v8 -> v8.1 (June 2024). Safeguard numbering is
  unchanged, so the mappings remain valid.
- **GitHub Advanced Security** terminology removed. GHAS was unbundled into
  GitHub Secret Protection and GitHub Code Security; the message pointed users
  at a product that no longer carries that name.
- **2FA message rewritten.** github.com has required 2FA of all contributors
  since 2024, so this check measures organization policy - what blocks a
  non-compliant account from being added - not whether members have 2FA.
- Remaining "21 security controls" claims corrected in the landing page,
  report introduction and docs.

### Added - drift guards

- `test_framework_labels_are_current` fails on any reappearance of
  "SOC 2 Type II", "ISO/IEC 27001:2013" or "GitHub Advanced Security".
- `test_check_count_claims_match_the_code` scans every source and doc file for
  "N security checks/controls" and fails when N does not match the engine.
- 39 tests total.

### Still unverified

The ISO, CIS and SOC 2 positions above reflect knowledge current to May 2026.
NIST SP 800-53 may have moved past the Rev. 5 patch level referenced here, and
the GitHub Free plan behaviour that drives `not_applicable` for private-repo
branch protection should be confirmed against current documentation before
release.

## [1.3.1] - 2026-08-09

First release validated against a live GitHub account rather than mocks only.

### Fixed

- **HTML report returned 500 on every request.** `generate_html_report` builds
  its output in a local variable named `html`, which shadowed the `html` module
  added for escaping, so every call raised `UnboundLocalError`. Escaping now
  uses `from html import escape as _esc`. Covered by
  `test_html_report_renders_from_a_real_result_shape`.
- **One missing setting no longer counts ten times.** Nine controls depend on
  branch protection. When protection is absent the root cause fails once and
  the dependants are reported `not_applicable`, excluded from the score, each
  pointing back at the root finding. On the reference account this moved the
  score from 28.77% to 58.33% without a single setting changing - the earlier
  number was 40 restatements of one fact.
- **Repository rulesets are now detected.** Only classic branch protection was
  read, so a repository governed entirely by a ruleset appeared unprotected.
  `GET /repos/{o}/{r}/rules/branches/{branch}` is merged with the classic
  endpoint into a single `ProtectionFacts` view.
- **Plan limitations are no longer reported as findings.** Branch protection is
  not configurable on private repositories under GitHub Free; those controls are
  `not_applicable` instead of failing. Same defect class as counting a 403 as a
  failure.
- **`"organization": null` in reports.** `org.name` is empty for personal
  accounts and unnamed organisations; falls back to `login`, then to the
  requested name.
- Report evidence sections and repository cards now use evaluated checks as the
  denominator, and render `NOT CHECKED` / `N/A` instead of showing unscored
  checks as failures.

### Added

- `not_applicable` result state, distinct from `unknown` (cannot apply vs.
  could not determine). Both are excluded from the score.
- 6 further regression tests (28 total), including one asserting that a single
  missing prerequisite cannot inflate the denominator.

## [1.3.0] - 2026-08-09

Post-review release. v1.2.2 should not be used: its scoring engine could not
report an accurate result under any configuration.

### Fixed - scoring engine (P0)

- **Branch protection checks rewritten against the real API.** Six checks called
  `repo.protected_branches` and `branch.protection`, neither of which exists in
  PyGithub. Every one raised `AttributeError`, was swallowed by a bare `except`,
  and was reported as a failure. They now use `branch.protected` and
  `branch.get_protection()`.
- **Secret scanning and dependency scanning implemented.** Both previously
  returned a hardcoded failure with no API call. They now read
  `security_and_analysis` and `get_vulnerability_alert()`.
- **Removed four checks that could not fail** (`count >= 0`, `passed: True` in
  both branches, and an org check whose admin counter was loop-invariant).
  They inflated every score without measuring anything.
- **Added a third result state.** Checks now return `pass`, `fail` or `unknown`.
  A permission the token does not hold is excluded from the score instead of
  being reported as a security finding.
- **Measured range restored:** a hardened repository now scores 100% and an
  unprotected public one 0%. In v1.2.2 the achievable range was 28%-56%, which
  made the 90% "LOW RISK" band mathematically unreachable.

### Fixed - security of the tool itself (P1)

- `debug=True` removed from `run.sh`, `app.py` and `--web`. The Werkzeug console
  renders the failing frame's local variables, and `github_token` is a local in
  `start_audit()`. Debug is now opt-in via `AUDITOR_DEBUG=1`.
- Session IDs are generated server-side with `secrets.token_urlsafe(32)`.
  They were previously client-supplied timestamps, enumerable and overwritable
  on endpoints that have no authentication.
- Path traversal in report download fixed: the user-supplied organisation name is
  passed through `secure_filename()` and the resolved path is confined to
  `audit_results/`.
- XSS in the generated HTML report fixed: every interpolated value is escaped.
  A GitHub organisation display name accepts arbitrary characters, so the
  downloadable report was executing attacker-controlled markup.
- Hardcoded `app.secret_key` replaced with `secrets.token_bytes(32)`.
- Exception text is no longer surfaced to the browser; errors are mapped to
  status-specific messages.
- `history.json` writes are serialised behind a lock.
- `--token` removed from the CLI (it landed in shell history and `ps aux`).
  Use `GITHUB_TOKEN` or `--token-stdin`.
- Requested token scopes reduced from `repo, admin:org_hook, read:org` to a
  read-only fine-grained token. `admin:org_hook` was never used.
- Container runs as an unprivileged user, `.dockerignore` added, healthcheck added.

### Fixed - accuracy of claims (P2)

- Check count corrected from 21 to the actual 23.
- ISO 27001 mapping renumbered from the 2013 Annex A scheme to 2022
  (clauses 5-8). It was labelled 2022 while using 2013 identifiers.
- Compliance mappings added for every check; several checks were previously
  dropped from the report because their names did not match the mapping keys.
- GDPR/CCPA "compliance" claim replaced with an accurate description: nothing is
  collected, so no processing regime applies.
- Dependencies updated (`requests` 2.31.0 -> 2.32.3, PyGithub 2.1.1 -> 2.5.0).

### Added

- `tests/test_checks.py` - 22 regression tests. Every P0 defect above is caught
  by `test_hardened_repo_scores_100_percent` alone.
- `requirements-dev.txt` with `pytest` and `pip-audit`.
