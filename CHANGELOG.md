# Changelog

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
